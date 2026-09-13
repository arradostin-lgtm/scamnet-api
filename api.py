"""
Scamnet FastAPI application.

Endpoints:
  GET  /auth/google                 → Google OAuth redirect
  GET  /auth/google/callback        → token exchange, returns JWT
  GET  /auth/me                     → current user profile
  POST /check/face                  → upload photo → risk result
  POST /check/voice                 → upload audio → risk result
  POST /check/company               → check company/broker by name or domain
  POST /report                      → submit a scammer report
  GET  /profiles                    → list profiles (admin or public)
  GET  /profiles/{id}               → single profile detail
  GET  /stats/global                → aggregate stats for dashboard

Run: uvicorn api:app --reload --host 0.0.0.0 --port 8000
"""
import hashlib
import io
import json
import sys
import os
from typing import Optional

sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse

import config
from database import db, row_to_dict, init_db
from models import (
    AuthResponse, UserPublic, ReportCreate, FaceCheckResult,
    CompanyCheckResult, ProfilePublic, ScoreBreakdown, CrowdsourceSignal,
)
from auth import google_auth_url, exchange_google_code, upsert_user, create_token, get_current_user
from scoring import Scorer

app = FastAPI(title="Scamnet API", version="1.0.0", docs_url="/api/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scorer = Scorer()


# ── Auth dependency ────────────────────────────────────────────────────────────

def bearer_token(request: Request) -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


def current_user(token: Optional[str] = Depends(bearer_token)) -> Optional[dict]:
    if not token:
        return None
    return get_current_user(token)


def require_user(user = Depends(current_user)):
    if not user:
        raise HTTPException(401, "Authentication required")
    return user


# ── Startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
def startup():
    init_db()


# ── Auth endpoints ─────────────────────────────────────────────────────────────

@app.get("/auth/google", tags=["auth"])
def login_with_google():
    """Redirect browser to Google OAuth consent screen."""
    return RedirectResponse(google_auth_url())


@app.get("/auth/google/callback", tags=["auth"])
async def google_callback(code: str, state: str = ""):
    """Exchange Google code → JWT. Redirect to frontend with token in hash."""
    try:
        profile = await exchange_google_code(code)
    except Exception as e:
        raise HTTPException(400, f"Google OAuth error: {e}")

    user = upsert_user(profile)
    token = create_token(user["id"])

    # Redirect to frontend; token passed in URL fragment (not logged by servers)
    frontend = config.FRONTEND_URL.rstrip("/")
    return RedirectResponse(f"{frontend}/#token={token}", status_code=302)


@app.get("/auth/me", tags=["auth"], response_model=UserPublic)
def me(user = Depends(require_user)):
    return UserPublic(
        id=user["id"],
        email=user["email"],
        name=user.get("name"),
        avatar_url=user.get("avatar_url"),
        plan=user.get("plan", "free"),
        checks_used=user.get("checks_used", 0),
        checks_limit=user.get("checks_limit", 10),
    )


# ── Check: face ───────────────────────────────────────────────────────────────

@app.post("/check/face", tags=["check"])
async def check_face(
    request: Request,
    file: UploadFile = File(...),
    user = Depends(require_user),
):
    """
    Upload a face photo. Requires authentication.
    Returns risk level, AI detection result, DB match, crowdsource signal.
    """
    image_bytes = await file.read()
    if len(image_bytes) > 10 * 1024 * 1024:
        raise HTTPException(413, "Image too large (max 10 MB)")

    # Check user quota
    if user["checks_used"] >= user["checks_limit"]:
        raise HTTPException(429, "Monthly check limit reached. Upgrade your plan.")

    # Anonymised session identifier
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "")
    from datetime import date
    session_hash = hashlib.sha256(f"{ip}{ua}{date.today()}".encode()).hexdigest()

    result = scorer.score_face(
        image_bytes=image_bytes,
        session_hash=session_hash,
        user_id=user["id"] if user else None,
        country_code=request.headers.get("CF-IPCountry"),
    )

    # Increment user check counter
    if user:
        with db() as conn:
            conn.execute(
                "UPDATE users SET checks_used = checks_used + 1 WHERE id=?", (user["id"],)
            )

    # Fetch profile if matched
    profile_data = None
    if result.profile_id:
        with db() as conn:
            row = conn.execute("SELECT * FROM profiles WHERE id=?", (result.profile_id,)).fetchone()
        if row:
            d = row_to_dict(row)
            profile_data = {k: d[k] for k in ProfilePublic.model_fields if k in d}

    return {
        "risk_level":       result.risk_level,
        "risk_score":       round(result.risk_score, 1),
        "is_ai_generated":  result.is_ai_generated,
        "ai_confidence":    result.ai_confidence,
        "detected_ai_model": result.detected_ai_model,
        "match_found":      result.match_found,
        "match_confidence": round(result.match_confidence, 3) if result.match_confidence else None,
        "profile":          profile_data,
        "crowdsource": {
            "total_checks":   result.crowdsource.total_checks,
            "unique_sessions": result.crowdsource.unique_sessions,
            "unique_users":   result.crowdsource.unique_users,
            "first_seen":     result.crowdsource.first_seen,
            "last_seen":      result.crowdsource.last_seen,
        },
        "score_breakdown": {
            "db_match":    result.breakdown.db_match,
            "crowdsource": result.breakdown.crowdsource,
            "reports":     result.breakdown.reports,
            "ai_flag":     result.breakdown.ai_flag,
            "total":       result.breakdown.total,
        },
    }


# ── Check: company ────────────────────────────────────────────────────────────

@app.get("/check/company", tags=["check"])
def check_company(q: str):
    """Search company by name or domain."""
    search = f"%{q.lower()}%"
    with db() as conn:
        row = conn.execute(
            """SELECT * FROM companies
               WHERE lower(name) LIKE ? OR lower(domain) LIKE ?
               ORDER BY status DESC LIMIT 1""",
            (search, search)
        ).fetchone()

    if not row:
        return {"found": False, "status": "unknown", "company": None, "regulator_flags": []}

    d = row_to_dict(row)
    return {
        "found": True,
        "status": d["status"],
        "company": {
            "id":            d["id"],
            "name":          d["name"],
            "company_type":  d.get("company_type"),
            "country":       d.get("country"),
            "status":        d["status"],
            "reports_count": d.get("reports_count", 0),
            "regulator_flags": d.get("regulator_flags", []),
            "notes":         d.get("notes"),
        },
        "regulator_flags": d.get("regulator_flags", []),
    }


# ── Report submission ─────────────────────────────────────────────────────────

@app.post("/report", tags=["reports"])
async def submit_report(
    report: ReportCreate,
    face_phash: Optional[str] = None,
    user = Depends(require_user),
):
    with db() as conn:
        conn.execute(
            """INSERT INTO reports
               (face_phash, reporter_id, scam_type, platform, amount_lost_usd,
                currency, description, evidence_urls)
               VALUES (?,?,?,?,?,?,?,?)""",
            (face_phash, user["id"], report.scam_type, report.platform,
             report.amount_lost_usd, report.currency, report.description,
             json.dumps(report.evidence_urls, ensure_ascii=False))
        )
    return {"status": "submitted", "message": "Спасибо. Отчёт принят на модерацию."}


# ── Profiles ──────────────────────────────────────────────────────────────────

@app.get("/profiles", tags=["profiles"])
def list_profiles(limit: int = 20, offset: int = 0, type: Optional[str] = None):
    where = "WHERE type=?" if type else ""
    params = [type, limit, offset] if type else [limit, offset]
    with db() as conn:
        rows = conn.execute(
            f"SELECT * FROM profiles {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params
        ).fetchall()
        total = conn.execute(
            f"SELECT COUNT(*) FROM profiles {where}", [type] if type else []
        ).fetchone()[0]
    return {"total": total, "profiles": [row_to_dict(r) for r in rows]}


@app.get("/profiles/{profile_id}", tags=["profiles"])
def get_profile(profile_id: str):
    with db() as conn:
        row = conn.execute("SELECT * FROM profiles WHERE id=?", (profile_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Profile not found")
    return row_to_dict(row)


# ── Global stats ──────────────────────────────────────────────────────────────

@app.get("/stats/global", tags=["stats"])
def global_stats():
    with db() as conn:
        total_checks    = conn.execute("SELECT COUNT(*) FROM face_checks").fetchone()[0]
        total_profiles  = conn.execute("SELECT COUNT(*) FROM profiles").fetchone()[0]
        total_users     = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        total_reports   = conn.execute("SELECT COUNT(*) FROM reports WHERE status='verified'").fetchone()[0]
        confirmed_today = conn.execute(
            "SELECT COUNT(*) FROM face_checks WHERE result_type='match' AND check_date=date('now')"
        ).fetchone()[0]
    return {
        "total_checks":       total_checks,
        "total_profiles":     total_profiles,
        "total_users":        total_users,
        "verified_reports":   total_reports,
        "confirmed_today":    confirmed_today,
    }


# ── Admin: create test profile with face embedding ────────────────────────────

@app.post("/admin/setup-test-profile", tags=["admin"])
async def setup_test_profile(
    file: UploadFile = File(...),
    admin_key: str = "scamnet-test-2026",
):
    """
    Creates a test scammer profile with face embedding and 10 verified reports.
    Protected by a simple admin key (for testing only).
    """
    if admin_key != os.getenv("ADMIN_KEY", "scamnet-test-2026"):
        raise HTTPException(403, "Invalid admin key")

    image_bytes = await file.read()
    profile_id = "test-ivan-podnyakov"

    # Compute hashes
    from face import compute_phash
    face_phash = compute_phash(image_bytes)

    # Insert profile
    with db() as conn:
        conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,))
        conn.execute(
            """INSERT INTO profiles
               (id, type, confidence, real_name, known_as, nationality,
                current_status, charges, platforms, target_regions,
                known_aliases, tags, victim_count, source, source_url)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                profile_id, "reported", "high",
                "Иван Подняков", "Ivan P.",
                "RU", "активен",
                "Брачное мошенничество, вымогательство денег под предлогом помощи",
                json.dumps(["Tinder", "Instagram", "Telegram"]),
                json.dumps(["RU", "UZ", "KZ"]),
                json.dumps(["Ivan Poz", "Иван П."]),
                json.dumps(["romance", "financial_fraud"]),
                10,
                "TEST — профиль создан для демонстрации системы",
                "",
            )
        )

        # Insert 10 verified reports linked to face_phash
        conn.execute("DELETE FROM reports WHERE face_phash=?", (face_phash,))
        reasons = [
            "Познакомился в Tinder, через 2 недели попросил 500$ на «билет»",
            "Просил деньги на лечение матери, после получения пропал",
            "Обещал приехать, просил перевод на «визу»",
            "Вымогал деньги угрозами после обмена фото",
            "Брал в долг на «бизнес», не вернул",
            "Просил помочь с таможней для «посылки с подарком»",
            "Познакомились ВКонтакте, просил деньги на операцию",
            "Ромэнс-скам через Instagram, потерял 1200$",
            "Знакомство в баре, через неделю попросил деньги",
            "Мошенничество через приложение для знакомств, -800$",
        ]
        amounts = [500, 300, 200, 0, 1000, 150, 700, 1200, 400, 800]
        for i, (reason, amount) in enumerate(zip(reasons, amounts)):
            conn.execute(
                """INSERT INTO reports
                   (face_phash, scam_type, platform, amount_lost_usd,
                    currency, description, status)
                   VALUES (?,?,?,?,?,?,?)""",
                (face_phash, "romance",
                 ["Tinder","ВКонтакте","Instagram","Telegram","Tinder",
                  "WhatsApp","ВКонтакте","Instagram","Offline","Dating app"][i],
                 amount, "USD", reason, "verified")
            )

    # Store actual image for Claude Vision comparison
    img_hash = hashlib.sha256(image_bytes).hexdigest()
    with db() as conn:
        conn.execute("DELETE FROM face_images WHERE profile_id=?", (profile_id,))
        conn.execute(
            """INSERT INTO face_images (profile_id, image_data, image_hash, face_phash)
               VALUES (?,?,?,?)""",
            (profile_id, image_bytes, img_hash, face_phash),
        )

    return {
        "status": "ok",
        "profile_id": profile_id,
        "face_phash": face_phash,
        "image_stored": True,
        "reports_created": 10,
    }


@app.post("/admin/reset-user-limits", tags=["admin"])
async def reset_user_limits(
    email: str = Form(...),
    checks_used: int = Form(0),
    checks_limit: int = Form(5),
    admin_key: str = Form("scamnet-test-2026"),
):
    """Reset or update a user's check limits by email. For testing only."""
    if admin_key != os.getenv("ADMIN_KEY", "scamnet-test-2026"):
        raise HTTPException(403, "Invalid admin key")

    with db() as conn:
        row = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if not row:
            raise HTTPException(404, f"User {email} not found")
        conn.execute(
            "UPDATE users SET checks_used=?, checks_limit=? WHERE email=?",
            (checks_used, checks_limit, email)
        )
    return {"status": "ok", "email": email, "checks_used": checks_used, "checks_limit": checks_limit}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host=config.API_HOST, port=config.API_PORT, reload=True)
