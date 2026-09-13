"""
Google OAuth 2.0 + JWT session tokens.

Flow:
  1. GET /auth/google          → redirect to Google consent screen
  2. GET /auth/google/callback → exchange code, upsert user, return JWT
  3. All protected routes      → Authorization: Bearer <token>
"""
import uuid
import hashlib
import hmac
import json
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

import config
from database import db


GOOGLE_AUTH_URL  = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO  = "https://www.googleapis.com/oauth2/v3/userinfo"

SCOPES = "openid email profile"


# ── Google OAuth URLs ─────────────────────────────────────────────────────────

def google_auth_url(state: str = "") -> str:
    params = {
        "client_id":     config.GOOGLE_CLIENT_ID,
        "redirect_uri":  config.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope":         SCOPES,
        "access_type":   "offline",
        "state":         state,
        "prompt":        "select_account",
    }
    qs = "&".join(f"{k}={v}" for k, v in params.items())
    return f"{GOOGLE_AUTH_URL}?{qs}"


async def exchange_google_code(code: str) -> dict:
    """Exchange authorisation code for tokens + user info."""
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(GOOGLE_TOKEN_URL, data={
            "code":          code,
            "client_id":     config.GOOGLE_CLIENT_ID,
            "client_secret": config.GOOGLE_CLIENT_SECRET,
            "redirect_uri":  config.GOOGLE_REDIRECT_URI,
            "grant_type":    "authorization_code",
        })
        token_resp.raise_for_status()
        tokens = token_resp.json()

        user_resp = await client.get(
            GOOGLE_USERINFO,
            headers={"Authorization": f"Bearer {tokens['access_token']}"}
        )
        user_resp.raise_for_status()
        return user_resp.json()


# ── User upsert ───────────────────────────────────────────────────────────────

def upsert_user(google_profile: dict) -> dict:
    """Create or update user from Google profile. Returns user row dict."""
    google_id  = google_profile["sub"]
    email      = google_profile["email"]
    name       = google_profile.get("name")
    avatar_url = google_profile.get("picture")

    with db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE google_id=? OR email=?", (google_id, email)
        ).fetchone()

        if row:
            conn.execute(
                """UPDATE users SET google_id=?, name=?, avatar_url=?, last_login=datetime('now')
                   WHERE id=?""",
                (google_id, name, avatar_url, row["id"])
            )
            user_id = row["id"]
        else:
            user_id = str(uuid.uuid4())
            conn.execute(
                """INSERT INTO users (id, email, name, avatar_url, google_id, last_login)
                   VALUES (?,?,?,?,?,datetime('now'))""",
                (user_id, email, name, avatar_url, google_id)
            )

        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return dict(user)


# ── JWT (simple HS256, no external library needed) ────────────────────────────

def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def create_token(user_id: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(days=config.JWT_EXPIRE_DAYS)
    header  = _b64_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64_encode(json.dumps({
        "sub": user_id,
        "exp": int(exp.timestamp()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
    }).encode())
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(config.JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64_encode(sig)}"


def verify_token(token: str) -> Optional[dict]:
    """Returns payload dict or None if invalid/expired."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, payload, sig = parts
        signing_input = f"{header}.{payload}".encode()
        expected_sig = hmac.new(config.JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(_b64_decode(sig), expected_sig):
            return None
        claims = json.loads(_b64_decode(payload))
        if claims["exp"] < datetime.now(timezone.utc).timestamp():
            return None
        return claims
    except Exception:
        return None


def get_current_user(token: str) -> Optional[dict]:
    """Verify JWT and return user row from DB, or None."""
    claims = verify_token(token)
    if not claims:
        return None
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (claims["sub"],)).fetchone()
    return dict(row) if row else None
