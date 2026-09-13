"""
Scamnet Risk Scoring Engine
────────────────────────────
Score formula (max 100 pts, capped):
  db_match      0–60   Claude Vision confirms same person as a known scammer
  crowdsource   0–25   unique people who independently checked this face
  reports       0–20   verified user reports linked to this face hash
  ai_flag       0–20   face photo detected as AI-generated

Level thresholds:
  0–15   → clean
  16–45  → warning
  46–79  → high
  80+    → confirmed
"""
from __future__ import annotations
import math
from dataclasses import dataclass, field
from typing import Optional

import config
from face import compute_phash, image_sha256, compare_faces_with_claude, detect_ai_image
from database import db, row_to_dict


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class ScoreBreakdown:
    db_match:    float = 0.0
    crowdsource: float = 0.0
    reports:     float = 0.0
    ai_flag:     float = 0.0

    @property
    def total(self) -> float:
        return min(100.0, self.db_match + self.crowdsource + self.reports + self.ai_flag)


@dataclass
class CrowdsourceSignal:
    total_checks:    int = 0
    unique_sessions: int = 0
    unique_users:    int = 0
    first_seen:      Optional[str] = None
    last_seen:       Optional[str] = None


@dataclass
class RiskResult:
    risk_level:       str
    risk_score:       float
    is_ai_generated:  bool = False
    ai_confidence:    Optional[float] = None
    detected_ai_model: Optional[str] = None
    match_found:      bool = False
    match_confidence: Optional[float] = None
    profile_id:       Optional[str] = None
    crowdsource:      CrowdsourceSignal = field(default_factory=CrowdsourceSignal)
    breakdown:        ScoreBreakdown = field(default_factory=ScoreBreakdown)
    face_phash:       Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _level(score: float) -> str:
    if score >= config.RISK_HIGH_MAX + 1:
        return "confirmed"
    if score >= config.RISK_WARNING_MAX + 1:
        return "high"
    if score >= config.RISK_CLEAN_MAX + 1:
        return "warning"
    return "clean"


def _crowdsource_score(unique_sessions: int) -> float:
    if unique_sessions < 2:
        return 0.0
    return min(config.SCORE_CROWDSOURCE_MAX, 8 * math.log2(unique_sessions))


def _report_score(verified: int, pending: int) -> float:
    return min(config.SCORE_REPORTS_MAX, float(verified * 10 + pending * 2))


# ── Main scorer ───────────────────────────────────────────────────────────────

class Scorer:

    def score_face(
        self,
        image_bytes: bytes,
        session_hash: str,
        user_id: Optional[str] = None,
        country_code: Optional[str] = None,
    ) -> RiskResult:
        bd = ScoreBreakdown()
        result = RiskResult(risk_level="clean", risk_score=0.0)

        img_hash = image_sha256(image_bytes)
        face_phash = compute_phash(image_bytes)
        result.face_phash = face_phash

        # ── 1. AI image detection (cached) ────────────────────────────────────
        ai = self._cached_ai_check(img_hash, image_bytes)
        if ai["is_ai"]:
            bd.ai_flag = float(config.SCORE_AI_FLAG)
            result.is_ai_generated = True
            result.ai_confidence = ai["confidence"]
            result.detected_ai_model = ai.get("model_hint")

        # ── 2. DB face comparison via Claude Vision ───────────────────────────
        stored = self._load_profile_images()
        match_type = "no_match"

        if stored:
            cmp = compare_faces_with_claude(image_bytes, stored)
            if cmp.get("matched") and cmp.get("profile_id"):
                conf = float(cmp.get("confidence", 0.0))
                result.match_found = True
                result.match_confidence = conf
                result.profile_id = cmp["profile_id"]
                if conf >= 0.85:
                    bd.db_match = float(config.SCORE_DB_MATCH_MAX)
                    match_type = "match"
                else:
                    bd.db_match = float(config.SCORE_DB_MATCH_MAX) * 0.6
                    match_type = "partial"

        # ── 3. Crowdsource signal ─────────────────────────────────────────────
        crowd = self._crowd_stats(face_phash)
        result.crowdsource = crowd
        bd.crowdsource = _crowdsource_score(crowd.unique_sessions)

        # ── 4. Reports ────────────────────────────────────────────────────────
        with db() as conn:
            v = conn.execute(
                "SELECT COUNT(*) FROM reports WHERE face_phash=? AND status='verified'",
                (face_phash,),
            ).fetchone()[0]
            p = conn.execute(
                "SELECT COUNT(*) FROM reports WHERE face_phash=? AND status='pending'",
                (face_phash,),
            ).fetchone()[0]
        bd.reports = _report_score(v, p)

        # ── 5. Also check reports linked to matched profile ───────────────────
        if result.profile_id and bd.reports == 0:
            with db() as conn:
                v2 = conn.execute(
                    "SELECT COUNT(*) FROM reports WHERE profile_id=? AND status='verified'",
                    (result.profile_id,),
                ).fetchone()[0]
                p2 = conn.execute(
                    "SELECT COUNT(*) FROM reports WHERE profile_id=? AND status='pending'",
                    (result.profile_id,),
                ).fetchone()[0]
            bd.reports = _report_score(v2, p2)

        # ── 6. Final score ────────────────────────────────────────────────────
        result.breakdown = bd
        result.risk_score = bd.total
        result.risk_level = _level(bd.total)

        # ── 7. Log check ──────────────────────────────────────────────────────
        with db() as conn:
            conn.execute(
                """INSERT INTO face_checks
                   (face_phash, session_hash, user_id, country_code,
                    result_type, matched_profile, risk_score)
                   VALUES (?,?,?,?,?,?,?)""",
                (face_phash, session_hash, user_id, country_code,
                 "ai_generated" if result.is_ai_generated else match_type,
                 result.profile_id, result.risk_score),
            )

        return result

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _load_profile_images(self) -> list:
        """
        Load face images for comparison — two sources:
        1. face_images: admin-verified scammer profiles (high confidence)
        2. reported_faces: victim-submitted photos (crowdsource signal)
        """
        result = []
        with db() as conn:
            # Verified profiles
            for r in conn.execute(
                """SELECT fi.profile_id, fi.image_data, p.real_name
                   FROM face_images fi
                   LEFT JOIN profiles p ON p.id = fi.profile_id
                   ORDER BY fi.created_at DESC"""
            ).fetchall():
                result.append({
                    "profile_id": r["profile_id"],
                    "image_bytes": bytes(r["image_data"]),
                    "name": r["real_name"] or "Unknown",
                    "source": "profile",
                })
            # User-reported faces (limit to 50 most recent)
            for r in conn.execute(
                """SELECT id, image_data, known_name, scam_type, report_count
                   FROM reported_faces
                   ORDER BY report_count DESC, created_at DESC LIMIT 50"""
            ).fetchall():
                result.append({
                    "profile_id": f"reported:{r['id']}",
                    "image_bytes": bytes(r["image_data"]),
                    "name": r["known_name"] or "Неизвестно",
                    "source": "reported",
                    "scam_type": r["scam_type"],
                    "report_count": r["report_count"],
                })
        return result

    def _cached_ai_check(self, img_hash: str, image_bytes: bytes) -> dict:
        """Check AI-detection cache, run detect_ai_image only on cache miss."""
        with db() as conn:
            row = conn.execute(
                "SELECT * FROM ai_detection_cache WHERE image_hash=?", (img_hash,)
            ).fetchone()
        if row:
            return {
                "is_ai": bool(row["is_ai_generated"]),
                "confidence": row["confidence"],
                "model_hint": row["detected_model"],
            }

        ai = detect_ai_image(image_bytes)
        with db() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO ai_detection_cache
                   (image_hash, is_ai_generated, confidence, detected_model, detection_method)
                   VALUES (?,?,?,?,?)""",
                (img_hash, int(ai["is_ai"]), ai["confidence"],
                 ai.get("model_hint", "unknown"), "claude_vision"),
            )
        return ai

    def _crowd_stats(self, face_phash: str) -> CrowdsourceSignal:
        with db() as conn:
            row = conn.execute(
                "SELECT * FROM face_stats WHERE face_phash=?", (face_phash,)
            ).fetchone()
        if not row:
            return CrowdsourceSignal()
        return CrowdsourceSignal(
            total_checks=row["total_checks"],
            unique_sessions=row["unique_sessions"],
            unique_users=row["unique_users"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
        )
