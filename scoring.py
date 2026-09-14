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
from face import compute_phash, image_sha256
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
        insight_match: Optional[dict] = None,   # from InsightFace pre-computed in api.py
        ai_result: Optional[dict] = None,        # from detect_ai_image / hive — pre-computed async
        claude_match: Optional[dict] = None,     # from compare_faces_with_claude — pre-computed async
        check_reason: Optional[str] = None,      # user-selected reason: money | investment | romance | job | goods | other
    ) -> RiskResult:
        bd = ScoreBreakdown()
        result = RiskResult(risk_level="clean", risk_score=0.0)

        img_hash = image_sha256(image_bytes)
        face_phash = compute_phash(image_bytes)
        result.face_phash = face_phash

        # ── 1. AI image detection (result pre-computed async in api.py) ───────
        ai = ai_result or {"is_ai": False, "confidence": 0.0, "model_hint": "unknown"}
        if ai["is_ai"]:
            bd.ai_flag = float(config.SCORE_AI_FLAG)
            result.is_ai_generated = True
            result.ai_confidence = ai["confidence"]
            result.detected_ai_model = ai.get("model_hint")

        # ── 2a. InsightFace embedding match (fast, no API cost) ───────────────
        match_type = "no_match"

        if insight_match:
            sim = insight_match["similarity"]
            result.match_found = True
            result.match_confidence = sim
            result.profile_id = insight_match["profile_id"]
            if sim >= 0.55:
                bd.db_match = float(config.SCORE_DB_MATCH_MAX)
                match_type = "match"
            else:
                bd.db_match = float(config.SCORE_DB_MATCH_MAX) * 0.6
                match_type = "partial"
            print(f"[scoring] InsightFace match used: {result.profile_id} sim={sim}")

        # ── 2b. Claude Vision match (pre-computed async in api.py) ───────────
        if not result.match_found and claude_match and claude_match.get("matched"):
            conf = float(claude_match.get("confidence", 0.0))
            result.match_found = True
            result.match_confidence = conf
            result.profile_id = claude_match["profile_id"]
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
                    result_type, matched_profile, risk_score, check_reason)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (face_phash, session_hash, user_id, country_code,
                 "ai_generated" if result.is_ai_generated else match_type,
                 result.profile_id, result.risk_score, check_reason or None),
            )

        return result

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _load_profile_images(self) -> list:
        """
        Load verified profile references for visual comparison.
        Photos are read from disk (seed_photos/) — never stored in DB.
        Reported faces contribute only to phash/crowdsource signal, not visual comparison.
        """
        result = []
        with db() as conn:
            for r in conn.execute(
                """SELECT fi.profile_id, fi.seed_photo_path, p.real_name
                   FROM face_images fi
                   LEFT JOIN profiles p ON p.id = fi.profile_id
                   WHERE fi.seed_photo_path IS NOT NULL
                   ORDER BY fi.created_at DESC"""
            ).fetchall():
                result.append({
                    "profile_id": r["profile_id"],
                    "seed_photo_path": r["seed_photo_path"],
                    "name": r["real_name"] or "Unknown",
                    "source": "profile",
                })
        return result

    def cache_ai_result(self, img_hash: str, ai: dict, method: str = "claude_vision") -> None:
        """Store AI detection result in cache (called from api.py after async detection)."""
        try:
            with db() as conn:
                conn.execute(
                    """INSERT OR IGNORE INTO ai_detection_cache
                       (image_hash, is_ai_generated, confidence, detected_model, detection_method)
                       VALUES (?,?,?,?,?)""",
                    (img_hash, int(ai["is_ai"]), ai["confidence"],
                     ai.get("model_hint", "unknown"), method),
                )
        except Exception as e:
            print(f"[scoring] cache_ai_result error: {e}")

    def get_cached_ai(self, img_hash: str) -> Optional[dict]:
        """Return cached AI detection result or None."""
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
        return None

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
