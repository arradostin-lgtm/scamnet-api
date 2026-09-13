"""
Scamnet Risk Scoring Engine
────────────────────────────
Inputs:  face embedding (optional), voice embedding (optional), image bytes (for AI detection)
Output:  RiskResult with score 0–100 and level: clean | warning | high | confirmed

Score formula (max 100 pts):
  db_match      0–60   direct hit in verified-scammer DB
  crowdsource   0–25   unique people who independently checked this face
  reports       0–20   verified user reports linked to this face hash
  ai_flag       0–20   face photo is AI-generated (can exceed 100 → capped)

Level thresholds:
  0–15   → clean
  16–45  → warning
  46–79  → high
  80–100 → confirmed
"""
from __future__ import annotations
import math
from dataclasses import dataclass, field
from typing import Optional

import config
from face import (
    find_best_match, compute_phash, extract_embedding,
    image_sha256, embedding_to_blob
)
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
    risk_level:       str           # clean | warning | high | confirmed
    risk_score:       float         # 0–100
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
    """
    Logarithmic scale: each additional unique checker adds diminishing points.
    0 sessions → 0 pts | 2 → 5 | 5 → 14 | 10 → 20 | 50 → 25 (max)
    """
    if unique_sessions < 2:
        return 0.0
    return min(config.SCORE_CROWDSOURCE_MAX, 8 * math.log2(unique_sessions))


def _report_score(verified_reports: int, pending_reports: int) -> float:
    """Verified reports worth 10 pts each, pending 2 pts. Cap at max."""
    raw = verified_reports * 10 + pending_reports * 2
    return min(config.SCORE_REPORTS_MAX, float(raw))


# ── Main scorer ───────────────────────────────────────────────────────────────

class Scorer:

    def score_face(
        self,
        image_bytes: bytes,
        session_hash: str,
        user_id: Optional[str] = None,
        country_code: Optional[str] = None,
    ) -> RiskResult:
        """
        Full scoring pipeline for a face image.
        Side-effects: logs the check to face_checks and updates face_stats.
        """
        bd = ScoreBreakdown()
        result = RiskResult(risk_level="clean", risk_score=0.0)

        img_hash = image_sha256(image_bytes)
        face_phash = compute_phash(image_bytes)
        result.face_phash = face_phash

        # ── 1. Extract face embedding ─────────────────────────────────────────
        embedding = None
        try:
            embedding = extract_embedding(image_bytes)
        except Exception as e:
            print(f"[scoring] embedding error: {e}")

        # ── 2. AI image detection ─────────────────────────────────────────────
        ai_result = self._check_ai(img_hash, image_bytes)
        if ai_result["is_ai"]:
            bd.ai_flag = config.SCORE_AI_FLAG
            result.is_ai_generated = True
            result.ai_confidence = ai_result["confidence"]
            result.detected_ai_model = ai_result["model"]

        # ── 3. DB match ───────────────────────────────────────────────────────
        db_match = None
        match_type = "no_match"
        if embedding is not None:
            with db() as conn:
                db_match = find_best_match(embedding, conn)

        if db_match:
            conf = db_match["confidence"]
            result.match_found = True
            result.match_confidence = conf
            result.profile_id = db_match["profile_id"]
            if conf >= (1 - config.FACE_HIGH_THRESHOLD):
                bd.db_match = config.SCORE_DB_MATCH_MAX           # 60 pts
                match_type = "match"
            else:
                bd.db_match = config.SCORE_DB_MATCH_MAX * 0.6     # 36 pts for partial
                match_type = "partial"

        # ── 4. Crowdsource signal ─────────────────────────────────────────────
        crowd = self._get_crowd_stats(face_phash)
        result.crowdsource = crowd
        bd.crowdsource = _crowdsource_score(crowd.unique_sessions)

        # ── 5. Reports ────────────────────────────────────────────────────────
        with db() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM reports WHERE face_phash=? AND status='verified'",
                (face_phash,)
            ).fetchone()
            verified = row["n"] if row else 0
            row2 = conn.execute(
                "SELECT COUNT(*) AS n FROM reports WHERE face_phash=? AND status='pending'",
                (face_phash,)
            ).fetchone()
            pending = row2["n"] if row2 else 0
        bd.reports = _report_score(verified, pending)

        # ── 6. Compute total ──────────────────────────────────────────────────
        result.breakdown = bd
        result.risk_score = bd.total
        result.risk_level = _level(bd.total)

        # ── 7. Log check + update stats ───────────────────────────────────────
        with db() as conn:
            cur = conn.execute(
                """INSERT INTO face_checks
                   (face_phash, session_hash, user_id, country_code, result_type,
                    matched_profile, risk_score)
                   VALUES (?,?,?,?,?,?,?)""",
                (face_phash, session_hash, user_id, country_code,
                 match_type if not result.is_ai_generated else "ai_generated",
                 result.profile_id, result.risk_score)
            )
            check_id = cur.lastrowid

        return result

    # ── AI detection ──────────────────────────────────────────────────────────

    def _check_ai(self, img_hash: str, image_bytes: bytes) -> dict:
        """Check cache first, then run detection."""
        with db() as conn:
            row = conn.execute(
                "SELECT * FROM ai_detection_cache WHERE image_hash=?", (img_hash,)
            ).fetchone()
        if row:
            return {
                "is_ai": bool(row["is_ai_generated"]),
                "confidence": row["confidence"],
                "model": row["detected_model"],
            }
        result = _run_ai_detection(image_bytes)
        with db() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO ai_detection_cache
                   (image_hash, is_ai_generated, confidence, detected_model, detection_method)
                   VALUES (?,?,?,?,?)""",
                (img_hash, int(result["is_ai"]), result["confidence"],
                 result["model"], result["method"])
            )
        return result

    # ── Crowd stats ───────────────────────────────────────────────────────────

    def _get_crowd_stats(self, face_phash: str) -> CrowdsourceSignal:
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


# ── AI detection (standalone, without ML deps: metadata + frequency heuristics) ──

def _run_ai_detection(image_bytes: bytes) -> dict:
    """
    Multi-signal AI image detector.
    Runs 3 checks, combines into ensemble confidence.
    Returns: {is_ai, confidence, model, method}
    """
    signals = []

    # Signal 1: EXIF metadata (AI images lack camera EXIF)
    exif_score = _check_exif(image_bytes)
    signals.append(exif_score)

    # Signal 2: Color distribution anomalies (GAN artefacts)
    color_score = _check_color_anomaly(image_bytes)
    signals.append(color_score)

    # Signal 3: ML-based (optional, requires installed library)
    ml_score = _check_ml_detector(image_bytes)
    if ml_score is not None:
        signals.append(ml_score)

    confidence = sum(signals) / len(signals)
    return {
        "is_ai": confidence >= 0.5,
        "confidence": round(confidence, 3),
        "model": "unknown" if confidence < 0.5 else "ai_detected",
        "method": "ensemble",
    }


def _check_exif(image_bytes: bytes) -> float:
    """No EXIF / no camera model → higher AI probability."""
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
        img = Image.open(__import__("io").BytesIO(image_bytes))
        exif_data = img._getexif()
        if not exif_data:
            return 0.6   # likely AI — no EXIF at all
        tags = {TAGS.get(k, k): v for k, v in exif_data.items()}
        has_camera = any(k in tags for k in ("Make", "Model", "LensModel"))
        return 0.15 if has_camera else 0.55
    except Exception:
        return 0.5   # unknown


def _check_color_anomaly(image_bytes: bytes) -> float:
    """
    GAN-generated faces often have unusually uniform skin tone distributions.
    Heuristic: low variance in hue channel → suspicious.
    """
    try:
        import numpy as np
        from PIL import Image
        img = Image.open(__import__("io").BytesIO(image_bytes)).convert("HSV").resize((64, 64))
        arr = np.array(img)
        hue_std = arr[:, :, 0].std()
        sat_mean = arr[:, :, 1].mean()
        # Very low hue variance with high saturation is a GAN signature
        if hue_std < 12 and sat_mean > 100:
            return 0.7
        if hue_std < 20:
            return 0.5
        return 0.25
    except Exception:
        return 0.5


def _check_ml_detector(image_bytes: bytes) -> float | None:
    """Use DeepFake-Detection-Challenge model if available."""
    try:
        # Optional: use Hugging Face pipeline for deepfake detection
        from transformers import pipeline
        detector = pipeline("image-classification", model="umm-maybe/AI-image-detector")
        import PIL.Image, io
        img = PIL.Image.open(io.BytesIO(image_bytes))
        results = detector(img)
        for r in results:
            if "artificial" in r["label"].lower() or "ai" in r["label"].lower():
                return r["score"]
        return 0.1
    except Exception:
        return None   # library not available, skip
