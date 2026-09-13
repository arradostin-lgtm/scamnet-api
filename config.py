import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

BASE_DIR = Path(__file__).parent.parent

# ── Database ──────────────────────────────────────────────────────────────────
DB_PATH = os.getenv("SCAMNET_DB", str(BASE_DIR / "db" / "scamnet.db"))

# ── Google OAuth ──────────────────────────────────────────────────────────────
GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI  = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback")

# ── JWT ───────────────────────────────────────────────────────────────────────
JWT_SECRET      = os.getenv("JWT_SECRET", "change-me-in-production-32-bytes!!!")
JWT_ALGORITHM   = "HS256"
JWT_EXPIRE_DAYS = 30

# ── Face embedding ────────────────────────────────────────────────────────────
FACE_MODEL           = os.getenv("FACE_MODEL", "face_recognition")   # face_recognition | insightface
FACE_MATCH_THRESHOLD = float(os.getenv("FACE_MATCH_THRESHOLD", "0.55"))   # cosine distance ≤ this → match
FACE_HIGH_THRESHOLD  = float(os.getenv("FACE_HIGH_THRESHOLD", "0.45"))    # very high confidence match

# ── Voice embedding ───────────────────────────────────────────────────────────
VOICE_MODEL           = os.getenv("VOICE_MODEL", "resemblyzer")
VOICE_MATCH_THRESHOLD = float(os.getenv("VOICE_MATCH_THRESHOLD", "0.75"))  # cosine similarity ≥ this → match

# ── Scoring weights ───────────────────────────────────────────────────────────
# Each component contributes up to its MAX points to a 0–100 total score
SCORE_DB_MATCH_MAX      = 60   # direct DB hit
SCORE_CROWDSOURCE_MAX   = 25   # unique people who checked this face
SCORE_REPORTS_MAX       = 20   # verified user reports
SCORE_AI_FLAG           = 20   # AI-generated image detected

# Crowdsource thresholds
CROWD_WARNING_CHECKS    = 2    # ≥ 2 unique sessions → warning
CROWD_HIGH_CHECKS       = 5    # ≥ 5 unique sessions → high risk

# Risk level boundaries (total score 0–100)
RISK_CLEAN_MAX      = 15
RISK_WARNING_MAX    = 45
RISK_HIGH_MAX       = 79
# ≥ 80 → confirmed

# ── API ───────────────────────────────────────────────────────────────────────
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000,https://scamnet.uz").split(",")
