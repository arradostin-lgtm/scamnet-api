-- Scamnet Database Schema v1.0
-- SQLite with JSON columns for arrays/metadata

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ─── USERS ────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,               -- UUID
    email       TEXT UNIQUE NOT NULL,
    name        TEXT,
    avatar_url  TEXT,
    google_id   TEXT UNIQUE,                    -- Google sub claim
    plan        TEXT NOT NULL DEFAULT 'free',   -- free | standard | invest
    checks_used INTEGER NOT NULL DEFAULT 0,
    checks_limit INTEGER NOT NULL DEFAULT 10,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    last_login  TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_google   ON users(google_id);

-- ─── SESSIONS / TOKENS ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,               -- opaque JWT or random token
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- ─── SCAMMER PROFILES ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS profiles (
    id              TEXT PRIMARY KEY,           -- SC-001, SC-002, ...
    type            TEXT NOT NULL               -- convicted | on_trial | reported | suspected
                        CHECK(type IN ('convicted','on_trial','reported','suspected')),
    confidence      TEXT NOT NULL DEFAULT 'medium'
                        CHECK(confidence IN ('high','medium','low')),
    source          TEXT,
    source_url      TEXT,

    -- Real identity
    real_name       TEXT,
    known_as        TEXT,                       -- primary alias
    dob             TEXT,
    nationality     TEXT,
    current_status  TEXT,                       -- released | convicted | at_large | under_investigation

    -- Criminal record
    charges         TEXT,
    sentence        TEXT,
    verdict_date    TEXT,

    -- Activity
    platforms       TEXT DEFAULT '[]',          -- JSON array: ["Tinder","Instagram"]
    target_regions  TEXT DEFAULT '[]',          -- JSON array: ["Russia","USA"]
    known_aliases   TEXT DEFAULT '[]',          -- JSON array
    tags            TEXT DEFAULT '[]',          -- JSON array

    -- Victim stats
    victim_count    INTEGER,
    total_damage_usd REAL,

    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_profiles_type ON profiles(type);
CREATE INDEX IF NOT EXISTS idx_profiles_confidence ON profiles(confidence);

-- ─── FACE EMBEDDINGS ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS face_embeddings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id      TEXT REFERENCES profiles(id) ON DELETE CASCADE,
    embedding       BLOB NOT NULL,              -- float32 numpy array (512-d InsightFace or 128-d face_recognition)
    embedding_dim   INTEGER NOT NULL DEFAULT 128,
    model           TEXT NOT NULL DEFAULT 'face_recognition',  -- face_recognition | insightface | deepface
    image_hash      TEXT UNIQUE,                -- SHA-256 of source image bytes
    source_url      TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_face_emb_profile ON face_embeddings(profile_id);
CREATE INDEX IF NOT EXISTS idx_face_emb_hash    ON face_embeddings(image_hash);

-- ─── VOICE EMBEDDINGS ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS voice_embeddings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id      TEXT REFERENCES profiles(id) ON DELETE CASCADE,
    embedding       BLOB NOT NULL,              -- float32 numpy array (256-d)
    embedding_dim   INTEGER NOT NULL DEFAULT 256,
    model           TEXT NOT NULL DEFAULT 'speechbrain',  -- speechbrain | resemblyzer
    audio_hash      TEXT UNIQUE,
    source          TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_voice_emb_profile ON voice_embeddings(profile_id);

-- ─── FACE CHECK LOG (crowdsource signal) ─────────────────────────────────────
-- Never stores original images — only perceptual hashes and anonymized sessions

CREATE TABLE IF NOT EXISTS face_checks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    face_phash      TEXT NOT NULL,              -- perceptual hash (pHash 64-bit hex)
    session_hash    TEXT NOT NULL,              -- SHA-256(ip + user_agent + date) — anonymous
    user_id         TEXT REFERENCES users(id),  -- NULL for anonymous checks
    country_code    TEXT,
    result_type     TEXT,                       -- match | partial | no_match | ai_generated
    matched_profile TEXT REFERENCES profiles(id),
    risk_score      REAL,
    check_date      TEXT NOT NULL DEFAULT (date('now'))
);

CREATE INDEX IF NOT EXISTS idx_checks_phash ON face_checks(face_phash);
CREATE INDEX IF NOT EXISTS idx_checks_date  ON face_checks(check_date);
CREATE INDEX IF NOT EXISTS idx_checks_user  ON face_checks(user_id);

-- ─── FACE STATS (denormalised for fast crowdsource lookup) ────────────────────

CREATE TABLE IF NOT EXISTS face_stats (
    face_phash          TEXT PRIMARY KEY,
    total_checks        INTEGER NOT NULL DEFAULT 0,
    unique_sessions     INTEGER NOT NULL DEFAULT 0,
    unique_users        INTEGER NOT NULL DEFAULT 0,
    match_count         INTEGER NOT NULL DEFAULT 0,
    ai_count            INTEGER NOT NULL DEFAULT 0,
    report_count        INTEGER NOT NULL DEFAULT 0,
    first_seen          TEXT,
    last_seen           TEXT,
    risk_level          TEXT DEFAULT 'unknown'  -- unknown | clean | warning | high | confirmed
);

-- ─── USER REPORTS ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    face_phash      TEXT,
    profile_id      TEXT REFERENCES profiles(id),
    reporter_id     TEXT REFERENCES users(id),
    scam_type       TEXT NOT NULL,              -- romance | investment | fake_job | consummation | gigolo | other
    platform        TEXT,
    amount_lost_usd REAL,
    currency        TEXT DEFAULT 'USD',
    description     TEXT NOT NULL,
    evidence_urls   TEXT DEFAULT '[]',          -- JSON array of image/doc URLs
    status          TEXT NOT NULL DEFAULT 'pending',  -- pending | verified | rejected
    moderator_note  TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_reports_phash   ON reports(face_phash);
CREATE INDEX IF NOT EXISTS idx_reports_profile ON reports(profile_id);
CREATE INDEX IF NOT EXISTS idx_reports_status  ON reports(status);

-- ─── AI DETECTION CACHE ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ai_detection_cache (
    image_hash          TEXT PRIMARY KEY,       -- SHA-256 of image bytes
    is_ai_generated     INTEGER NOT NULL,       -- 0/1 boolean
    confidence          REAL NOT NULL,          -- 0.0–1.0
    detected_model      TEXT,                   -- midjourney | dalle | stable_diffusion | stylegan | real
    detection_method    TEXT,                   -- freq_analysis | metadata | ensemble
    raw_scores          TEXT,                   -- JSON object with per-method scores
    analyzed_at         TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ─── COMPANY / BROKER REPUTATION ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS companies (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    aliases         TEXT DEFAULT '[]',          -- JSON array
    domain          TEXT,
    company_type    TEXT,                       -- broker | exchange | investment | recruiter | other
    country         TEXT,
    status          TEXT NOT NULL DEFAULT 'unknown',  -- blacklisted | suspicious | unknown | clean
    regulator_flags TEXT DEFAULT '[]',          -- JSON: ["FCA warning", "SEC action"]
    reports_count   INTEGER NOT NULL DEFAULT 0,
    source_urls     TEXT DEFAULT '[]',          -- JSON array
    notes           TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_companies_domain ON companies(domain);
CREATE INDEX IF NOT EXISTS idx_companies_status ON companies(status);

-- ─── SCORING AUDIT LOG ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS score_audit (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    check_id        INTEGER REFERENCES face_checks(id),
    face_phash      TEXT,
    score_total     REAL NOT NULL,
    score_breakdown TEXT NOT NULL,              -- JSON: {db_match, crowdsource, reports, ai_flag}
    risk_level      TEXT NOT NULL,
    computed_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ─── TRIGGERS: keep updated_at fresh ─────────────────────────────────────────

CREATE TRIGGER IF NOT EXISTS profiles_updated
    AFTER UPDATE ON profiles
    BEGIN UPDATE profiles SET updated_at = datetime('now') WHERE id = NEW.id; END;

CREATE TRIGGER IF NOT EXISTS reports_updated
    AFTER UPDATE ON reports
    BEGIN UPDATE reports SET updated_at = datetime('now') WHERE id = NEW.id; END;

-- ─── TRIGGER: update face_stats on new check ──────────────────────────────────

CREATE TRIGGER IF NOT EXISTS update_face_stats
AFTER INSERT ON face_checks
BEGIN
    INSERT INTO face_stats(face_phash, total_checks, unique_sessions, unique_users,
                           match_count, ai_count, first_seen, last_seen, risk_level)
    VALUES (NEW.face_phash, 1,
            CASE WHEN NEW.session_hash NOT IN
                (SELECT session_hash FROM face_checks WHERE face_phash = NEW.face_phash AND id != NEW.id) THEN 1 ELSE 0 END,
            CASE WHEN NEW.user_id IS NOT NULL THEN 1 ELSE 0 END,
            CASE WHEN NEW.result_type IN ('match','partial') THEN 1 ELSE 0 END,
            CASE WHEN NEW.result_type = 'ai_generated' THEN 1 ELSE 0 END,
            date('now'), date('now'), 'unknown')
    ON CONFLICT(face_phash) DO UPDATE SET
        total_checks    = total_checks + 1,
        match_count     = match_count + (CASE WHEN NEW.result_type IN ('match','partial') THEN 1 ELSE 0 END),
        ai_count        = ai_count + (CASE WHEN NEW.result_type = 'ai_generated' THEN 1 ELSE 0 END),
        last_seen       = date('now');
END;
