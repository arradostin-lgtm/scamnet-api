"""SQLite connection, schema init, and low-level helpers."""
import sqlite3
import json
from pathlib import Path
from contextlib import contextmanager
from typing import Generator

from config import DB_PATH

_SCHEMA = Path(__file__).parent / "schema.sql"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def db() -> Generator[sqlite3.Connection, None, None]:
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Create all tables from schema.sql if they don't exist, then run migrations."""
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as conn:
        conn.executescript(_SCHEMA.read_text())
        conn.commit()
    _migrate()
    print(f"[db] Initialised: {DB_PATH}")


def _migrate() -> None:
    """Incremental migrations — each is idempotent."""
    with get_connection() as conn:
        # m001: face_images — drop image_data blob, add seed_photo_path
        cols = {r[1] for r in conn.execute("PRAGMA table_info(face_images)")}
        if "image_data" in cols:
            print("[db] m001: migrating face_images → privacy schema")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS face_images_new (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    profile_id      TEXT REFERENCES profiles(id) ON DELETE CASCADE,
                    seed_photo_path TEXT,
                    image_hash      TEXT UNIQUE,
                    face_phash      TEXT,
                    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
                );
                INSERT INTO face_images_new (id, profile_id, image_hash, face_phash, created_at)
                    SELECT id, profile_id, image_hash, face_phash, created_at FROM face_images;
                DROP TABLE face_images;
                ALTER TABLE face_images_new RENAME TO face_images;
                CREATE INDEX IF NOT EXISTS idx_face_img_profile ON face_images(profile_id);
                CREATE INDEX IF NOT EXISTS idx_face_img_hash    ON face_images(image_hash);
            """)
            print("[db] m001: done — photo blobs removed from face_images")

        # m002: reported_faces — drop image_data blob
        cols = {r[1] for r in conn.execute("PRAGMA table_info(reported_faces)")}
        if "image_data" in cols:
            print("[db] m002: migrating reported_faces → privacy schema")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS reported_faces_new (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    image_hash      TEXT UNIQUE,
                    face_phash      TEXT NOT NULL,
                    known_name      TEXT,
                    scam_type       TEXT NOT NULL,
                    platform        TEXT,
                    description     TEXT,
                    amount_lost_usd REAL,
                    reporter_id     TEXT REFERENCES users(id),
                    report_count    INTEGER NOT NULL DEFAULT 1,
                    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
                );
                INSERT INTO reported_faces_new
                    (id, image_hash, face_phash, known_name, scam_type, platform,
                     description, amount_lost_usd, reporter_id, report_count, created_at)
                SELECT id, image_hash, face_phash, known_name, scam_type, platform,
                       description, amount_lost_usd, reporter_id, report_count, created_at
                FROM reported_faces;
                DROP TABLE reported_faces;
                ALTER TABLE reported_faces_new RENAME TO reported_faces;
                CREATE INDEX IF NOT EXISTS idx_reported_phash    ON reported_faces(face_phash);
                CREATE INDEX IF NOT EXISTS idx_reported_reporter ON reported_faces(reporter_id);
            """)
            print("[db] m002: done — photo blobs removed from reported_faces")
        # m003: face_checks — add check_reason column
        cols = {r[1] for r in conn.execute("PRAGMA table_info(face_checks)")}
        if "check_reason" not in cols:
            conn.execute("ALTER TABLE face_checks ADD COLUMN check_reason TEXT")
            print("[db] m003: added check_reason to face_checks")

        conn.commit()


# ── Generic helpers ────────────────────────────────────────────────────────────

def row_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    # Auto-parse JSON columns
    for k, v in d.items():
        if isinstance(v, str) and v.startswith(('[', '{')):
            try:
                d[k] = json.loads(v)
            except json.JSONDecodeError:
                pass
    return d


def json_col(value) -> str:
    """Serialize a list/dict to JSON string for storage."""
    if value is None:
        return "[]"
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)
