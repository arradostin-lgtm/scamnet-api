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
    """Create all tables from schema.sql if they don't exist."""
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as conn:
        conn.executescript(_SCHEMA.read_text())
        conn.commit()
    print(f"[db] Initialised: {DB_PATH}")


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
