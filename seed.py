"""
Seed the Scamnet database from db/seed_profiles.json.
Face photos are loaded from backend/seed_photos/<seed_photo> field in the profile.

Usage:
  python seed.py
  SCAMNET_DB=custom.db python seed.py
"""
import hashlib
import json
import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from database import init_db, db
from config import BASE_DIR

SEED_FILE = Path(__file__).parent.parent / "db" / "seed_profiles.json"
SEED_PHOTOS = Path(__file__).parent / "seed_photos"

# Hardcoded seed profiles — always seeded regardless of JSON file
BUILTIN_PROFILES = [
    {
        "id": "ivan-podnyakov",
        "type": "reported",
        "confidence": "high",
        "source": "Внутренняя база Scamnet",
        "source_url": None,
        "real_name": "Подняков Иван",
        "known_as": "Иван",
        "dob": None,
        "nationality": "RU",
        "current_status": "at_large",
        "charges": "Мошенничество (ст. 159 УК РФ)",
        "sentence": None,
        "verdict_date": None,
        "platforms": ["Tinder", "Instagram", "Telegram"],
        "target_regions": ["RU", "UZ", "KZ"],
        "known_aliases": ["Иван", "Ivan"],
        "tags": ["romance", "dating_app"],
        "victim_count": None,
        "total_damage_usd": None,
        "seed_photo": "ivan-podnyakov.jpg",
    },
]


def seed():
    print("[seed] Initialising database...")
    init_db()

    # Always seed builtin profiles first
    _seed_profiles(BUILTIN_PROFILES)

    # Then load optional JSON file if present
    if not SEED_FILE.exists():
        print(f"[seed] No seed file at {SEED_FILE} — skipping JSON import.")
        _insert_sample_companies()
        print("[seed] Done.")
        return

    with open(SEED_FILE, encoding="utf-8") as f:
        data = json.load(f)

    profiles = data if isinstance(data, list) else data.get("profiles", [])

    # Filter out IDs already covered by BUILTIN_PROFILES
    builtin_ids = {p["id"] for p in BUILTIN_PROFILES}
    profiles = [p for p in profiles if p.get("id") not in builtin_ids]

    inserted = 0
    skipped = 0

    for p in profiles:
        ri = p.get("real_identity", {})
        cr = p.get("criminal_record", {})
        vi = p.get("victims", {})

        real_name   = ri.get("real_name") or p.get("real_name")
        known_as    = ri.get("known_as")  or p.get("known_as")
        dob         = ri.get("dob")       or p.get("dob")
        nationality = ri.get("nationality") or p.get("nationality")
        cur_status  = ri.get("current_status") or p.get("current_status")
        charges     = cr.get("charges")   or p.get("charges")
        sentence    = cr.get("sentence")  or p.get("sentence")
        verdict_dt  = cr.get("verdict_date") or p.get("verdict_date")
        victim_cnt  = vi.get("total_count") or p.get("victim_count")
        damage      = vi.get("total_amount_usd") or p.get("total_damage_usd")

        with db() as conn:
            existing = conn.execute(
                "SELECT id FROM profiles WHERE id=?", (p["id"],)
            ).fetchone()
            if existing:
                skipped += 1
            else:
                conn.execute(
                    """INSERT INTO profiles
                       (id, type, confidence, source, source_url,
                        real_name, known_as, dob, nationality, current_status,
                        charges, sentence, verdict_date,
                        platforms, target_regions, known_aliases, tags,
                        victim_count, total_damage_usd)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        p["id"], p.get("type", "reported"), p.get("confidence", "medium"),
                        p.get("source"), p.get("source_url"),
                        real_name, known_as, dob, nationality, cur_status,
                        charges, sentence, verdict_dt,
                        json.dumps(p.get("platforms", []), ensure_ascii=False),
                        json.dumps(p.get("target_regions", []), ensure_ascii=False),
                        json.dumps(p.get("known_aliases", []), ensure_ascii=False),
                        json.dumps(p.get("tags", []), ensure_ascii=False),
                        victim_cnt, damage,
                    )
                )
                inserted += 1
                print(f"  [+] {p['id']} — {known_as or real_name or '(unnamed)'}")

        # Seed face photo if specified and file exists
        photo_file = p.get("seed_photo")
        if photo_file:
            photo_path = SEED_PHOTOS / photo_file
            if photo_path.exists():
                _seed_face_photo(p["id"], photo_path)
            else:
                print(f"  [!] {p['id']}: seed_photo '{photo_file}' not found in seed_photos/ — skipping face")

    print(f"[seed] Profiles: {inserted} inserted, {skipped} already existed.")
    _insert_sample_companies()
    print("[seed] Done.")


def _seed_profiles(profiles: list):
    """Insert profiles from a list of dicts (flat format, no nesting)."""
    for p in profiles:
        with db() as conn:
            existing = conn.execute("SELECT id FROM profiles WHERE id=?", (p["id"],)).fetchone()
            if not existing:
                conn.execute(
                    """INSERT INTO profiles
                       (id, type, confidence, source, source_url,
                        real_name, known_as, dob, nationality, current_status,
                        charges, sentence, verdict_date,
                        platforms, target_regions, known_aliases, tags,
                        victim_count, total_damage_usd)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        p["id"], p.get("type","reported"), p.get("confidence","medium"),
                        p.get("source"), p.get("source_url"),
                        p.get("real_name"), p.get("known_as"), p.get("dob"),
                        p.get("nationality"), p.get("current_status"),
                        p.get("charges"), p.get("sentence"), p.get("verdict_date"),
                        json.dumps(p.get("platforms",[]), ensure_ascii=False),
                        json.dumps(p.get("target_regions",[]), ensure_ascii=False),
                        json.dumps(p.get("known_aliases",[]), ensure_ascii=False),
                        json.dumps(p.get("tags",[]), ensure_ascii=False),
                        p.get("victim_count"), p.get("total_damage_usd"),
                    )
                )
                print(f"  [+] {p['id']} — {p.get('known_as') or p.get('real_name','?')}")
            else:
                print(f"  [=] {p['id']} already exists")

        photo_file = p.get("seed_photo")
        if photo_file:
            photo_path = SEED_PHOTOS / photo_file
            if photo_path.exists():
                _seed_face_photo(p["id"], photo_path)
            else:
                print(f"  [!] seed_photo '{photo_file}' not found in seed_photos/")


def _seed_face_photo(profile_id: str, photo_path: Path):
    """Register face photo reference in face_images and index into Rekognition."""
    try:
        from face import compute_phash, image_sha256, rek_index_face
        image_bytes = photo_path.read_bytes()
        img_hash = image_sha256(image_bytes)
        face_phash = compute_phash(image_bytes)

        already_in_db = False
        with db() as conn:
            existing = conn.execute(
                "SELECT id FROM face_images WHERE image_hash=?", (img_hash,)
            ).fetchone()
            if existing:
                print(f"  [=] {profile_id}: face reference already in DB")
                already_in_db = True
            else:
                conn.execute(
                    """INSERT INTO face_images (profile_id, seed_photo_path, image_hash, face_phash)
                       VALUES (?,?,?,?)""",
                    (profile_id, photo_path.name, img_hash, face_phash)
                )
                print(f"  [+] {profile_id}: face reference registered (no photo stored in DB)")

        # Always attempt Rekognition indexing — idempotent, safe to re-run
        rek_index_face(image_bytes, profile_id)

    except Exception as e:
        print(f"  [!] {profile_id}: failed to register face — {e}")


def _insert_sample_companies():
    """Insert a small set of known fraudulent broker/company names for demo."""
    companies = [
        ("BroFX Global", "broker", "offshore", "blacklisted", ["FCA warning", "CySEC revoked"], "Ponzi scheme, 2021"),
        ("CryptoVault Pro", "crypto_exchange", "unknown", "blacklisted", ["FinCEN alert"], "Exit scam, 2022"),
        ("RomanceCapital", "investment", "CY", "suspicious", [], "Multiple romance-fraud-linked accounts"),
        ("GlobalTrade24", "broker", "unknown", "blacklisted", ["ESMA warning"], "Unlicensed, cloned website"),
    ]
    with db() as conn:
        for name, ctype, country, status, flags, notes in companies:
            existing = conn.execute("SELECT id FROM companies WHERE name=?", (name,)).fetchone()
            if existing:
                continue
            conn.execute(
                """INSERT INTO companies (name, company_type, country, status, regulator_flags, notes)
                   VALUES (?,?,?,?,?,?)""",
                (name, ctype, country, status, json.dumps(flags, ensure_ascii=False), notes)
            )
            print(f"  [+] company: {name} ({status})")


if __name__ == "__main__":
    seed()
