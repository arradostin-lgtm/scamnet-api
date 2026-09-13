"""
Seed the Scamnet database from db/seed_profiles.json.

Usage:
  python seed.py                    # uses default DB from config
  SCAMNET_DB=custom.db python seed.py

JSON format (array of profile objects):
{
  "id": "simon-leviev",
  "type": "convicted",             # convicted | on_trial | reported | suspected
  "confidence": "high",            # high | medium | low
  "real_name": "Shimon Hayut",
  "known_as": "Simon Leviev",
  "dob": "1990-11-26",
  "nationality": "IL",
  "current_status": "released",
  "charges": "fraud, forgery",
  "sentence": "5 months (served)",
  "verdict_date": "2019-12-01",
  "platforms": ["Tinder", "Instagram"],
  "target_regions": ["NO", "SE", "DE", "RU"],
  "known_aliases": ["The Tinder Swindler"],
  "tags": ["romance", "investment"],
  "victim_count": 10,
  "total_damage_usd": 10000000,
  "source": "Netflix, Haaretz",
  "source_url": "https://example.com/article"
}
"""
import json
import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from database import init_db, db
from config import BASE_DIR

SEED_FILE = Path(__file__).parent.parent / "db" / "seed_profiles.json"


def seed():
    print("[seed] Initialising database...")
    init_db()

    if not SEED_FILE.exists():
        print(f"[seed] No seed file found at {SEED_FILE} — skipping profile import.")
        _insert_sample_companies()
        print("[seed] Done.")
        return

    with open(SEED_FILE, encoding="utf-8") as f:
        profiles = json.load(f)

    inserted = 0
    skipped = 0

    with db() as conn:
        for p in profiles:
            existing = conn.execute(
                "SELECT id FROM profiles WHERE id=?", (p["id"],)
            ).fetchone()
            if existing:
                skipped += 1
                continue

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
                    p.get("real_name"), p.get("known_as"), p.get("dob"),
                    p.get("nationality"), p.get("current_status"),
                    p.get("charges"), p.get("sentence"), p.get("verdict_date"),
                    json.dumps(p.get("platforms", []), ensure_ascii=False),
                    json.dumps(p.get("target_regions", []), ensure_ascii=False),
                    json.dumps(p.get("known_aliases", []), ensure_ascii=False),
                    json.dumps(p.get("tags", []), ensure_ascii=False),
                    p.get("victim_count"), p.get("total_damage_usd"),
                )
            )
            inserted += 1
            print(f"  [+] {p['id']} — {p.get('known_as') or p.get('real_name', '(unnamed)')}")

    print(f"[seed] Profiles: {inserted} inserted, {skipped} already existed.")

    _insert_sample_companies()
    print("[seed] Done.")


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
