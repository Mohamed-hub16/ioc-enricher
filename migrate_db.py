#!/usr/bin/env python3
"""
Database migration: add missing columns to ioc_records and backfill data.
Safe to run multiple times — skips columns that already exist.

Usage:
    python3 migrate_db.py
"""

import json
from dotenv import load_dotenv
load_dotenv()

from sqlalchemy import text
from webapp import create_app, db


NEW_COLUMNS = [
    # (name,                  sql_definition)
    ("verdict",               "VARCHAR(20)"),
    ("malware_family",        "VARCHAR(120)"),
    ("tlp",                   "VARCHAR(10)  DEFAULT 'WHITE'"),
    ("tags_json",             "TEXT"),
    ("score_breakdown_json",  "TEXT"),
]


def get_existing_columns(conn) -> set[str]:
    result = conn.execute(text("PRAGMA table_info(ioc_records)"))
    return {row[1] for row in result.fetchall()}


def main():
    app = create_app()
    with app.app_context():
        with db.engine.connect() as conn:

            # ── 1. Add missing columns ──────────────────────────────────
            existing = get_existing_columns(conn)
            added = []
            for name, defn in NEW_COLUMNS:
                if name in existing:
                    print(f"  ✓  {name} (déjà présente)")
                else:
                    conn.execute(text(
                        f"ALTER TABLE ioc_records ADD COLUMN {name} {defn}"
                    ))
                    conn.commit()
                    added.append(name)
                    print(f"  +  {name} ajoutée")

            # ── 2. Backfill verdict from threat_score ───────────────────
            r = conn.execute(text(
                "UPDATE ioc_records SET verdict = 'malicious' "
                "WHERE verdict IS NULL AND threat_score > 0"
            ))
            conn.commit()
            print(f"\n  verdict 'malicious' backfillé : {r.rowcount} ligne(s)")

            r = conn.execute(text(
                "UPDATE ioc_records SET verdict = 'clean' "
                "WHERE verdict IS NULL"
            ))
            conn.commit()
            print(f"  verdict 'clean'     backfillé : {r.rowcount} ligne(s)")

            # ── 3. Reset + backfill malware_family (strict sources only) ──
            conn.execute(text("UPDATE ioc_records SET malware_family = NULL"))
            conn.commit()
            print("  malware_family réinitialisé (données bruitées purgées)")

            rows = conn.execute(text(
                "SELECT id, raw_results FROM ioc_records WHERE raw_results IS NOT NULL"
            )).fetchall()

            from src.family_extractor import extract_label

            def _pick_family(results: list) -> str | None:
                vt = next((r.get("data") for r in results
                           if r.get("source") == "VirusTotal" and r.get("data")
                           and not r.get("error")), None)
                extra = [r for r in results
                         if r.get("source") in ("ThreatFox", "MalwareBazaar")]
                return extract_label(vt, extra)

            backfilled = 0
            for row_id, raw in rows:
                try:
                    results = json.loads(raw)
                except Exception:
                    continue

                family = _pick_family(results)

                if family:
                    conn.execute(text(
                        "UPDATE ioc_records SET malware_family = :fam WHERE id = :id"
                    ), {"fam": family, "id": row_id})
                    backfilled += 1

            conn.commit()
            print(f"  malware_family backfillé  : {backfilled} ligne(s)")

        print("\n✓ Migration terminée.")


if __name__ == "__main__":
    main()
