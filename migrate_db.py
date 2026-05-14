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

            import re as _re
            _GENERIC_SIGNERS = frozenset({
                "microsoft windows", "microsoft corporation", "windows", "verisign",
                "thawte", "digicert", "comodo", "sectigo", "globalsign", "entrust",
                "symantec", "certum", "ssl.com", "godaddy", "amazon",
            })
            _INFRA_TAGS = frozenset({"tor", "vpn", "proxy", "cdn", "anonymizer", "i2p", "bulletproof"})
            _GENERIC_FILENAMES = frozenset({
                "setup", "installer", "install", "update", "updater", "client", "app",
                "application", "service", "agent", "server", "host", "launcher", "loader",
                "helper", "patch", "tool", "main", "x64", "x86", "client64", "client32",
            })
            _CA_INDICATORS = ("certificate", "signing ca", "trusted root", "root ca",
                              "intermediate", " ca ", " ca\t")

            def _fname_to_label(fname: str) -> str | None:
                if not fname: return None
                name = _re.sub(r'\.[a-zA-Z]{2,4}$', '', fname.strip())
                name = _re.sub(r'[-_\s]+v?\d[\d.\-]*$', '', name, flags=_re.IGNORECASE).strip()
                name = _re.sub(r'[-_\s]*\(\d+\)$', '', name).strip()
                name = _re.sub(r'[-_\s]+\d{4}[-T\d.]+.*$', '', name).strip()
                name = name.replace('-', ' ').replace('_', ' ').strip()
                if name and name.lower() not in _GENERIC_FILENAMES and len(name) > 2:
                    return name[0].upper() + name[1:]
                return None

            def _pick_family(results: list) -> str | None:
                vt = next((r.get("data") for r in results
                           if r.get("source") == "VirusTotal" and r.get("data")
                           and not r.get("error")), None)
                if vt:
                    f = vt.get("popular_threat_label")
                    if f: return f
                    ptc = vt.get("popular_threat_classification")
                    if isinstance(ptc, dict) and ptc.get("label"):
                        return ptc["label"]
                for r in results:
                    if r.get("source") in ("ThreatFox", "MalwareBazaar") and r.get("data"):
                        items = r["data"].get("results") or []
                        f = ((items[0].get("malware_printable") or items[0].get("malware"))
                             if items else r["data"].get("signature"))
                        if f: return f
                if vt:
                    exif = vt.get("exiftool") or {}
                    product = (exif.get("ProductName") or exif.get("InternalName") or "").strip()
                    if product and len(product) > 2:
                        return product
                    label = _fname_to_label(vt.get("meaningful_name") or "")
                    if not label:
                        for fname in (vt.get("names") or []):
                            label = _fname_to_label(fname)
                            if label: break
                    if label: return label
                    sig = vt.get("signature_info") or {}
                    for signer in (sig.get("signers") or "").split(";"):
                        signer = signer.strip()
                        if not signer: continue
                        lower = signer.lower()
                        if any(ind in lower for ind in _CA_INDICATORS): continue
                        if lower in _GENERIC_SIGNERS: continue
                        for sfx in (" gmbh", " inc.", " inc", " llc", " ltd.", " ltd",
                                    " corp.", " corp", " corporation", " software", " s.a."):
                            if lower.endswith(sfx):
                                signer = signer[: len(signer) - len(sfx)].strip()
                                break
                        if signer and len(signer) > 3:
                            return signer
                    for tag in (vt.get("tags") or []):
                        if tag and tag.lower() in _INFRA_TAGS:
                            return tag.lower()
                return None

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
