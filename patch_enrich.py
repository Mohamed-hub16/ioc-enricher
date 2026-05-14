#!/usr/bin/env python3
"""
Patch enrichment: for every IOCRecord in the database, run any enricher
whose source is NOT yet present in raw_results (i.e. it was added after
the record was originally enriched).

Safe to run multiple times — already-present sources are never re-called.

Usage:
    python3 patch_enrich.py            # all records
    python3 patch_enrich.py --dry-run  # show what would be patched, no API calls
    python3 patch_enrich.py --limit 50 # patch at most N records
"""

import argparse
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(
            os.path.join(os.path.dirname(__file__), "patch_enrich.log"), mode="a"
        ),
    ],
)
log = logging.getLogger("patch_enrich")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be patched without calling any API")
    parser.add_argument("--limit", type=int, default=0,
                        help="Max number of records to patch (0 = all)")
    args = parser.parse_args()

    from webapp import create_app, db
    from webapp.models import IOCRecord
    from src.enrichers import ENRICHERS_BY_TYPE, ENRICHER_SOURCE_NAME
    from src.parsers.ioc_parser import parse_iocs
    from webapp.ioc_routes import _compute_threat_score, _compute_score_breakdown

    app = create_app()
    with app.app_context():
        records = IOCRecord.query.order_by(IOCRecord.enriched_at.asc()).all()
        if args.limit:
            records = records[: args.limit]

        log.info("=== patch_enrich started — %d record(s) to scan ===", len(records))
        if args.dry_run:
            log.info("DRY RUN — no API calls will be made")

        patched = 0
        skipped = 0
        errors = 0

        for record in records:
            existing_sources = {
                r["source"]
                for r in record.get_results()
                if not r.get("error") and r.get("data")
            }
            enrichers_for_type = ENRICHERS_BY_TYPE.get(record.ioc_type, [])

            missing = [
                fn for fn in enrichers_for_type
                if ENRICHER_SOURCE_NAME.get(fn, "") not in existing_sources
            ]

            if not missing:
                skipped += 1
                continue

            missing_names = [ENRICHER_SOURCE_NAME.get(fn, "?") for fn in missing]
            log.info(
                "[%s] %s — manque : %s",
                record.ioc_type.upper(),
                record.value,
                ", ".join(missing_names),
            )

            if args.dry_run:
                patched += 1
                continue

            # Parse IOC
            iocs, _ = parse_iocs([record.value])
            if not iocs:
                log.warning("  → IOC non parseable, ignoré")
                errors += 1
                continue

            ioc = iocs[0]

            # Run missing enrichers in parallel (admin keys from .env only)
            new_result_objects = []
            with ThreadPoolExecutor(max_workers=4) as pool:
                futures = {pool.submit(fn, ioc, keys=None): fn for fn in missing}
                for future in as_completed(futures):
                    fn = futures[future]
                    src_name = ENRICHER_SOURCE_NAME.get(fn, "?")
                    try:
                        r = future.result()
                        new_result_objects.append(r)
                        if r.error:
                            log.warning("  → %s : erreur — %s", src_name, r.error)
                        else:
                            log.info("  → %s : OK", src_name)
                    except Exception as exc:
                        log.error("  → %s : exception — %s", src_name, exc)
                        errors += 1

            if not new_result_objects:
                continue

            # Merge into existing raw_results
            existing_raw = record.get_results()
            for r in new_result_objects:
                existing_raw.append({
                    "source": r.source,
                    "data":   r.data,
                    "error":  r.error,
                })
            record.set_results(existing_raw)

            # Recompute score
            new_score = _compute_threat_score(existing_raw)
            if new_score != (record.threat_score or 0):
                log.info(
                    "  → score : %d → %d",
                    record.threat_score or 0, new_score,
                )
            record.threat_score = new_score
            record.verdict = "malicious" if new_score > 0 else "clean"
            record.set_score_breakdown(_compute_score_breakdown(existing_raw))

            db.session.commit()
            patched += 1

            # Small pause to avoid hammering APIs between records
            time.sleep(0.5)

        log.info(
            "=== terminé — %d patché(s) · %d déjà complet(s) · %d erreur(s) ===",
            patched, skipped, errors,
        )


if __name__ == "__main__":
    main()
