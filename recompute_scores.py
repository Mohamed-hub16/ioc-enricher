#!/usr/bin/env python3
"""
One-shot script: recompute threat_score for all existing IOCRecords.
Run once after deploying the new scoring formula.

    python3 recompute_scores.py
"""

from dotenv import load_dotenv
load_dotenv()

from webapp import create_app, db
from webapp.models import IOCRecord
from webapp.ioc_routes import _compute_threat_score, _compute_score_breakdown


def main():
    app = create_app()
    with app.app_context():
        records = IOCRecord.query.all()
        print(f"{len(records)} IOC(s) trouvé(s) en base.")

        updated = 0
        for record in records:
            raw = record.get_results()
            if not raw:
                continue
            new_score = _compute_threat_score(raw)
            changed = False
            if new_score != (record.threat_score or 0):
                print(f"  {record.value:<40} {record.threat_score or 0:>3} → {new_score}")
                record.threat_score = new_score
                changed = True
            # Backfill verdict and score_breakdown for existing records
            if not record.verdict:
                record.verdict = "malicious" if new_score > 0 else "clean"
                changed = True
            if not record.score_breakdown_json:
                record.set_score_breakdown(_compute_score_breakdown(raw))
                changed = True
            if changed:
                updated += 1

        db.session.commit()
        print(f"\nTerminé : {updated} enregistrement(s) mis à jour.")


if __name__ == "__main__":
    main()
