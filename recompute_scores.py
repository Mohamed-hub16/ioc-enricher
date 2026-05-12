#!/usr/bin/env python3
"""Re-calcule threat_score + score_breakdown_json pour tous les IOCRecords.

À lancer une fois après une mise à jour de la formule de scoring
(ex: ajout de bonus GreyNoise / URLhaus / ThreatFox / MalwareBazaar).

Note : les anciens IOCs n'ayant pas été enrichis par les nouvelles sources
verront simplement leur score conservé tel quel (aucun bonus possible
sans données). Pour profiter du nouveau scoring, ré-enrichir.

    python3 recompute_scores.py
"""

import os
from dotenv import load_dotenv
load_dotenv()
os.environ.setdefault("SECRET_KEY", "test" * 16)

from webapp import create_app, db
from webapp.models import IOCRecord
from webapp.ioc_routes import _compute_score_breakdown


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
            bd = _compute_score_breakdown(raw)
            new_score = bd["total"]
            old_score = record.threat_score or 0
            if new_score != old_score:
                print(f"  {record.value:<40} {old_score:>3} → {new_score}")
                record.threat_score = new_score
            record.set_score_breakdown(bd)
            updated += 1

        db.session.commit()
        print(f"\nTerminé : {updated} record(s) traité(s).")


if __name__ == "__main__":
    main()
