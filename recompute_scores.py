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


def _compute_threat_score(raw_results: list[dict]) -> int:
    """50% AbuseIPDB confidence + 50% VirusTotal detection ratio → 0-100."""
    abuse_score = None
    vt_score = None

    for res in raw_results:
        if res.get("error"):
            continue
        data = res.get("data", {})
        if res["source"] == "AbuseIPDB":
            abuse_score = data.get("abuse_confidence_score", 0) or 0
        elif res["source"] == "VirusTotal":
            malicious = data.get("malicious", 0) or 0
            total = data.get("total_engines", 0) or 0
            vt_score = round(malicious / total * 100) if total > 0 else 0

    if abuse_score is not None and vt_score is not None:
        return min(100, round(abuse_score * 0.5 + vt_score * 0.5))
    if abuse_score is not None:
        return min(100, int(abuse_score))
    if vt_score is not None:
        return min(100, int(vt_score))
    return 0


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
            if new_score != (record.threat_score or 0):
                print(f"  {record.value:<40} {record.threat_score or 0:>3} → {new_score}")
                record.threat_score = new_score
                updated += 1

        db.session.commit()
        print(f"\nTerminé : {updated} score(s) mis à jour.")


if __name__ == "__main__":
    main()
