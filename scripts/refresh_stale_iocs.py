#!/usr/bin/env python3
"""
Re-enriches all IOCs older than STALE_DAYS using server-level API keys (env vars).

Schedule this on PythonAnywhere every 14 days:
  PythonAnywhere → Tasks → Add scheduled task
  Command: /home/<pa_user>/.virtualenvs/<venv>/bin/python /home/<pa_user>/ioc-enricher/scripts/refresh_stale_iocs.py
  Interval: Monthly (or every 14 days via a daily task that checks internally)
"""

import sys
import os

# Allow running from any working directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"))

from app import app
from webapp import db
from webapp.models import IOCRecord, STALE_DAYS
from webapp.ioc_routes import _enrich_ioc
from datetime import datetime


def refresh_all_stale():
    with app.app_context():
        stale = IOCRecord.query.filter(IOCRecord.is_stale_expr()).all() if hasattr(IOCRecord, "is_stale_expr") else _get_stale()
        print(f"[refresh] {len(stale)} IOC(s) à rafraîchir (> {STALE_DAYS} jours)")

        for record in stale:
            try:
                print(f"  → {record.value} ({record.ioc_type}) ...", end=" ", flush=True)
                ioc_type, raw, paragraph, threat_score = _enrich_ioc(record.value, keys=None)
                record.enriched_at = datetime.utcnow()
                record.enriched_by = "auto-refresh"
                record.set_results(raw)
                record.paragraph = paragraph
                record.threat_score = threat_score
                db.session.commit()
                print("OK")
            except Exception as exc:
                db.session.rollback()
                print(f"ERREUR — {exc}")

        print(f"[refresh] Terminé.")


def _get_stale():
    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(days=STALE_DAYS)
    return IOCRecord.query.filter(IOCRecord.enriched_at < cutoff).all()


if __name__ == "__main__":
    refresh_all_stale()
