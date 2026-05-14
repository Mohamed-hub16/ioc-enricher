import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Blueprint, render_template, redirect, url_for, flash, abort, current_app
from flask_login import login_required, current_user
from webapp import db
from webapp.models import User, IOCRecord

log = logging.getLogger(__name__)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def _require_admin() -> None:
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)


@admin_bp.route("/users")
@login_required
def users():
    _require_admin()
    pending = User.query.filter_by(role="pending").order_by(User.created_at).all()
    approved = User.query.filter(User.role != "pending").order_by(User.created_at).all()
    return render_template("admin.html", pending=pending, approved=approved)


@admin_bp.route("/approve/<int:user_id>", methods=["POST"])
@login_required
def approve(user_id: int):
    _require_admin()
    user = User.query.get_or_404(user_id)
    user.role = "analyst"
    db.session.commit()
    flash(f"{user.email} approuvé comme analyste.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/reject/<int:user_id>", methods=["POST"])
@login_required
def reject(user_id: int):
    _require_admin()
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f"Compte {user.email} supprimé.", "info")
    return redirect(url_for("admin.users"))


@admin_bp.route("/revoke/<int:user_id>", methods=["POST"])
@login_required
def revoke(user_id: int):
    _require_admin()
    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash("Impossible de révoquer un administrateur.", "danger")
        return redirect(url_for("admin.users"))
    user.role = "pending"
    db.session.commit()
    flash(f"Accès révoqué pour {user.email}.", "warning")
    return redirect(url_for("admin.users"))


# ── Maintenance ────────────────────────────────────────────────────────────

@admin_bp.route("/migrate-db", methods=["POST"])
@login_required
def migrate_db():
    """Add missing columns to ioc_records and backfill malware_family / verdict."""
    _require_admin()
    from sqlalchemy import text
    import json as _json

    new_columns = [
        ("verdict",               "VARCHAR(20)"),
        ("malware_family",        "VARCHAR(120)"),
        ("tlp",                   "VARCHAR(10)  DEFAULT 'WHITE'"),
        ("tags_json",             "TEXT"),
        ("score_breakdown_json",  "TEXT"),
    ]

    added = []
    with db.engine.connect() as conn:
        existing = {row[1] for row in conn.execute(text("PRAGMA table_info(ioc_records)")).fetchall()}

        for name, defn in new_columns:
            if name not in existing:
                conn.execute(text(f"ALTER TABLE ioc_records ADD COLUMN {name} {defn}"))
                conn.commit()
                added.append(name)

        conn.execute(text(
            "UPDATE ioc_records SET verdict='malicious' WHERE verdict IS NULL AND threat_score > 0"
        ))
        conn.execute(text(
            "UPDATE ioc_records SET verdict='clean' WHERE verdict IS NULL"
        ))
        conn.commit()

        # Reset all family data — re-backfill from scratch with strict logic
        conn.execute(text("UPDATE ioc_records SET malware_family = NULL"))
        conn.commit()

        rows = conn.execute(text(
            "SELECT id, raw_results FROM ioc_records WHERE raw_results IS NOT NULL"
        )).fetchall()

        from src.family_extractor import extract_label

        def _pick_family(results_json: list) -> str | None:
            vt = next((r.get("data") for r in results_json
                       if r.get("source") == "VirusTotal" and r.get("data")
                       and not r.get("error")), None)
            extra = [r for r in results_json
                     if r.get("source") in ("ThreatFox", "MalwareBazaar")]
            return extract_label(vt, extra)

        backfilled = 0
        for row_id, raw in rows:
            try:
                results_data = _json.loads(raw)
            except Exception:
                continue
            family = _pick_family(results_data)
            if family:
                conn.execute(text(
                    "UPDATE ioc_records SET malware_family=:f WHERE id=:i"
                ), {"f": family, "i": row_id})
                backfilled += 1

        conn.commit()

    parts = []
    if added:
        parts.append(f"{len(added)} colonne(s) ajoutée(s) : {', '.join(added)}")
    else:
        parts.append("schéma déjà à jour")
    parts.append(f"{backfilled} famille(s) détectée(s) (données erronées purgées)")
    flash("Migration terminée — " + " · ".join(parts), "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/recompute-scores", methods=["POST"])
@login_required
def recompute_scores():
    """Recalculate threat scores from existing raw_results — no API calls."""
    _require_admin()
    from webapp.ioc_routes import _compute_threat_score, _compute_score_breakdown
    records = IOCRecord.query.all()
    updated = 0
    for record in records:
        raw = record.get_results()
        if not raw:
            continue
        new_score = _compute_threat_score(raw)
        changed = new_score != (record.threat_score or 0)
        record.threat_score = new_score
        if not record.verdict:
            record.verdict = "malicious" if new_score > 0 else "clean"
            changed = True
        if not record.score_breakdown_json:
            record.set_score_breakdown(_compute_score_breakdown(raw))
            changed = True
        if changed:
            updated += 1
    db.session.commit()
    flash(f"Scores recalculés — {updated} enregistrement(s) mis à jour.", "success")
    return redirect(url_for("admin.users"))


def _do_patch_enrich(app) -> None:
    """Patch IOCRecords missing new enricher sources. Runs in a background thread."""
    from src.enrichers import ENRICHERS_BY_TYPE, ENRICHER_SOURCE_NAME
    from src.parsers.ioc_parser import parse_iocs
    from webapp.ioc_routes import _compute_threat_score, _compute_score_breakdown

    with app.app_context():
        records = IOCRecord.query.all()
        log.info("[patch_enrich] scanning %d record(s)…", len(records))
        patched = 0

        for record in records:
            existing = {
                r["source"] for r in record.get_results()
                if not r.get("error") and r.get("data")
            }
            missing_fns = [
                fn for fn in ENRICHERS_BY_TYPE.get(record.ioc_type, [])
                if ENRICHER_SOURCE_NAME.get(fn, "") not in existing
            ]
            if not missing_fns:
                continue

            iocs, _ = parse_iocs([record.value])
            if not iocs:
                continue
            ioc = iocs[0]

            new_results = []
            with ThreadPoolExecutor(max_workers=4) as pool:
                futures = {pool.submit(fn, ioc, keys=None): fn for fn in missing_fns}
                for future in as_completed(futures):
                    fn = futures[future]
                    src = ENRICHER_SOURCE_NAME.get(fn, "?")
                    try:
                        r = future.result()
                        new_results.append(r)
                        log.info("[patch_enrich] %s ← %s %s",
                                 record.value, src, "OK" if not r.error else r.error)
                    except Exception as exc:
                        log.error("[patch_enrich] %s ← %s error: %s", record.value, src, exc)

            if not new_results:
                continue

            raw = record.get_results()
            for r in new_results:
                raw.append({"source": r.source, "data": r.data, "error": r.error})
            record.set_results(raw)
            new_score = _compute_threat_score(raw)
            record.threat_score = new_score
            record.verdict = "malicious" if new_score > 0 else "clean"
            record.set_score_breakdown(_compute_score_breakdown(raw))
            db.session.commit()
            patched += 1
            time.sleep(0.3)

        log.info("[patch_enrich] done — %d record(s) patched", patched)


@admin_bp.route("/patch-enrich", methods=["POST"])
@login_required
def patch_enrich():
    """Launch background enrichment for IOCs missing new sources (ThreatFox, etc.)."""
    _require_admin()
    app = current_app._get_current_object()
    t = threading.Thread(target=_do_patch_enrich, args=(app,), daemon=True)
    t.start()
    flash(
        "Patch enrichissement lancé en arrière-plan — "
        "progression visible dans les logs serveur (error log PythonAnywhere).",
        "info",
    )
    return redirect(url_for("admin.users"))
