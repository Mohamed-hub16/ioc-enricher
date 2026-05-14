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
