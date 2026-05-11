import ipaddress
import logging
import os
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user

logger = logging.getLogger(__name__)

from webapp import db
from webapp.models import IOCRecord
from src.parsers.ioc_parser import parse_iocs
from src.enrichers import ENRICHERS_BY_TYPE
from src.synthesis import groq_synthesizer

ioc_bp = Blueprint("ioc", __name__)


def _is_private_ioc(value: str, ioc_type: str) -> bool:
    if ioc_type == "ip":
        try:
            ip = ipaddress.ip_address(value)
            return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
        except ValueError:
            return False
    if ioc_type == "domain":
        lower = value.lower()
        return lower == "localhost" or lower.endswith(".local") or lower.endswith(".internal")
    return False


def _compute_threat_score(raw_results: list[dict]) -> int:
    """Returns a 0-100 threat score: 50% AbuseIPDB confidence + 50% VirusTotal detection ratio."""
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


def _all_sources_failed(raw_results: list[dict]) -> bool:
    return bool(raw_results) and all(res.get("error") for res in raw_results)


def _enrich_ioc(value: str) -> tuple[str, list[dict], str | None]:
    iocs, _ = parse_iocs([value])
    if not iocs:
        raise ValueError(f"IOC non reconnu : {value!r}")

    ioc = iocs[0]
    enrichers = ENRICHERS_BY_TYPE.get(ioc.type, [])
    if not enrichers:
        raise ValueError(f"Aucun enrichisseur disponible pour le type '{ioc.type}'")

    result_objects = [fn(ioc) for fn in enrichers]
    raw = [{"source": r.source, "data": r.data, "error": r.error} for r in result_objects]
    threat_score = _compute_threat_score(raw)
    paragraph = groq_synthesizer.synthesize(result_objects, threat_score) if os.getenv("GROQ_API_KEY") else None
    return ioc.type, raw, paragraph, threat_score


@ioc_bp.route("/")
def index():
    q = request.args.get("q", "").strip()
    filt = request.args.get("filter", "all")  # all | malicious | legitimate

    query = IOCRecord.query.order_by(IOCRecord.enriched_at.desc())
    if q:
        query = query.filter(IOCRecord.value.ilike(f"%{q}%"))
    if filt == "malicious":
        query = query.filter(IOCRecord.threat_score > 0)
    elif filt == "legitimate":
        query = query.filter(IOCRecord.threat_score == 0)

    records = query.limit(100).all()

    counts = {
        "all": IOCRecord.query.count(),
        "malicious": IOCRecord.query.filter(IOCRecord.threat_score > 0).count(),
        "legitimate": IOCRecord.query.filter(IOCRecord.threat_score == 0).count(),
    }

    return render_template("index.html", records=records, q=q, filt=filt, counts=counts)


@ioc_bp.route("/ioc/<path:value>")
@login_required
def detail(value: str):
    if not current_user.is_approved:
        abort(403)
    record = IOCRecord.query.filter_by(value=value).first_or_404()
    record.view_count = (record.view_count or 0) + 1
    db.session.commit()
    return render_template("ioc_detail.html", record=record)


@ioc_bp.route("/enrich", methods=["GET", "POST"])
@login_required
def enrich():
    if not current_user.is_approved:
        flash("Votre compte n'est pas encore approuvé par un administrateur.", "warning")
        return redirect(url_for("ioc.index"))

    if request.method == "POST":
        value = request.form.get("ioc", "").strip()
        force = request.form.get("force") == "1"

        if not value:
            flash("Veuillez saisir un IOC.", "danger")
            return render_template("enrich.html")

        # Detect IOC type first to check for private addresses
        iocs, _ = parse_iocs([value])
        if not iocs:
            flash(f"IOC non reconnu : {value!r}", "danger")
            return render_template("enrich.html", prefill=value)

        ioc_type = iocs[0].type

        # Private / local IOC: no info available, don't save
        if _is_private_ioc(value, ioc_type):
            return render_template(
                "enrich.html",
                prefill=value,
                no_info=True,
                no_info_reason="Adresse privée ou locale (RFC1918 / loopback / .local)",
            )

        existing = IOCRecord.query.filter_by(value=value).first()
        if existing and not force and not existing.is_stale:
            flash(
                f"IOC déjà en base (enrichi il y a {existing.age_days} jour(s)). "
                "Résultat affiché depuis le cache.",
                "info",
            )
            return redirect(url_for("ioc.detail", value=value))

        try:
            ioc_type, raw, paragraph, threat_score = _enrich_ioc(value)
        except ValueError as exc:
            flash(str(exc), "danger")
            return render_template("enrich.html", prefill=value)
        except Exception as exc:
            logger.error("Enrichment error for %r: %s", value, exc)
            flash("Une erreur est survenue lors de l'enrichissement. Contactez un administrateur.", "danger")
            return render_template("enrich.html", prefill=value)

        # No data from any source: don't save, show info message
        if _all_sources_failed(raw):
            return render_template(
                "enrich.html",
                prefill=value,
                no_info=True,
                no_info_reason="Aucune source n'a retourné d'information pour cet IOC.",
            )

        if existing:
            existing.enriched_at = datetime.utcnow()
            existing.enriched_by = current_user.email
            existing.set_results(raw)
            existing.paragraph = paragraph
            existing.threat_score = threat_score
        else:
            record = IOCRecord(
                value=value,
                ioc_type=ioc_type,
                enriched_by=current_user.email,
                paragraph=paragraph,
                threat_score=threat_score,
            )
            record.set_results(raw)
            db.session.add(record)

        db.session.commit()
        flash("Enrichissement terminé avec succès.", "success")
        return redirect(url_for("ioc.detail", value=value))

    return render_template("enrich.html", prefill=request.args.get("ioc", ""))
