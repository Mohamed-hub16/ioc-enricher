import os
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user

from webapp import db
from webapp.models import IOCRecord
from src.parsers.ioc_parser import parse_iocs
from src.enrichers import ENRICHERS_BY_TYPE
from src.synthesis import groq_synthesizer

ioc_bp = Blueprint("ioc", __name__)


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
    paragraph = groq_synthesizer.synthesize(result_objects) if os.getenv("GROQ_API_KEY") else None
    return ioc.type, raw, paragraph


@ioc_bp.route("/")
def index():
    q = request.args.get("q", "").strip()
    query = IOCRecord.query.order_by(IOCRecord.enriched_at.desc())
    if q:
        query = query.filter(IOCRecord.value.ilike(f"%{q}%"))
    records = query.limit(100).all()
    return render_template("index.html", records=records, q=q)


@ioc_bp.route("/ioc/<path:value>")
def detail(value: str):
    record = IOCRecord.query.filter_by(value=value).first_or_404()
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

        existing = IOCRecord.query.filter_by(value=value).first()
        if existing and not force and not existing.is_stale:
            flash(
                f"IOC déjà en base (enrichi il y a {existing.age_days} jour(s)). "
                "Résultat affiché depuis le cache.",
                "info",
            )
            return redirect(url_for("ioc.detail", value=value))

        try:
            ioc_type, raw, paragraph = _enrich_ioc(value)
        except ValueError as exc:
            flash(str(exc), "danger")
            return render_template("enrich.html", prefill=value)
        except Exception as exc:
            flash(f"Erreur lors de l'enrichissement : {exc}", "danger")
            return render_template("enrich.html", prefill=value)

        if existing:
            existing.enriched_at = datetime.utcnow()
            existing.enriched_by = current_user.email
            existing.set_results(raw)
            existing.paragraph = paragraph
        else:
            record = IOCRecord(
                value=value,
                ioc_type=ioc_type,
                enriched_by=current_user.email,
                paragraph=paragraph,
            )
            record.set_results(raw)
            db.session.add(record)

        db.session.commit()
        flash("Enrichissement terminé avec succès.", "success")
        return redirect(url_for("ioc.detail", value=value))

    return render_template("enrich.html", prefill=request.args.get("ioc", ""))
