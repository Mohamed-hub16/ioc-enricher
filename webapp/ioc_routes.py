import ipaddress
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, send_file, jsonify
from flask_login import login_required, current_user

logger = logging.getLogger(__name__)

from webapp import db
from webapp.models import IOCRecord, Comment
from src.parsers.ioc_parser import parse_iocs
from src.enrichers import ENRICHERS_BY_TYPE
from src.synthesis import groq_synthesizer

ioc_bp = Blueprint("ioc", __name__)

_MAX_FILE_BYTES = 512 * 1024   # 512 Ko
_MAX_BATCH      = 30


def _parse_upload(file_storage) -> tuple[list[str], str | None]:
    """Validate and parse an uploaded .txt file. Returns (values, error_message)."""
    filename = file_storage.filename or ""

    # 1. Extension — whitelist strict
    if not filename.lower().endswith(".txt"):
        return [], "Seuls les fichiers .txt sont acceptés."

    # 2. Read at most MAX+1 bytes to detect oversized files without loading everything
    raw_bytes = file_storage.read(_MAX_FILE_BYTES + 1)
    if len(raw_bytes) > _MAX_FILE_BYTES:
        return [], "Fichier trop volumineux (maximum 512 Ko)."

    # 3. Decode as UTF-8 — reject binary / unexpected encodings
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return [], "Fichier illisible — encodage non supporté (UTF-8 attendu)."

    # 4. Parse lines — strip inline comments and blanks
    values = []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if line:
            values.append(line)

    if not values:
        return [], "Fichier vide (aucun IOC trouvé — les lignes débutant par # sont ignorées)."

    if len(values) > _MAX_BATCH:
        return [], (
            f"Trop d'IOCs dans le fichier ({len(values)}) — "
            f"maximum {_MAX_BATCH} par import."
        )

    return values, None


def _parse_text_input(raw: str) -> list[str]:
    """Split a free-text input on commas and/or newlines, deduplicate, preserve order."""
    seen: set[str] = set()
    result: list[str] = []
    for part in re.split(r"[,\n\r]+", raw):
        part = part.strip()
        if part and part not in seen:
            seen.add(part)
            result.append(part)
    return result


def _fmt_ts(v) -> str:
    if not v:
        return "—"
    try:
        return datetime.utcfromtimestamp(int(v)).strftime("%Y-%m-%d")
    except Exception:
        return str(v)[:10]


def _build_summary(results: list[dict], ioc_type: str, ioc_value: str) -> dict | None:
    """Build the quick-summary table data for the IOC detail page."""
    src = {
        r["source"]: r.get("data") or {}
        for r in results
        if not r.get("error") and r.get("data")
    }
    vt  = src.get("VirusTotal", {})
    mal = vt.get("malicious", 0) or 0
    tot = vt.get("total_engines", 0) or 0
    vt_str = f"{mal}/{tot}" if tot else "—"

    if ioc_type == "ip":
        abuse = src.get("AbuseIPDB", {})
        ipapi = src.get("ip-api.com", {})
        asn_num = vt.get("asn") or ipapi.get("asn") or ""
        abuse_sc = abuse.get("abuse_confidence_score")
        fields = [
            ("IP",              ioc_value),
            ("Score AbuseIPDB", f"{abuse_sc}%" if abuse_sc is not None else "—"),
            ("Score VT",        vt_str),
            ("ISP",             ipapi.get("isp") or abuse.get("isp") or "—"),
            ("Usage Type",      ipapi.get("network_type") or "—"),
            ("ASN",             f"AS{asn_num}" if asn_num else "—"),
            ("AS Owner",        vt.get("as_owner") or ipapi.get("as_name") or "—"),
            ("Réseau",          vt.get("network") or "—"),
            ("Reverse DNS",     ipapi.get("reverse_dns") or "—"),
            ("Country",         ipapi.get("country") or abuse.get("country_name") or "—"),
            ("City",            ipapi.get("city") or "—"),
        ]

    elif ioc_type == "domain":
        cats = vt.get("categories") or {}
        cats_str = " · ".join(sorted({str(v) for v in cats.values()}))[:80] if cats else "—"
        rep = vt.get("reputation")
        fields = [
            ("Domaine",       ioc_value),
            ("Score VT",      vt_str),
            ("Réputation VT", str(rep) if rep is not None else "—"),
            ("Tags",          " · ".join(vt.get("tags") or []) or "—"),
            ("Catégories",    cats_str),
            ("Registrar",     vt.get("registrar") or "—"),
            ("Création",      _fmt_ts(vt.get("creation_date"))),
        ]

    elif ioc_type == "hash":
        exif = vt.get("exiftool") or {}
        sig  = vt.get("signature_info") or {}
        sub  = sig.get("subject") or ""
        cn   = (sub.split("CN=")[-1].split(",")[0] if "CN=" in sub
                else (sig.get("signers") or "").split(";")[0]).strip()
        signer_str = cn if cn else ("Non signé" if vt else "—")

        size = vt.get("file_size")
        size_str = f"{size:,}".replace(",", " ") + " o" if size else "—"

        sha256 = vt.get("sha256") or "—"
        sha256_display = sha256[:22] + "…" if len(sha256) > 22 else sha256

        fields = [
            ("MD5",             vt.get("md5") or ioc_value),
            ("SHA1",            vt.get("sha1") or "—"),
            ("SHA256",          sha256_display),
            ("Type",            vt.get("type_description") or vt.get("magic") or "—"),
            ("Taille",          size_str),
            ("Score VT",        vt_str),
            ("Famille",         vt.get("popular_threat_label") or "—"),
            ("Compilé le",      str(vt.get("pe_compilation_date") or "—")[:10]),
            ("1ère soumission", vt.get("first_submission_date") or "—"),
            ("Signé par",       signer_str),
            ("Company (Exif)",  exif.get("CompanyName") or "—"),
            ("Product (Exif)",  exif.get("ProductName") or "—"),
        ]
    else:
        return None

    headers = [f[0] for f in fields]
    values  = [str(f[1]) for f in fields]
    md_header = "| " + " | ".join(f"**{h}**" for h in headers) + " |"
    md_sep    = "| " + " | ".join(["---"] * len(headers)) + " |"
    md_row    = "| " + " | ".join(values) + " |"
    markdown  = "\n".join([md_header, md_sep, md_row])

    return {"fields": fields, "markdown": markdown}


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
    """0-100 threat score: AbuseIPDB + VirusTotal + MXToolBox blacklist bonus."""
    abuse_score = None
    vt_score = None
    bl_bonus = 0

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
        elif res["source"] == "MXToolBox":
            bl_count = len(data.get("blacklisted_on") or [])
            bl_bonus = min(20, bl_count * 4)

    if abuse_score is not None and vt_score is not None:
        base = round(abuse_score * 0.5 + vt_score * 0.5)
    elif abuse_score is not None:
        base = int(abuse_score)
    elif vt_score is not None:
        base = int(vt_score)
    else:
        base = 0

    return min(100, base + bl_bonus)


def _all_sources_failed(raw_results: list[dict]) -> bool:
    return bool(raw_results) and all(res.get("error") for res in raw_results)


def _compute_score_breakdown(raw_results: list[dict]) -> dict:
    """Return per-source scores that contributed to the final threat score."""
    breakdown = {}
    for res in raw_results:
        if res.get("error") or not res.get("data"):
            continue
        data = res["data"]
        src = res["source"]
        if src == "AbuseIPDB":
            val = data.get("abuse_confidence_score")
            if val is not None:
                breakdown["AbuseIPDB"] = int(val)
        elif src == "VirusTotal":
            malicious = data.get("malicious", 0) or 0
            total = data.get("total_engines", 0) or 0
            if total > 0:
                breakdown["VirusTotal"] = round(malicious / total * 100)
        elif src == "URLhaus":
            if data.get("found"):
                breakdown["URLhaus"] = data.get("url_count", 0)
        elif src == "ThreatFox":
            if data.get("found"):
                breakdown["ThreatFox"] = len(data.get("results") or [])
        elif src == "GreyNoise":
            cls = data.get("classification")
            if cls == "malicious":
                breakdown["GreyNoise"] = "malicious"
            elif cls == "benign":
                breakdown["GreyNoise"] = "benign"
        elif src == "Shodan InternetDB":
            vulns = data.get("vulns") or []
            if vulns:
                breakdown["Shodan InternetDB"] = len(vulns)
    return breakdown


def _enrich_ioc(value: str, keys: dict | None = None) -> tuple[str, list[dict], str | None, int, dict, str | None]:
    """Return (ioc_type, raw, paragraph, threat_score, score_breakdown, malware_family)."""
    iocs, _ = parse_iocs([value])
    if not iocs:
        raise ValueError(f"IOC non reconnu : {value!r}")

    ioc = iocs[0]
    enrichers = ENRICHERS_BY_TYPE.get(ioc.type, [])
    if not enrichers:
        raise ValueError(f"Aucun enrichisseur disponible pour le type '{ioc.type}'")

    # Run enrichers in parallel, preserving original ordering
    result_slots: list[object | None] = [None] * len(enrichers)

    def _run(idx, fn):
        return idx, fn(ioc, keys=keys)

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {pool.submit(_run, i, fn): i for i, fn in enumerate(enrichers)}
        for future in as_completed(futures):
            try:
                idx, r = future.result()
                result_slots[idx] = r
            except Exception as exc:
                logger.error("Enricher error: %s", exc)

    result_objects = [r for r in result_slots if r is not None]

    raw = [{"source": r.source, "data": r.data, "error": r.error} for r in result_objects]
    threat_score = _compute_threat_score(raw)
    score_breakdown = _compute_score_breakdown(raw)

    groq_key = (keys or {}).get("GROQ_API_KEY", "") or os.getenv("GROQ_API_KEY", "")
    if groq_key:
        synthesis = groq_synthesizer.synthesize_full(result_objects, threat_score, groq_key=groq_key)
        paragraph = synthesis["paragraph"]
        malware_family = synthesis["malware_family"]
    else:
        paragraph = None
        malware_family = None

    return ioc.type, raw, paragraph, threat_score, score_breakdown, malware_family


@ioc_bp.route("/")
def index():
    q = request.args.get("q", "").strip()
    filt = request.args.get("filter", "all")  # all | malicious | legitimate
    sort = request.args.get("sort", "date")   # date | score | views

    query = IOCRecord.query
    if q:
        query = query.filter(IOCRecord.value.ilike(f"%{q}%"))
    if filt == "malicious":
        query = query.filter(IOCRecord.threat_score > 0)
    elif filt == "legitimate":
        query = query.filter(IOCRecord.threat_score == 0)

    if sort == "score":
        query = query.order_by(IOCRecord.threat_score.desc())
    elif sort == "views":
        query = query.order_by(IOCRecord.view_count.desc())
    else:
        query = query.order_by(IOCRecord.enriched_at.desc())

    records = query.limit(100).all()

    counts = {
        "all": IOCRecord.query.count(),
        "malicious": IOCRecord.query.filter(IOCRecord.threat_score > 0).count(),
        "legitimate": IOCRecord.query.filter(IOCRecord.threat_score == 0).count(),
    }

    return render_template("index.html", records=records, q=q, filt=filt, sort=sort, counts=counts)


@ioc_bp.route("/ioc/<path:value>")
@login_required
def detail(value: str):
    if not current_user.is_approved:
        abort(403)
    record = IOCRecord.query.filter_by(value=value).first_or_404()
    record.view_count = (record.view_count or 0) + 1
    db.session.commit()
    results = record.get_results()
    summary = _build_summary(results, record.ioc_type, record.value)
    return render_template("ioc_detail.html", record=record, results=results, summary=summary)


@ioc_bp.route("/enrich", methods=["GET", "POST"])
@login_required
def enrich():
    if not current_user.is_approved:
        flash("Votre compte n'est pas encore approuvé par un administrateur.", "warning")
        return redirect(url_for("ioc.index"))

    if request.method == "POST":
        # Analysts must have configured their own API keys
        if not current_user.is_admin and not current_user.has_api_keys:
            flash("Vous devez d'abord configurer vos clés API.", "warning")
            return redirect(url_for("auth.api_keys"))

        force = request.form.get("force") == "1"
        keys  = current_user.get_api_keys() if not current_user.is_admin else None

        # ── Collect IOC values: file upload takes priority over text input ──
        uploaded = request.files.get("ioc_file")
        if uploaded and uploaded.filename:
            values, file_error = _parse_upload(uploaded)
            if file_error:
                flash(file_error, "danger")
                return render_template("enrich.html", prefill="", max_batch=_MAX_BATCH)
        else:
            raw = request.form.get("ioc", "").strip()
            if not raw:
                flash("Veuillez saisir au moins un IOC.", "danger")
                return render_template("enrich.html", prefill="", max_batch=_MAX_BATCH)
            values = _parse_text_input(raw)

        if not values:
            flash("Aucun IOC valide trouvé.", "danger")
            return render_template("enrich.html", prefill="", max_batch=_MAX_BATCH)

        # ── Single IOC: original flow (redirect to detail page) ──
        if len(values) == 1:
            value = values[0]

            iocs, _ = parse_iocs([value])
            if not iocs:
                flash(f"IOC non reconnu : {value!r}", "danger")
                return render_template("enrich.html", prefill=value, max_batch=_MAX_BATCH)

            ioc_type = iocs[0].type

            if _is_private_ioc(value, ioc_type):
                return render_template(
                    "enrich.html",
                    prefill=value, max_batch=_MAX_BATCH,
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
                ioc_type, raw, paragraph, threat_score, score_breakdown, malware_family = _enrich_ioc(value, keys=keys)
            except ValueError as exc:
                flash(str(exc), "danger")
                return render_template("enrich.html", prefill=value, max_batch=_MAX_BATCH)
            except Exception as exc:
                logger.error("Enrichment error for %r: %s", value, exc)
                flash("Une erreur est survenue lors de l'enrichissement.", "danger")
                return render_template("enrich.html", prefill=value, max_batch=_MAX_BATCH)

            if _all_sources_failed(raw):
                return render_template(
                    "enrich.html",
                    prefill=value, max_batch=_MAX_BATCH,
                    no_info=True,
                    no_info_reason="Aucune source n'a retourné d'information pour cet IOC.",
                )

            existing = IOCRecord.query.filter_by(value=value).first()
            if existing:
                existing.enriched_at = datetime.utcnow()
                existing.enriched_by = current_user.email
                existing.set_results(raw)
                existing.paragraph = paragraph
                existing.threat_score = threat_score
                existing.malware_family = malware_family
                existing.verdict = "malicious" if threat_score > 0 else "clean"
                existing.set_score_breakdown(score_breakdown)
            else:
                record = IOCRecord(
                    value=value, ioc_type=ioc_type,
                    enriched_by=current_user.email,
                    paragraph=paragraph, threat_score=threat_score,
                    malware_family=malware_family,
                    verdict="malicious" if threat_score > 0 else "clean",
                )
                record.set_results(raw)
                record.set_score_breakdown(score_breakdown)
                db.session.add(record)

            db.session.commit()
            flash("Enrichissement terminé avec succès.", "success")
            return redirect(url_for("ioc.detail", value=value))

        # ── Bulk: process all IOCs and display a results table ──
        bulk_results = []
        for value in values[:_MAX_BATCH]:
            entry = {"value": value, "ioc_type": "?", "threat_score": None,
                     "status": "error", "message": ""}

            iocs, _ = parse_iocs([value])
            if not iocs:
                entry["status"] = "skipped"
                entry["message"] = "IOC non reconnu"
                bulk_results.append(entry)
                continue

            ioc_type = iocs[0].type
            entry["ioc_type"] = ioc_type

            if _is_private_ioc(value, ioc_type):
                entry["status"] = "skipped"
                entry["message"] = "Adresse privée / locale"
                bulk_results.append(entry)
                continue

            existing = IOCRecord.query.filter_by(value=value).first()
            if existing and not force and not existing.is_stale:
                entry["status"] = "cached"
                entry["threat_score"] = existing.threat_score
                bulk_results.append(entry)
                continue

            try:
                ioc_type, raw_res, paragraph, threat_score, score_breakdown, malware_family = _enrich_ioc(value, keys=keys)
            except Exception as exc:
                logger.error("Bulk enrichment error for %r: %s", value, exc)
                entry["message"] = "Erreur d'enrichissement"
                bulk_results.append(entry)
                continue

            if _all_sources_failed(raw_res):
                entry["status"] = "skipped"
                entry["message"] = "Aucune source n'a répondu"
                bulk_results.append(entry)
                continue

            now = datetime.utcnow()
            if existing:
                existing.enriched_at = now
                existing.enriched_by = current_user.email
                existing.set_results(raw_res)
                existing.paragraph = paragraph
                existing.threat_score = threat_score
                existing.malware_family = malware_family
                existing.verdict = "malicious" if threat_score > 0 else "clean"
                existing.set_score_breakdown(score_breakdown)
                entry["status"] = "updated"
            else:
                record = IOCRecord(
                    value=value, ioc_type=ioc_type,
                    enriched_by=current_user.email,
                    paragraph=paragraph, threat_score=threat_score,
                    malware_family=malware_family,
                    verdict="malicious" if threat_score > 0 else "clean",
                )
                record.set_results(raw_res)
                record.set_score_breakdown(score_breakdown)
                db.session.add(record)
                entry["status"] = "new"

            entry["threat_score"] = threat_score
            bulk_results.append(entry)

        db.session.commit()
        return render_template("enrich.html", bulk_results=bulk_results, max_batch=_MAX_BATCH)

    return render_template("enrich.html", prefill=request.args.get("ioc", ""),
                           max_batch=_MAX_BATCH)


@ioc_bp.route("/ioc/<path:value>/delete", methods=["POST"])
@login_required
def delete_ioc(value: str):
    if not current_user.is_admin:
        abort(403)
    record = IOCRecord.query.filter_by(value=value).first_or_404()
    Comment.query.filter_by(ioc_record_id=record.id).delete()
    db.session.delete(record)
    db.session.commit()
    flash(f"IOC « {value} » supprimé.", "success")
    return redirect(url_for("ioc.index"))


@ioc_bp.route("/export/excel")
@login_required
def export_excel():
    if not current_user.is_approved:
        abort(403)

    import openpyxl
    from io import BytesIO
    from openpyxl.styles import Alignment, Font, PatternFill

    wb = openpyxl.Workbook()
    wb.remove(wb.active)

    IP_HEADERS = ["Valeur", "ISP", "Score global", "Score AbuseIPDB", "Score VirusTotal",
                  "Vues", "Malveillant", "Enrichi le", "Enrichi par"]
    OTHER_HEADERS = ["Valeur", "Score global", "Score AbuseIPDB", "Score VirusTotal",
                     "Vues", "Malveillant", "Enrichi le", "Enrichi par"]
    IP_WIDTHS    = [38, 30, 13, 16, 16, 8, 12, 20, 28]
    OTHER_WIDTHS = [45,     13, 16, 16, 8, 12, 20, 28]

    HDR_FONT = Font(bold=True, color="C9D1D9")
    HDR_FILL = PatternFill("solid", fgColor="1C2128")
    HDR_ALIGN = Alignment(horizontal="center")
    RED_FONT  = Font(color="DA3633", bold=True)

    def _extract_row_data(raw_results: list[dict], ioc_type: str) -> tuple[str, str, str, str]:
        """Return (isp, abuse_score, vt_score) extracted from raw results."""
        isp = ""
        abuse_score = ""
        vt_score = ""
        for res in raw_results:
            if res.get("error") or not res.get("data"):
                continue
            d = res["data"]
            if res["source"] == "ip-api.com":
                isp = d.get("isp") or ""
            elif res["source"] == "AbuseIPDB":
                val = d.get("abuse_confidence_score")
                if val is not None:
                    abuse_score = str(val)
                if not isp:
                    isp = d.get("isp") or ""
            elif res["source"] == "VirusTotal":
                mal = d.get("malicious", 0) or 0
                tot = d.get("total_engines", 0) or 0
                if tot > 0:
                    vt_score = str(round(mal / tot * 100))
                elif mal == 0:
                    vt_score = "0"
        return isp, abuse_score, vt_score

    for ioc_type in ("ip", "domain", "hash"):
        is_ip = ioc_type == "ip"
        headers   = IP_HEADERS if is_ip else OTHER_HEADERS
        col_widths = IP_WIDTHS  if is_ip else OTHER_WIDTHS

        ws = wb.create_sheet(title=ioc_type.upper() + "s")
        ws.append(headers)
        for i, cell in enumerate(ws[1], start=1):
            cell.font = HDR_FONT
            cell.fill = HDR_FILL
            cell.alignment = HDR_ALIGN
            ws.column_dimensions[cell.column_letter].width = col_widths[i - 1]

        records = (
            IOCRecord.query.filter_by(ioc_type=ioc_type)
            .order_by(IOCRecord.threat_score.desc(), IOCRecord.enriched_at.desc())
            .all()
        )
        for r in records:
            isp, abuse_score, vt_score = _extract_row_data(r.get_results(), ioc_type)
            if is_ip:
                row = [r.value, isp, r.threat_score or 0, abuse_score, vt_score,
                       r.view_count or 0, "Oui" if r.is_malicious else "Non",
                       r.enriched_at.strftime("%Y-%m-%d %H:%M UTC"), r.enriched_by or ""]
                mal_cols = (1, 3, 7)   # Valeur, Score global, Malveillant
            else:
                row = [r.value, r.threat_score or 0, abuse_score, vt_score,
                       r.view_count or 0, "Oui" if r.is_malicious else "Non",
                       r.enriched_at.strftime("%Y-%m-%d %H:%M UTC"), r.enriched_by or ""]
                mal_cols = (1, 2, 6)
            ws.append(row)
            if r.is_malicious:
                for col in mal_cols:
                    ws.cell(row=ws.max_row, column=col).font = RED_FONT

    output = BytesIO()
    wb.save(output)
    output.seek(0)

    filename = f"ioc_export_{datetime.utcnow().strftime('%Y%m%d_%H%M')}.xlsx"
    return send_file(
        output,
        download_name=filename,
        as_attachment=True,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@ioc_bp.route("/ioc/<path:value>/tlp", methods=["POST"])
@login_required
def set_tlp(value: str):
    if not current_user.is_approved:
        abort(403)
    record = IOCRecord.query.filter_by(value=value).first_or_404()
    tlp = request.form.get("tlp", "WHITE").upper()
    if tlp not in ("RED", "AMBER", "GREEN", "WHITE"):
        flash("Valeur TLP invalide.", "danger")
    else:
        record.tlp = tlp
        db.session.commit()
        flash(f"TLP mis à jour : TLP:{tlp}", "success")
    return redirect(url_for("ioc.detail", value=value))


@ioc_bp.route("/ioc/<path:value>/tags", methods=["POST"])
@login_required
def set_tags(value: str):
    if not current_user.is_approved:
        abort(403)
    record = IOCRecord.query.filter_by(value=value).first_or_404()
    raw_tags = request.form.get("tags", "")
    tags = [t.strip() for t in re.split(r"[,;]+", raw_tags) if t.strip()]
    record.set_tags(tags)
    db.session.commit()
    flash("Tags mis à jour.", "success")
    return redirect(url_for("ioc.detail", value=value))


@ioc_bp.route("/pivot/family/<path:family>")
def pivot_family(family: str):
    records = (
        IOCRecord.query
        .filter(IOCRecord.malware_family.ilike(f"%{family}%"))
        .order_by(IOCRecord.threat_score.desc(), IOCRecord.enriched_at.desc())
        .limit(200)
        .all()
    )
    return render_template("pivot_family.html", family=family, records=records)


@ioc_bp.route("/ioc/<path:value>/comment", methods=["POST"])
@login_required
def add_comment(value: str):
    if not current_user.is_approved:
        abort(403)
    record = IOCRecord.query.filter_by(value=value).first_or_404()
    content = request.form.get("content", "").strip()
    if not content:
        flash("Le commentaire ne peut pas être vide.", "danger")
        return redirect(url_for("ioc.detail", value=value))
    comment = Comment(
        ioc_record_id=record.id,
        author=current_user.email,
        content=content,
        enriched_at_snapshot=record.enriched_at,
    )
    db.session.add(comment)
    db.session.commit()
    flash("Commentaire ajouté.", "success")
    return redirect(url_for("ioc.detail", value=value))
