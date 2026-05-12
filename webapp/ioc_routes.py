import ipaddress
import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, send_file, jsonify
from flask_login import login_required, current_user

logger = logging.getLogger(__name__)

from webapp import db
from webapp.models import IOCRecord, Comment, TLP_LEVELS
from src.parsers.ioc_parser import parse_iocs, defang
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

    # Pivot helper: rend un champ cliquable vers l'index filtré
    def _pv(param: str, val) -> str | None:
        if not val or val == "—":
            return None
        return f"{param}={val}"

    if ioc_type == "ip":
        abuse = src.get("AbuseIPDB", {})
        ipapi = src.get("ip-api.com", {})
        gn = src.get("GreyNoise", {})
        sho = src.get("Shodan InternetDB", {})
        asn_num = vt.get("asn") or ipapi.get("asn") or ""
        as_owner = vt.get("as_owner") or ipapi.get("as_name") or ""
        country = ipapi.get("country") or abuse.get("country_name") or ""
        abuse_sc = abuse.get("abuse_confidence_score")
        gn_verdict = gn.get("verdict_short") or "—"
        ports = sho.get("ports") or []
        vulns = sho.get("vulns") or []
        fields = [
            ("IP",              ioc_value, None),
            ("Score AbuseIPDB", f"{abuse_sc}%" if abuse_sc is not None else "—", None),
            ("Score VT",        vt_str, None),
            ("GreyNoise",       gn_verdict, None),
            ("ISP",             ipapi.get("isp") or abuse.get("isp") or "—", None),
            ("Usage Type",      ipapi.get("network_type") or "—", None),
            ("ASN",             f"AS{asn_num}" if asn_num else "—",
                                _pv("asn", f"AS{asn_num}") if asn_num else None),
            ("AS Owner",        as_owner or "—", _pv("asn", as_owner)),
            ("Reverse DNS",     ipapi.get("reverse_dns") or "—", None),
            ("Country",         country or "—", _pv("country", country)),
            ("City",            ipapi.get("city") or "—", None),
            ("Ports ouverts",   ", ".join(str(p) for p in ports[:10]) if ports else "—", None),
            ("CVE détectées",   ", ".join(vulns[:6]) if vulns else "—", None),
        ]

    elif ioc_type == "domain":
        cats = vt.get("categories") or {}
        cats_str = " · ".join(sorted({str(v) for v in cats.values()}))[:80] if cats else "—"
        rep = vt.get("reputation")
        urlhaus = src.get("URLhaus", {})
        threatfox = src.get("ThreatFox", {})
        urlhaus_online = urlhaus.get("online_url_count") or 0
        tfox_fams = threatfox.get("malware_families") or []
        fields = [
            ("Domaine",          ioc_value, None),
            ("Score VT",         vt_str, None),
            ("Réputation VT",    str(rep) if rep is not None else "—", None),
            ("Tags",             " · ".join(vt.get("tags") or []) or "—", None),
            ("Catégories",       cats_str, None),
            ("Registrar",        vt.get("registrar") or "—", None),
            ("Création",         _fmt_ts(vt.get("creation_date")), None),
            ("URLhaus (online)", str(urlhaus_online) if urlhaus_online else "—", None),
            ("ThreatFox family", tfox_fams[0] if tfox_fams else "—",
                                 _pv("family", tfox_fams[0]) if tfox_fams else None),
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

        mb = src.get("MalwareBazaar", {})
        threatfox = src.get("ThreatFox", {})
        family = (mb.get("signature") or vt.get("popular_threat_label")
                  or (threatfox.get("malware_families") or [None])[0] or "—")

        fields = [
            ("MD5",             vt.get("md5") or ioc_value, None),
            ("SHA1",            vt.get("sha1") or "—", None),
            ("SHA256",          sha256_display, None),
            ("Type",            vt.get("type_description") or vt.get("magic") or "—", None),
            ("Taille",          size_str, None),
            ("Score VT",        vt_str, None),
            ("Famille",         family, _pv("family", family) if family != "—" else None),
            ("Compilé le",      str(vt.get("pe_compilation_date") or "—")[:10], None),
            ("1ère soumission", vt.get("first_submission_date") or "—", None),
            ("Signé par",       signer_str, None),
            ("Company (Exif)",  exif.get("CompanyName") or "—", None),
            ("Product (Exif)",  exif.get("ProductName") or "—", None),
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


def _compute_score_breakdown(raw_results: list[dict]) -> dict:
    """Compute the threat score and produce a transparent breakdown.

    Sub-scores (0-100):
      - AbuseIPDB confidence  (IP)
      - VirusTotal ratio
      - GreyNoise classification (malicious=+15, +noise=-10, +RIOT=cap at 10)
      - ThreatFox match  (+25 if confidence high, +15 otherwise)
      - URLhaus host/payload (+25 if online URLs or online host, else +15)
      - MalwareBazaar match (+25, hash only)
    Cap at 100.
    """
    abuse_score = None
    vt_score = None
    bonuses: list[tuple[str, int, str]] = []  # (source, delta, reason)
    cap: int | None = None

    for res in raw_results:
        if res.get("error"):
            continue
        data = res.get("data") or {}
        source = res.get("source", "")

        if source == "AbuseIPDB":
            abuse_score = int(data.get("abuse_confidence_score") or 0)
        elif source == "VirusTotal":
            mal = int(data.get("malicious") or 0)
            tot = int(data.get("total_engines") or 0)
            vt_score = round(mal / tot * 100) if tot > 0 else 0
        elif source == "GreyNoise":
            classification = (data.get("classification") or "").lower()
            if data.get("riot"):
                cap = 10
                bonuses.append(("GreyNoise", 0, f"RIOT ({data.get('name') or 'service légitime connu'})"))
            elif classification == "malicious":
                bonuses.append(("GreyNoise", 15, "classification malveillante"))
            elif data.get("noise") and classification != "benign":
                bonuses.append(("GreyNoise", -10, "scanner Internet (bruit)"))
            elif classification == "benign":
                bonuses.append(("GreyNoise", -5, "classifié bénin"))
        elif source == "ThreatFox":
            conf = data.get("max_confidence") or 0
            delta = 25 if conf >= 75 else 15
            families = data.get("malware_families") or []
            label = f"famille {families[0]}" if families else "IOC tagué"
            bonuses.append(("ThreatFox", delta, label))
        elif source == "URLhaus":
            online = int(data.get("online_url_count") or 0)
            threats = data.get("threats_observed") or []
            host_count = int(data.get("host_url_count") or 0)
            if online > 0:
                bonuses.append(("URLhaus", 25, f"{online} URL malveillante(s) en ligne"))
            elif host_count > 0:
                bonuses.append(("URLhaus", 15, "URL malveillante historique"))
            elif data.get("payload_sha256"):
                bonuses.append(("URLhaus", 20, f"payload référencé ({data.get('signature') or 'malware'})"))
            elif threats:
                bonuses.append(("URLhaus", 12, ", ".join(threats[:2])))
        elif source == "MalwareBazaar":
            sig = data.get("signature") or data.get("triage_family") or data.get("intezer_family")
            bonuses.append(("MalwareBazaar", 25, f"hash connu ({sig})" if sig else "hash référencé"))

    # Base = pondération AbuseIPDB / VirusTotal (rétro-compatible avec l'ancien score)
    if abuse_score is not None and vt_score is not None:
        base = round(abuse_score * 0.5 + vt_score * 0.5)
    elif abuse_score is not None:
        base = abuse_score
    elif vt_score is not None:
        base = vt_score
    else:
        base = 0

    bonus_total = sum(b[1] for b in bonuses)
    raw = base + bonus_total
    final = max(0, min(100, raw))
    if cap is not None and final > cap:
        final = cap

    return {
        "total":      final,
        "base":       base,
        "abuseipdb":  abuse_score,
        "virustotal": vt_score,
        "bonuses":    bonuses,
        "cap":        cap,
    }


def _compute_threat_score(raw_results: list[dict]) -> int:
    return _compute_score_breakdown(raw_results)["total"]


def _all_sources_failed(raw_results: list[dict]) -> bool:
    return bool(raw_results) and all(res.get("error") for res in raw_results)


def _enrich_ioc(value: str, keys: dict | None = None) -> dict:
    """Enrich a single IOC and return a bundle dict.

    Returns:
      {
        ioc_type, raw (list[dict]), paragraph (str|None),
        structured (dict|None), threat_score (int), breakdown (dict)
      }
    Raises ValueError on unrecognised IOC or missing registry.
    """
    iocs, _ = parse_iocs([value])
    if not iocs:
        raise ValueError(f"IOC non reconnu : {value!r}")

    ioc = iocs[0]
    enrichers = ENRICHERS_BY_TYPE.get(ioc.type, [])
    if not enrichers:
        raise ValueError(f"Aucun enrichisseur disponible pour le type '{ioc.type}'")

    # Parallélisation : 4 threads suffisent (8 enrichers max sur IP, mostly I/O)
    with ThreadPoolExecutor(max_workers=min(6, len(enrichers))) as ex:
        futures = [ex.submit(fn, ioc, keys=keys) for fn in enrichers]
        result_objects = [f.result() for f in futures]

    raw = [{"source": r.source, "data": r.data, "error": r.error} for r in result_objects]
    breakdown = _compute_score_breakdown(raw)
    threat_score = breakdown["total"]

    groq_key = (keys or {}).get("GROQ_API_KEY", "") or os.getenv("GROQ_API_KEY", "")
    paragraph = None
    structured = None
    if groq_key:
        paragraph, structured = groq_synthesizer.synthesize_full(
            result_objects, threat_score, groq_key=groq_key,
        )

    return {
        "ioc_type":     ioc.type,
        "raw":          raw,
        "paragraph":    paragraph,
        "structured":   structured,
        "threat_score": threat_score,
        "breakdown":    breakdown,
    }


def _persist_enrichment(value: str, bundle: dict, user_email: str,
                        existing: IOCRecord | None = None) -> IOCRecord:
    """Create or update an IOCRecord from an enrichment bundle. Doesn't commit."""
    now = datetime.utcnow()
    if existing:
        record = existing
        record.enriched_at = now
        record.enriched_by = user_email
    else:
        record = IOCRecord(
            value=value, ioc_type=bundle["ioc_type"], enriched_by=user_email,
        )
        db.session.add(record)
    record.set_results(bundle["raw"])
    record.paragraph = bundle["paragraph"]
    record.threat_score = bundle["threat_score"]
    record.set_structured(bundle["structured"])
    record.set_score_breakdown(bundle["breakdown"])
    return record


def _pivot_filter_records(records: list[IOCRecord], *,
                          ttp: str | None = None,
                          family: str | None = None,
                          verdict: str | None = None,
                          tag: str | None = None,
                          asn: str | None = None,
                          country: str | None = None,
                          ioc_type: str | None = None) -> list[IOCRecord]:
    """Filter records in Python (post-load) on pivot dimensions stored in
    JSON columns or raw_results. Used by index() when complex filters are set."""
    out = []
    for r in records:
        if ioc_type and r.ioc_type != ioc_type:
            continue
        if verdict and (r.verdict or "") != verdict:
            continue
        if family:
            f = (r.malware_family or "").lower()
            needle = family.lower().rstrip("*")
            if not (f == needle or (family.endswith("*") and f.startswith(needle))):
                continue
        if ttp:
            ttp_up = ttp.upper()
            if ttp_up not in r.ttp_ids and not any(t.startswith(ttp_up + ".") for t in r.ttp_ids):
                continue
        if tag and tag.lower() not in (r.get_tags() or []):
            continue
        if asn or country:
            raw = r.get_results()
            asn_match = False
            country_match = False
            for res in raw:
                d = res.get("data") or {}
                # ASN can be in AbuseIPDB (rare), ipapi (`asn` = "AS15169 Google"), VT (`asn`)
                if asn:
                    asn_val = str(d.get("asn") or d.get("as_owner") or "")
                    if asn.upper() in asn_val.upper():
                        asn_match = True
                if country:
                    c_val = str(d.get("country") or d.get("country_name") or "")
                    if country.lower() in c_val.lower():
                        country_match = True
            if asn and not asn_match:
                continue
            if country and not country_match:
                continue
        out.append(r)
    return out


@ioc_bp.route("/")
def index():
    q = request.args.get("q", "").strip()
    filt = request.args.get("filter", "all")  # all | malicious | legitimate
    sort = request.args.get("sort", "date")   # date | score | views
    ioc_type = request.args.get("type", "").strip().lower() or None
    ttp = request.args.get("ttp", "").strip() or None
    family = request.args.get("family", "").strip() or None
    verdict = request.args.get("verdict", "").strip().lower() or None
    tag = request.args.get("tag", "").strip().lower() or None
    asn = request.args.get("asn", "").strip() or None
    country = request.args.get("country", "").strip() or None

    query = IOCRecord.query
    if q:
        query = query.filter(IOCRecord.value.ilike(f"%{q}%"))
    if filt == "malicious":
        query = query.filter(IOCRecord.threat_score > 0)
    elif filt == "legitimate":
        query = query.filter(IOCRecord.threat_score == 0)
    if ioc_type in ("ip", "domain", "hash"):
        query = query.filter(IOCRecord.ioc_type == ioc_type)
    if verdict in ("malicious", "suspicious", "legitimate", "inconclusive"):
        query = query.filter(IOCRecord.verdict == verdict)
    if family and not family.endswith("*"):
        query = query.filter(IOCRecord.malware_family == family)

    if sort == "score":
        query = query.order_by(IOCRecord.threat_score.desc())
    elif sort == "views":
        query = query.order_by(IOCRecord.view_count.desc())
    else:
        query = query.order_by(IOCRecord.enriched_at.desc())

    # Sur les pivots non-SQL (TTP/tag/ASN/country), on filtre en Python après load.
    needs_python_filter = bool(ttp or tag or asn or country or (family and family.endswith("*")))
    if needs_python_filter:
        # Charge plus large pour ne pas tronquer trop tôt
        candidates = query.limit(500).all()
        records = _pivot_filter_records(candidates, ttp=ttp, family=family if family and family.endswith("*") else None,
                                        tag=tag, asn=asn, country=country)[:100]
    else:
        records = query.limit(100).all()

    counts = {
        "all": IOCRecord.query.count(),
        "malicious": IOCRecord.query.filter(IOCRecord.threat_score > 0).count(),
        "legitimate": IOCRecord.query.filter(IOCRecord.threat_score == 0).count(),
    }

    active_pivots = {k: v for k, v in {
        "ttp": ttp, "family": family, "verdict": verdict, "tag": tag,
        "asn": asn, "country": country, "type": ioc_type,
    }.items() if v}

    return render_template("index.html",
                           records=records, q=q, filt=filt, sort=sort,
                           counts=counts, active_pivots=active_pivots)


@ioc_bp.route("/ttps")
def ttps_index():
    """Liste des TTPs MITRE ATT&CK observés en base avec leur fréquence."""
    counts: dict[str, dict] = {}
    for record in IOCRecord.query.filter(IOCRecord.structured_json.isnot(None)).all():
        for t in record.ttps:
            tid = t.get("technique_id")
            if not tid:
                continue
            entry = counts.setdefault(tid, {"id": tid, "name": t.get("name", ""), "count": 0})
            entry["count"] += 1
            if t.get("name") and not entry["name"]:
                entry["name"] = t["name"]
    rows = sorted(counts.values(), key=lambda r: r["count"], reverse=True)
    return render_template("ttps_index.html", rows=rows)


@ioc_bp.route("/families")
def families_index():
    """Liste des familles de malware observées en base."""
    counts: dict[str, int] = {}
    for record in IOCRecord.query.filter(IOCRecord.malware_family.isnot(None)).all():
        fam = record.malware_family
        if fam:
            counts[fam] = counts.get(fam, 0) + 1
    rows = sorted(({"family": f, "count": c} for f, c in counts.items()),
                  key=lambda r: r["count"], reverse=True)
    return render_template("families_index.html", rows=rows)


@ioc_bp.route("/health")
def health():
    """Healthcheck endpoint for monitoring."""
    try:
        last = db.session.execute(
            db.select(IOCRecord.enriched_at).order_by(IOCRecord.enriched_at.desc()).limit(1)
        ).scalar()
        return jsonify({
            "status": "ok",
            "ioc_count": IOCRecord.query.count(),
            "last_enriched_at": last.isoformat() + "Z" if last else None,
        }), 200
    except Exception as exc:
        return jsonify({"status": "error", "error": str(exc)}), 503


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
                bundle = _enrich_ioc(value, keys=keys)
            except ValueError as exc:
                flash(str(exc), "danger")
                return render_template("enrich.html", prefill=value, max_batch=_MAX_BATCH)
            except Exception as exc:
                logger.error("Enrichment error for %r: %s", value, exc)
                flash("Une erreur est survenue lors de l'enrichissement.", "danger")
                return render_template("enrich.html", prefill=value, max_batch=_MAX_BATCH)

            if _all_sources_failed(bundle["raw"]):
                return render_template(
                    "enrich.html",
                    prefill=value, max_batch=_MAX_BATCH,
                    no_info=True,
                    no_info_reason="Aucune source n'a retourné d'information pour cet IOC.",
                )

            existing = IOCRecord.query.filter_by(value=value).first()
            _persist_enrichment(value, bundle, current_user.email, existing)
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
                bundle = _enrich_ioc(value, keys=keys)
            except Exception as exc:
                logger.error("Bulk enrichment error for %r: %s", value, exc)
                entry["message"] = "Erreur d'enrichissement"
                bulk_results.append(entry)
                continue

            if _all_sources_failed(bundle["raw"]):
                entry["status"] = "skipped"
                entry["message"] = "Aucune source n'a répondu"
                bulk_results.append(entry)
                continue

            _persist_enrichment(value, bundle, current_user.email, existing)
            entry["status"] = "updated" if existing else "new"
            entry["threat_score"] = bundle["threat_score"]
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
    """Update TLP marking for an IOC. Analysts approved+."""
    if not current_user.is_approved:
        abort(403)
    record = IOCRecord.query.filter_by(value=value).first_or_404()
    new_tlp = (request.form.get("tlp") or "").strip().upper()
    if new_tlp not in TLP_LEVELS:
        flash(f"TLP invalide. Valeurs autorisées : {', '.join(TLP_LEVELS)}.", "danger")
        return redirect(url_for("ioc.detail", value=value))
    record.tlp = new_tlp
    db.session.commit()
    flash(f"TLP mis à jour : {new_tlp}.", "success")
    return redirect(url_for("ioc.detail", value=value))


@ioc_bp.route("/ioc/<path:value>/tags", methods=["POST"])
@login_required
def update_tags(value: str):
    """Replace the full tag list (CSV input). Analysts approved+."""
    if not current_user.is_approved:
        abort(403)
    record = IOCRecord.query.filter_by(value=value).first_or_404()
    raw = request.form.get("tags", "")
    tags = [t.strip().lower() for t in re.split(r"[,;\s]+", raw) if t.strip()]
    record.set_tags(tags)
    db.session.commit()
    flash("Tags mis à jour.", "success")
    return redirect(url_for("ioc.detail", value=value))


@ioc_bp.route("/api/ioc/<path:value>/defanged", methods=["GET"])
def defanged_value(value: str):
    """Endpoint utilitaire — retourne la valeur défangee pour les boutons copy."""
    record = IOCRecord.query.filter_by(value=value).first_or_404()
    return jsonify({
        "original": record.value,
        "defanged": defang(record.value, record.ioc_type),
        "type": record.ioc_type,
    })


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
