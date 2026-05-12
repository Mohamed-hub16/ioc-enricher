"""REST API v1 — authenticated via X-API-Key header (no CSRF required)."""

from datetime import datetime
from functools import wraps

from flask import Blueprint, g, jsonify, request

from webapp import db
from webapp.models import Comment, IOCRecord, User

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")


def _require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key", "").strip()
        if not key:
            return jsonify({"error": "X-API-Key header missing"}), 401
        user = User.get_by_rest_api_key(key)
        if not user or not user.is_approved:
            return jsonify({"error": "Invalid or unauthorized API key"}), 401
        g.api_user = user
        return f(*args, **kwargs)
    return decorated


def _ioc_to_dict(record: IOCRecord, include_raw: bool = False) -> dict:
    d = {
        "value": record.value,
        "type": record.ioc_type,
        "threat_score": record.threat_score or 0,
        "is_malicious": record.is_malicious,
        "verdict": record.verdict,
        "malware_family": record.malware_family,
        "tlp": record.tlp or "WHITE",
        "tags": record.get_tags(),
        "score_breakdown": record.get_score_breakdown(),
        "view_count": record.view_count or 0,
        "enriched_at": record.enriched_at.isoformat() + "Z",
        "enriched_by": record.enriched_by,
        "is_stale": record.is_stale,
        "paragraph": record.paragraph,
    }
    if include_raw:
        d["raw_results"] = record.get_results()
    return d


@api_bp.route("/iocs", methods=["GET"])
@_require_api_key
def list_iocs():
    """List IOCs with optional filters.

    Query params: q, type (ip|domain|hash), min_score, sort (date|score|views),
                  page (default 1), per_page (default 50, max 200).
    """
    q = request.args.get("q", "").strip()
    ioc_type = request.args.get("type", "").strip().lower()
    min_score = request.args.get("min_score", type=int)
    sort = request.args.get("sort", "date")

    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(200, max(1, int(request.args.get("per_page", 50))))
    except ValueError:
        return jsonify({"error": "Invalid pagination parameters"}), 400

    query = IOCRecord.query
    if q:
        query = query.filter(IOCRecord.value.ilike(f"%{q}%"))
    if ioc_type in ("ip", "domain", "hash"):
        query = query.filter(IOCRecord.ioc_type == ioc_type)
    if min_score is not None:
        query = query.filter(IOCRecord.threat_score >= min_score)

    if sort == "score":
        query = query.order_by(IOCRecord.threat_score.desc())
    elif sort == "views":
        query = query.order_by(IOCRecord.view_count.desc())
    else:
        query = query.order_by(IOCRecord.enriched_at.desc())

    total = query.count()
    records = query.offset((page - 1) * per_page).limit(per_page).all()

    return jsonify({
        "total": total,
        "page": page,
        "per_page": per_page,
        "iocs": [_ioc_to_dict(r) for r in records],
    })


@api_bp.route("/ioc/<path:value>", methods=["GET"])
@_require_api_key
def get_ioc(value: str):
    """Return full details for a single IOC (includes raw_results and paragraph)."""
    record = IOCRecord.query.filter_by(value=value).first()
    if not record:
        return jsonify({"error": "IOC not found"}), 404
    return jsonify(_ioc_to_dict(record, include_raw=True))


@api_bp.route("/enrich", methods=["POST"])
@_require_api_key
def enrich_ioc():
    """Enrich an IOC. Body: {"ioc": "<value>", "force": false}.

    Returns cached result if fresh and force=false, otherwise triggers enrichment.
    Uses the requesting user's configured API keys.
    """
    body = request.get_json(silent=True) or {}
    value = (body.get("ioc") or body.get("value") or "").strip()
    force = bool(body.get("force", False))

    if not value:
        return jsonify({"error": "Missing 'ioc' field in request body"}), 400

    from src.parsers.ioc_parser import parse_iocs
    from webapp.ioc_routes import _all_sources_failed, _enrich_ioc, _is_private_ioc

    iocs, _ = parse_iocs([value])
    if not iocs:
        return jsonify({"error": f"Unrecognized IOC: {value!r}"}), 400

    ioc_type = iocs[0].type
    if _is_private_ioc(value, ioc_type):
        return jsonify({"error": "Private or local address — no public intel available"}), 422

    existing = IOCRecord.query.filter_by(value=value).first()
    if existing and not force and not existing.is_stale:
        return jsonify({"cached": True, **_ioc_to_dict(existing, include_raw=True)}), 200

    keys = g.api_user.get_api_keys()
    try:
        ioc_type, raw, paragraph, threat_score, score_breakdown, malware_family = _enrich_ioc(value, keys=keys)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        return jsonify({"error": "Enrichment failed — check server logs"}), 500

    if _all_sources_failed(raw):
        return jsonify({"error": "No source returned data for this IOC"}), 422

    now = datetime.utcnow()
    if existing:
        existing.enriched_at = now
        existing.enriched_by = g.api_user.email
        existing.set_results(raw)
        existing.paragraph = paragraph
        existing.threat_score = threat_score
        existing.malware_family = malware_family
        existing.verdict = "malicious" if threat_score > 0 else "clean"
        existing.set_score_breakdown(score_breakdown)
        record = existing
    else:
        record = IOCRecord(
            value=value,
            ioc_type=ioc_type,
            enriched_by=g.api_user.email,
            paragraph=paragraph,
            threat_score=threat_score,
            malware_family=malware_family,
            verdict="malicious" if threat_score > 0 else "clean",
        )
        record.set_results(raw)
        record.set_score_breakdown(score_breakdown)
        db.session.add(record)

    db.session.commit()
    return jsonify({"cached": False, **_ioc_to_dict(record, include_raw=True)}), 201


@api_bp.route("/ioc/<path:value>", methods=["DELETE"])
@_require_api_key
def delete_ioc(value: str):
    """Delete an IOC record. Admin role required."""
    if not g.api_user.is_admin:
        return jsonify({"error": "Admin role required"}), 403
    record = IOCRecord.query.filter_by(value=value).first()
    if not record:
        return jsonify({"error": "IOC not found"}), 404
    Comment.query.filter_by(ioc_record_id=record.id).delete()
    db.session.delete(record)
    db.session.commit()
    return jsonify({"message": f"IOC '{value}' deleted"}), 200
