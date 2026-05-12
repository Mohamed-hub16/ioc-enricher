"""ThreatFox (abuse.ch) enricher — IOC tagué par famille de malware.

https://threatfox-api.abuse.ch/
Auth-Key abuse.ch partagée avec URLhaus et MalwareBazaar.
"""

import os
import httpx
from src.models import IOC, EnrichmentResult

_BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"
_TIMEOUT = 12.0


def _abuse_key(keys: dict | None) -> str:
    return (keys or {}).get("ABUSE_CH_API_KEY") or os.getenv("ABUSE_CH_API_KEY", "")


def enrich(ioc: IOC, keys: dict | None = None) -> EnrichmentResult:
    if ioc.type not in ("ip", "domain", "hash"):
        return EnrichmentResult(
            source="ThreatFox", ioc=ioc, error=f"Unsupported type: {ioc.type}",
        )

    api_key = _abuse_key(keys)
    if not api_key:
        return EnrichmentResult(
            source="ThreatFox", ioc=ioc, error="ABUSE_CH_API_KEY not set",
        )

    try:
        resp = httpx.post(
            _BASE_URL,
            json={"query": "search_ioc", "search_term": ioc.value},
            headers={"Auth-Key": api_key},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        body = resp.json()
    except httpx.HTTPStatusError as exc:
        return EnrichmentResult(
            source="ThreatFox", ioc=ioc,
            error=f"HTTP {exc.response.status_code}",
        )
    except Exception as exc:
        return EnrichmentResult(source="ThreatFox", ioc=ioc, error=str(exc))

    if body.get("query_status") != "ok":
        return EnrichmentResult(
            source="ThreatFox", ioc=ioc,
            error="No information available",
        )

    rows = body.get("data") or []
    if not rows:
        return EnrichmentResult(
            source="ThreatFox", ioc=ioc,
            error="No information available",
        )

    # Aggregate across all matches
    families = sorted({r.get("malware") for r in rows if r.get("malware")})
    aliases = sorted({r.get("malware_printable") for r in rows if r.get("malware_printable")})
    ioc_types = sorted({r.get("threat_type") for r in rows if r.get("threat_type")})
    tags = sorted({t for r in rows for t in (r.get("tags") or [])})
    confidences = [r.get("confidence_level") for r in rows if r.get("confidence_level") is not None]
    max_conf = max(confidences) if confidences else None

    data = {
        "match_count":      len(rows),
        "malware_families": families[:10],
        "family_aliases":   aliases[:10],
        "threat_types":     ioc_types[:5],
        "tags":             tags[:20],
        "max_confidence":   max_conf,
        "first_seen":       min((r.get("first_seen") for r in rows if r.get("first_seen")), default=None),
        "last_seen":        max((r.get("last_seen") for r in rows if r.get("last_seen")), default=None),
        "matches":          [
            {
                "ioc":           r.get("ioc"),
                "type":          r.get("ioc_type"),
                "malware":       r.get("malware_printable") or r.get("malware"),
                "threat_type":   r.get("threat_type"),
                "confidence":    r.get("confidence_level"),
                "first_seen":    r.get("first_seen"),
                "last_seen":     r.get("last_seen"),
                "reporter":      r.get("reporter"),
                "reference":     r.get("reference"),
                "tags":          r.get("tags") or [],
            }
            for r in rows[:5]
        ],
    }

    return EnrichmentResult(
        source="ThreatFox", ioc=ioc,
        data={k: v for k, v in data.items() if v not in (None, "", [], {})},
    )
