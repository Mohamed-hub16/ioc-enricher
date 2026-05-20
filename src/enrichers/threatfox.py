"""ThreatFox enricher — IOC intel (abuse.ch)."""

import os
import httpx
from src.models import IOC, EnrichmentResult

_BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"
_TIMEOUT = 15.0


def enrich(ioc: IOC, keys: dict | None = None) -> EnrichmentResult:
    api_key = keys.get("ABUSE_CH_API_KEY", "") if keys is not None else os.getenv("ABUSE_CH_API_KEY", "")
    if not api_key:
        return EnrichmentResult(source="ThreatFox", ioc=ioc, error="ABUSE_CH_API_KEY not set")
    try:
        resp = httpx.post(
            _BASE_URL,
            headers={"Auth-Key": api_key},
            json={"query": "search_ioc", "search_term": ioc.value},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        payload = resp.json()
    except httpx.HTTPStatusError as exc:
        msg = (f"HTTP {exc.response.status_code} — IP hébergeur bloquée par abuse.ch"
               if exc.response.status_code == 403
               else f"HTTP {exc.response.status_code}")
        return EnrichmentResult(source="ThreatFox", ioc=ioc, error=msg)
    except Exception as exc:
        return EnrichmentResult(source="ThreatFox", ioc=ioc, error=str(exc))

    if payload.get("query_status") in ("no_result", "no_results", "illegal_search_term"):
        return EnrichmentResult(source="ThreatFox", ioc=ioc, data={"found": False})

    raw_data = payload.get("data") or []
    if not isinstance(raw_data, list):
        return EnrichmentResult(source="ThreatFox", ioc=ioc, data={"found": False})
    data = raw_data[:5]
    return EnrichmentResult(
        source="ThreatFox",
        ioc=ioc,
        data={
            "found": True,
            "results": [
                {
                    "ioc_type": d.get("ioc_type"),
                    "threat_type": d.get("threat_type"),
                    "malware": d.get("malware"),
                    "malware_printable": d.get("malware_printable"),
                    "confidence_level": d.get("confidence_level"),
                    "first_seen": d.get("first_seen"),
                    "last_seen": d.get("last_seen"),
                    "reference": d.get("reference"),
                    "reporter": d.get("reporter"),
                    "tags": d.get("tags"),
                }
                for d in data
            ],
        },
    )
