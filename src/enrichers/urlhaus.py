"""URLhaus (abuse.ch) enricher — URLs distribuant du malware, host & payload lookup.

https://urlhaus-api.abuse.ch/
Auth-Key gratuite (compte abuse.ch). Même clé que ThreatFox et MalwareBazaar.
"""

import os
import httpx
from src.models import IOC, EnrichmentResult

_BASE_URL = "https://urlhaus-api.abuse.ch/v1"
_TIMEOUT = 12.0


def _abuse_key(keys: dict | None) -> str:
    return (keys or {}).get("ABUSE_CH_API_KEY") or os.getenv("ABUSE_CH_API_KEY", "")


def _post(endpoint: str, payload: dict, api_key: str) -> dict:
    resp = httpx.post(
        f"{_BASE_URL}/{endpoint}/",
        data=payload,
        headers={"Auth-Key": api_key},
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def _enrich_host(value: str, api_key: str) -> dict:
    body = _post("host", {"host": value}, api_key)
    if body.get("query_status") != "ok":
        return {}

    urls = body.get("urls") or []
    online = [u for u in urls if u.get("url_status") == "online"]
    threats = sorted({u.get("threat") for u in urls if u.get("threat")})
    tags = sorted({t for u in urls for t in (u.get("tags") or [])})

    data = {
        "host_url_count":      body.get("url_count"),
        "first_seen":          body.get("firstseen"),
        "blacklists":          body.get("blacklists") or {},
        "threats_observed":    threats[:10],
        "tags":                tags[:20],
        "online_url_count":    len(online),
        "recent_urls":         [
            {
                "url":       u.get("url"),
                "status":    u.get("url_status"),
                "added":     u.get("dateadded"),
                "threat":    u.get("threat"),
                "tags":      u.get("tags") or [],
            }
            for u in urls[:5]
        ],
    }
    return data


def _enrich_payload(value: str, api_key: str) -> dict:
    body = _post("payload", {"hash": value}, api_key)
    if body.get("query_status") != "ok":
        return {}

    return {
        "payload_md5":         body.get("md5_hash"),
        "payload_sha256":      body.get("sha256_hash"),
        "file_type":           body.get("file_type"),
        "file_size":           body.get("file_size"),
        "signature":           body.get("signature"),
        "first_seen":          body.get("firstseen"),
        "last_seen":           body.get("lastseen"),
        "url_count":           body.get("url_count"),
        "urlhaus_reference":   body.get("urlhaus_reference"),
        "imphash":             body.get("imphash"),
        "ssdeep":              body.get("ssdeep"),
        "tlsh":                body.get("tlsh"),
    }


def enrich(ioc: IOC, keys: dict | None = None) -> EnrichmentResult:
    api_key = _abuse_key(keys)
    if not api_key:
        return EnrichmentResult(
            source="URLhaus", ioc=ioc, error="ABUSE_CH_API_KEY not set",
        )

    try:
        if ioc.type in ("ip", "domain"):
            data = _enrich_host(ioc.value, api_key)
        elif ioc.type == "hash":
            data = _enrich_payload(ioc.value, api_key)
        else:
            return EnrichmentResult(
                source="URLhaus", ioc=ioc, error=f"Unsupported type: {ioc.type}",
            )
    except httpx.HTTPStatusError as exc:
        return EnrichmentResult(
            source="URLhaus", ioc=ioc,
            error=f"HTTP {exc.response.status_code}",
        )
    except Exception as exc:
        return EnrichmentResult(source="URLhaus", ioc=ioc, error=str(exc))

    if not data:
        return EnrichmentResult(
            source="URLhaus", ioc=ioc, error="No information available",
        )

    return EnrichmentResult(
        source="URLhaus", ioc=ioc,
        data={k: v for k, v in data.items() if v not in (None, "", [], {})},
    )
