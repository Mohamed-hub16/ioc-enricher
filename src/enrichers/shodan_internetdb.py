"""Shodan InternetDB enricher — ports + CVEs + CPEs + hostnames par IP.

Pas de clé API requise. Free tier non-commercial.
https://internetdb.shodan.io/
"""

import httpx
from src.models import IOC, EnrichmentResult

_BASE_URL = "https://internetdb.shodan.io"
_TIMEOUT = 10.0


def enrich(ioc: IOC, keys: dict | None = None) -> EnrichmentResult:
    if ioc.type != "ip":
        return EnrichmentResult(
            source="Shodan InternetDB", ioc=ioc,
            error=f"Unsupported type: {ioc.type}",
        )

    try:
        resp = httpx.get(f"{_BASE_URL}/{ioc.value}", timeout=_TIMEOUT)
        if resp.status_code == 404:
            return EnrichmentResult(
                source="Shodan InternetDB", ioc=ioc,
                error="No information available",
            )
        resp.raise_for_status()
        payload = resp.json()
    except httpx.HTTPStatusError as exc:
        return EnrichmentResult(
            source="Shodan InternetDB", ioc=ioc,
            error=f"HTTP {exc.response.status_code}",
        )
    except Exception as exc:
        return EnrichmentResult(source="Shodan InternetDB", ioc=ioc, error=str(exc))

    data = {
        "ports":     sorted(payload.get("ports") or [])[:30],
        "vulns":     (payload.get("vulns") or [])[:25],
        "cpes":      (payload.get("cpes") or [])[:15],
        "hostnames": (payload.get("hostnames") or [])[:10],
        "tags":      payload.get("tags") or [],
    }

    return EnrichmentResult(
        source="Shodan InternetDB", ioc=ioc,
        data={k: v for k, v in data.items() if v},
    )
