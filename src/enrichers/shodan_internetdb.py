"""Shodan InternetDB enricher — free, no API key required."""

import httpx
from src.models import IOC, EnrichmentResult

_BASE_URL = "https://internetdb.shodan.io"
_TIMEOUT = 10.0


def enrich(ioc: IOC, keys: dict | None = None) -> EnrichmentResult:
    if ioc.type != "ip":
        return EnrichmentResult(source="Shodan InternetDB", ioc=ioc, error="IP only")
    try:
        resp = httpx.get(f"{_BASE_URL}/{ioc.value}", timeout=_TIMEOUT)
        if resp.status_code == 404:
            return EnrichmentResult(source="Shodan InternetDB", ioc=ioc, data={"found": False})
        resp.raise_for_status()
        payload = resp.json()
    except httpx.HTTPStatusError as exc:
        msg = (f"HTTP {exc.response.status_code} — IP hébergeur bloquée par Shodan"
               if exc.response.status_code == 403
               else f"HTTP {exc.response.status_code}")
        return EnrichmentResult(source="Shodan InternetDB", ioc=ioc, error=msg)
    except Exception as exc:
        return EnrichmentResult(source="Shodan InternetDB", ioc=ioc, error=str(exc))

    return EnrichmentResult(
        source="Shodan InternetDB",
        ioc=ioc,
        data={
            "found": True,
            "open_ports": payload.get("ports", []),
            "hostnames": payload.get("hostnames", []),
            "cpes": payload.get("cpes", []),
            "vulns": payload.get("vulns", []),
            "tags": payload.get("tags", []),
        },
    )
