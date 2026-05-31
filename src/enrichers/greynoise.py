"""GreyNoise enricher — IP context via community API."""

import os
import httpx
from src.models import IOC, EnrichmentResult

_BASE_URL = "https://api.greynoise.io/v3/community"
_TIMEOUT = 10.0


def enrich(ioc: IOC, keys: dict | None = None) -> EnrichmentResult:
    if ioc.type != "ip":
        return EnrichmentResult(source="GreyNoise", ioc=ioc, error="IP only")
    api_key = keys.get("GREYNOISE_API_KEY", "") if keys is not None else os.getenv("GREYNOISE_API_KEY", "")
    headers = {"key": api_key} if api_key else {}
    try:
        resp = httpx.get(
            f"{_BASE_URL}/{ioc.value}",
            headers=headers,
            timeout=_TIMEOUT,
        )
        if resp.status_code == 404:
            return EnrichmentResult(source="GreyNoise", ioc=ioc, data={"seen": False})
        resp.raise_for_status()
        payload = resp.json()
    except httpx.HTTPStatusError as exc:
        return EnrichmentResult(source="GreyNoise", ioc=ioc, error=f"HTTP {exc.response.status_code}")
    except Exception as exc:
        return EnrichmentResult(source="GreyNoise", ioc=ioc, error=str(exc))

    return EnrichmentResult(
        source="GreyNoise",
        ioc=ioc,
        data={
            "seen": payload.get("seen", False),
            "classification": payload.get("classification"),
            "noise": payload.get("noise", False),
            "riot": payload.get("riot", False),
            "name": payload.get("name"),
            "link": payload.get("link"),
            "last_seen": payload.get("last_seen"),
            "message": payload.get("message"),
        },
    )
