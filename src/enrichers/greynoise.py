"""GreyNoise Community enricher — distingue scanner Internet vs ciblé.

https://docs.greynoise.io/docs/using-the-greynoise-community-api
- `noise = true`  → IP scanne massivement Internet (faux positif probable côté SOC)
- `riot = true`   → IP appartient à un service légitime (CDN, DNS public…)
- `classification` ∈ {benign, unknown, malicious}
"""

import os
import httpx
from src.models import IOC, EnrichmentResult

_BASE_URL = "https://api.greynoise.io/v3/community"
_TIMEOUT = 10.0


def enrich(ioc: IOC, keys: dict | None = None) -> EnrichmentResult:
    if ioc.type != "ip":
        return EnrichmentResult(
            source="GreyNoise", ioc=ioc,
            error=f"Unsupported type: {ioc.type}",
        )

    api_key = (keys or {}).get("GREYNOISE_API_KEY") or os.getenv("GREYNOISE_API_KEY", "")
    if not api_key:
        return EnrichmentResult(
            source="GreyNoise", ioc=ioc, error="GREYNOISE_API_KEY not set",
        )

    try:
        resp = httpx.get(
            f"{_BASE_URL}/{ioc.value}",
            headers={"key": api_key, "Accept": "application/json"},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 404:
            return EnrichmentResult(
                source="GreyNoise", ioc=ioc,
                error="IP not observed by GreyNoise",
            )
        resp.raise_for_status()
        payload = resp.json()
    except httpx.HTTPStatusError as exc:
        return EnrichmentResult(
            source="GreyNoise", ioc=ioc,
            error=f"HTTP {exc.response.status_code}",
        )
    except Exception as exc:
        return EnrichmentResult(source="GreyNoise", ioc=ioc, error=str(exc))

    data = {
        "noise":          payload.get("noise"),
        "riot":           payload.get("riot"),
        "classification": payload.get("classification"),
        "name":           payload.get("name"),
        "link":           payload.get("link"),
        "last_seen":      payload.get("last_seen"),
        "message":        payload.get("message"),
    }

    # Build a human-friendly verdict to display first
    if data.get("riot"):
        data["verdict_short"] = f"RIOT — {data.get('name') or 'service légitime connu'}"
    elif data.get("noise"):
        data["verdict_short"] = f"Bruit Internet — {data.get('classification') or 'unknown'}"
    elif data.get("classification") == "malicious":
        data["verdict_short"] = "Activité malveillante observée"
    elif data.get("classification") == "benign":
        data["verdict_short"] = "Bénin"

    return EnrichmentResult(
        source="GreyNoise", ioc=ioc,
        data={k: v for k, v in data.items() if v is not None and v != ""},
    )
