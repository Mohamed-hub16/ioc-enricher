"""URLhaus enricher — malicious URL/host intel (abuse.ch, free)."""

import httpx
from src.models import IOC, EnrichmentResult

_BASE_URL = "https://urlhaus-api.abuse.ch/v1"
_TIMEOUT = 15.0


def enrich(ioc: IOC, keys: dict | None = None) -> EnrichmentResult:
    if ioc.type not in ("ip", "domain"):
        return EnrichmentResult(source="URLhaus", ioc=ioc, error="IP/domain only")
    try:
        resp = httpx.post(
            f"{_BASE_URL}/host/",
            data={"host": ioc.value},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        payload = resp.json()
    except httpx.HTTPStatusError as exc:
        return EnrichmentResult(source="URLhaus", ioc=ioc, error=f"HTTP {exc.response.status_code}")
    except Exception as exc:
        return EnrichmentResult(source="URLhaus", ioc=ioc, error=str(exc))

    if payload.get("query_status") == "no_results":
        return EnrichmentResult(source="URLhaus", ioc=ioc, data={"found": False})

    urls = (payload.get("urls") or [])[:10]
    return EnrichmentResult(
        source="URLhaus",
        ioc=ioc,
        data={
            "found": True,
            "urlhaus_reference": payload.get("urlhaus_reference"),
            "blacklists": payload.get("blacklists", {}),
            "url_count": payload.get("url_count", len(urls)),
            "urls": [
                {
                    "url": u.get("url"),
                    "url_status": u.get("url_status"),
                    "threat": u.get("threat"),
                    "date_added": u.get("date_added"),
                    "tags": u.get("tags"),
                }
                for u in urls
            ],
        },
    )
