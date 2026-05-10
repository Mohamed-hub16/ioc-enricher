"""urlscan.io enricher — https://urlscan.io (public search, API key optional)"""

import os
import httpx
from src.models import IOC, EnrichmentResult

_BASE = "https://urlscan.io/api/v1"
_TIMEOUT = 15.0


def enrich(ioc: IOC) -> EnrichmentResult:
    if ioc.type == "ip":
        query = f"ip:{ioc.value}"
    elif ioc.type == "domain":
        query = f"domain:{ioc.value}"
    else:
        return EnrichmentResult(source="urlscan.io", ioc=ioc, error=f"Unsupported type: {ioc.type}")

    headers: dict[str, str] = {}
    api_key = os.getenv("URLSCAN_API_KEY", "")
    if api_key:
        headers["API-Key"] = api_key

    try:
        resp = httpx.get(
            f"{_BASE}/search/",
            params={"q": query, "size": 5},
            headers=headers,
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        payload = resp.json()
    except httpx.HTTPStatusError as exc:
        return EnrichmentResult(source="urlscan.io", ioc=ioc, error=f"HTTP {exc.response.status_code}")
    except Exception as exc:
        return EnrichmentResult(source="urlscan.io", ioc=ioc, error=str(exc))

    raw_results = payload.get("results", [])
    total = payload.get("total", 0)

    scans = []
    for r in raw_results[:5]:
        verdicts = r.get("verdicts", {}).get("overall", {})
        scans.append({
            "url": r.get("task", {}).get("url"),
            "time": r.get("task", {}).get("time"),
            "domain": r.get("page", {}).get("domain"),
            "ip": r.get("page", {}).get("ip"),
            "score": verdicts.get("score", 0),
            "malicious": verdicts.get("malicious", False),
            "tags": verdicts.get("tags", []),
        })

    malicious_count = sum(1 for s in scans if s.get("malicious"))

    return EnrichmentResult(
        source="urlscan.io",
        ioc=ioc,
        data={
            "total_scans": total,
            "recent_scans": scans,
            "malicious_count": malicious_count,
        },
    )
