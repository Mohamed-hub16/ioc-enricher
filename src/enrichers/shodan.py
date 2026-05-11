"""Shodan enricher — open ports, CVEs, banners, DNS records (https://www.shodan.io)"""
import os
import httpx
from src.models import IOC, EnrichmentResult

_BASE = "https://api.shodan.io"
_TIMEOUT = 15.0


def enrich(ioc: IOC, keys: dict | None = None) -> EnrichmentResult:
    api_key = (keys or {}).get("SHODAN_API_KEY") or os.getenv("SHODAN_API_KEY", "")
    if not api_key:
        return EnrichmentResult(source="Shodan", ioc=ioc, error="SHODAN_API_KEY not set")

    try:
        if ioc.type == "ip":
            resp = httpx.get(
                f"{_BASE}/shodan/host/{ioc.value}",
                params={"key": api_key},
                timeout=_TIMEOUT,
            )
        elif ioc.type == "domain":
            resp = httpx.get(
                f"{_BASE}/dns/domain/{ioc.value}",
                params={"key": api_key},
                timeout=_TIMEOUT,
            )
        else:
            return EnrichmentResult(source="Shodan", ioc=ioc, error=f"Unsupported type: {ioc.type}")

        if resp.status_code == 404:
            return EnrichmentResult(source="Shodan", ioc=ioc, error="No information available")
        resp.raise_for_status()
        payload = resp.json()
    except httpx.HTTPStatusError as exc:
        return EnrichmentResult(source="Shodan", ioc=ioc, error=f"HTTP {exc.response.status_code}")
    except Exception as exc:
        return EnrichmentResult(source="Shodan", ioc=ioc, error=str(exc))

    if ioc.type == "ip":
        services = []
        for svc in (payload.get("data") or [])[:8]:
            entry = {k: svc.get(k) for k in ("port", "transport", "product", "version") if svc.get(k)}
            if entry:
                services.append(entry)

        data = {
            "org": payload.get("org"),
            "isp": payload.get("isp"),
            "os": payload.get("os"),
            "city": payload.get("city"),
            "country_name": payload.get("country_name"),
            "ports": payload.get("ports", [])[:20],
            "hostnames": payload.get("hostnames", [])[:10],
            "domains": payload.get("domains", [])[:10],
            "vulns": list((payload.get("vulns") or {}).keys())[:15],
            "tags": payload.get("tags", []),
            "services": services,
            "last_update": payload.get("last_update"),
        }

    else:  # domain
        seen: set[tuple] = set()
        dns_records = []
        for r in (payload.get("data") or []):
            key = (r.get("type"), r.get("value"))
            if key not in seen:
                seen.add(key)
                dns_records.append({
                    "subdomain": r.get("subdomain") or "@",
                    "type": r.get("type"),
                    "value": r.get("value"),
                })
            if len(dns_records) >= 25:
                break

        data = {
            "subdomains": payload.get("subdomains", [])[:20],
            "dns_records": dns_records,
            "tags": payload.get("tags", []),
        }

    return EnrichmentResult(
        source="Shodan",
        ioc=ioc,
        data={k: v for k, v in data.items() if v is not None and v != [] and v != ""},
    )
