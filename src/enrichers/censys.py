"""Censys enricher — ports, services, ASN, geo (https://search.censys.io)"""
import os
import httpx
from src.models import IOC, EnrichmentResult

_BASE = "https://search.censys.io/api/v2"
_TIMEOUT = 15.0


def enrich(ioc: IOC, keys: dict | None = None) -> EnrichmentResult:
    api_id     = (keys or {}).get("CENSYS_API_ID")     or os.getenv("CENSYS_API_ID", "")
    api_secret = (keys or {}).get("CENSYS_API_SECRET") or os.getenv("CENSYS_API_SECRET", "")

    if not api_id or not api_secret:
        return EnrichmentResult(source="Censys", ioc=ioc, error="CENSYS_API_ID / CENSYS_API_SECRET not set")

    if ioc.type != "ip":
        return EnrichmentResult(source="Censys", ioc=ioc, error=f"Unsupported type: {ioc.type}")

    try:
        resp = httpx.get(
            f"{_BASE}/hosts/{ioc.value}",
            auth=(api_id, api_secret),
            timeout=_TIMEOUT,
        )
        if resp.status_code == 404:
            return EnrichmentResult(source="Censys", ioc=ioc, error="No information available")
        resp.raise_for_status()
        payload = resp.json().get("result", {})
    except httpx.HTTPStatusError as exc:
        return EnrichmentResult(source="Censys", ioc=ioc, error=f"HTTP {exc.response.status_code}")
    except Exception as exc:
        return EnrichmentResult(source="Censys", ioc=ioc, error=str(exc))

    services = []
    for svc in (payload.get("services") or [])[:10]:
        entry = {
            "port":      svc.get("port"),
            "transport": (svc.get("transport_protocol") or "TCP").upper(),
            "service":   svc.get("service_name") or "",
        }
        sw_list = svc.get("software") or []
        if sw_list:
            entry["product"] = sw_list[0].get("product") or ""
            entry["version"] = sw_list[0].get("version") or ""
        if entry["port"]:
            services.append({k: v for k, v in entry.items() if v})

    loc = payload.get("location") or {}
    asn = payload.get("autonomous_system") or {}
    dns = payload.get("dns") or {}
    reverse = (dns.get("reverse_dns") or {}).get("names") or []

    data = {
        "country":        loc.get("country"),
        "city":           loc.get("city"),
        "asn":            asn.get("asn"),
        "as_name":        asn.get("name"),
        "as_description": asn.get("description"),
        "bgp_prefix":     asn.get("bgp_prefix"),
        "reverse_dns":    reverse[:5],
        "services":       services,
        "labels":         payload.get("labels") or [],
        "last_updated":   (payload.get("last_updated_at") or "")[:10] or None,
    }

    return EnrichmentResult(
        source="Censys",
        ioc=ioc,
        data={k: v for k, v in data.items() if v is not None and v != [] and v != ""},
    )
