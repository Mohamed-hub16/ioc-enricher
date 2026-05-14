"""ip-api.com enricher — geo, ASN, ISP, type réseau (gratuit, sans clé)"""
import httpx
from src.models import IOC, EnrichmentResult

_BASE    = "http://ip-api.com/json"
_FIELDS  = "status,message,country,countryCode,regionName,city,isp,org,as,asname,reverse,mobile,proxy,hosting"
_TIMEOUT = 10.0


def enrich(ioc: IOC, keys: dict | None = None) -> EnrichmentResult:
    if ioc.type != "ip":
        return EnrichmentResult(source="ip-api.com", ioc=ioc, error=f"Unsupported type: {ioc.type}")

    try:
        resp = httpx.get(
            f"{_BASE}/{ioc.value}",
            params={"fields": _FIELDS},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:
        return EnrichmentResult(source="ip-api.com", ioc=ioc, error=str(exc))

    if payload.get("status") == "fail":
        return EnrichmentResult(source="ip-api.com", ioc=ioc, error=payload.get("message", "Unknown error"))

    tags = []
    if payload.get("hosting"): tags.append("datacenter/hosting")
    if payload.get("proxy"):   tags.append("proxy/VPN")
    if payload.get("mobile"):  tags.append("mobile")

    data = {
        "country":      payload.get("country"),
        "country_code": payload.get("countryCode"),
        "region":       payload.get("regionName"),
        "city":         payload.get("city"),
        "isp":          payload.get("isp"),
        "org":          payload.get("org"),
        "asn":          payload.get("as"),
        "as_name":      payload.get("asname"),
        "reverse_dns":  payload.get("reverse") or None,
        "network_type": ", ".join(tags) if tags else None,
    }

    return EnrichmentResult(
        source="ip-api.com",
        ioc=ioc,
        data={k: v for k, v in data.items() if v is not None and v != ""},
    )
