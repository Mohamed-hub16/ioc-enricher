"""MXToolBox enricher — blacklist, MX records, TXT/SPF (https://mxtoolbox.com)"""
import os
import httpx
from src.models import IOC, EnrichmentResult

_BASE = "https://api.mxtoolbox.com/api/v1/lookup"
_TIMEOUT = 20.0


def _call(command: str, value: str, api_key: str) -> dict:
    resp = httpx.get(
        f"{_BASE}/{command}/{value}",
        headers={"Authorization": api_key},
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def enrich(ioc: IOC, keys: dict | None = None) -> EnrichmentResult:
    api_key = (keys or {}).get("MXTOOLBOX_API_KEY") or os.getenv("MXTOOLBOX_API_KEY", "")
    if not api_key:
        return EnrichmentResult(source="MXToolBox", ioc=ioc, error="MXTOOLBOX_API_KEY not set")

    try:
        bl = _call("blacklist", ioc.value, api_key)
        blacklisted = [item["Name"] for item in bl.get("Failed", [])]
        data = {
            "blacklisted_on": blacklisted[:15],
            "blacklist_passed": len(bl.get("Passed", [])),
            "blacklist_total_checked": len(bl.get("Failed", [])) + len(bl.get("Passed", [])) + len(bl.get("Timeouts", [])),
        }
    except httpx.HTTPStatusError as exc:
        return EnrichmentResult(source="MXToolBox", ioc=ioc, error=f"HTTP {exc.response.status_code}")
    except Exception as exc:
        return EnrichmentResult(source="MXToolBox", ioc=ioc, error=str(exc))

    if ioc.type == "domain":
        try:
            mx = _call("mx", ioc.value, api_key)
            records = [
                {"domain": item.get("Domain-Name"), "pref": item.get("Pref"), "ip": item.get("IP-Address")}
                for item in mx.get("Information", [])[:10]
            ]
            if records:
                data["mx_records"] = records
        except Exception:
            pass

        try:
            txt = _call("txt", ioc.value, api_key)
            txt_vals = [item.get("Value", "")[:200] for item in txt.get("Information", [])[:5] if item.get("Value")]
            if txt_vals:
                data["txt_records"] = txt_vals
        except Exception:
            pass

    return EnrichmentResult(
        source="MXToolBox",
        ioc=ioc,
        data={k: v for k, v in data.items() if v is not None and v != [] and v != ""},
    )
