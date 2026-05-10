"""VirusTotal enricher — https://www.virustotal.com (free tier: 500 req/day)"""

import os
import httpx
from src.models import IOC, EnrichmentResult

_BASE = "https://www.virustotal.com/api/v3"
_TIMEOUT = 15.0


def _extract_detections(last_analysis_results: dict) -> tuple[list[str], list[str]]:
    vendors: list[str] = []
    labels: set[str] = set()
    for engine, detail in last_analysis_results.items():
        if detail.get("category") == "malicious":
            vendors.append(engine)
            result = (detail.get("result") or "").strip()
            if result and result.lower() not in ("malicious", "malware", ""):
                labels.add(result)
    return sorted(vendors), sorted(labels)


def _get_related_files(ip: str, api_key: str) -> list[dict]:
    """Fetch top communicating files for an IP (separate API call)."""
    try:
        resp = httpx.get(
            f"{_BASE}/ip_addresses/{ip}/communicating_files",
            headers={"x-apikey": api_key},
            params={"limit": 5},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return []
        result = []
        for item in resp.json().get("data", []):
            attrs = item.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            tot = sum(stats.values()) if stats else 0
            result.append({
                "name": attrs.get("meaningful_name") or attrs.get("name") or "—",
                "type": attrs.get("type_description") or attrs.get("magic") or "—",
                "sha256": (attrs.get("sha256") or "")[:20] + "…",
                "malicious": mal,
                "total": tot,
            })
        return result
    except Exception:
        return []


def enrich(ioc: IOC) -> EnrichmentResult:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return EnrichmentResult(source="VirusTotal", ioc=ioc, error="VIRUSTOTAL_API_KEY not set")

    if ioc.type == "ip":
        endpoint = f"{_BASE}/ip_addresses/{ioc.value}"
    elif ioc.type == "domain":
        endpoint = f"{_BASE}/domains/{ioc.value}"
    elif ioc.type == "hash":
        endpoint = f"{_BASE}/files/{ioc.value}"
    else:
        return EnrichmentResult(source="VirusTotal", ioc=ioc, error=f"Unsupported type: {ioc.type}")

    try:
        resp = httpx.get(endpoint, headers={"x-apikey": api_key}, timeout=_TIMEOUT)
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
    except httpx.HTTPStatusError as exc:
        return EnrichmentResult(source="VirusTotal", ioc=ioc, error=f"HTTP {exc.response.status_code}")
    except Exception as exc:
        return EnrichmentResult(source="VirusTotal", ioc=ioc, error=str(exc))

    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0

    malicious_vendors, threat_labels = _extract_detections(
        attrs.get("last_analysis_results", {})
    )

    votes = attrs.get("total_votes", {})

    data: dict = {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total_engines": total,
        "reputation": attrs.get("reputation"),
        "tags": attrs.get("tags", []),
        "malicious_vendors": malicious_vendors,
        "threat_labels": threat_labels,
        "votes_malicious": votes.get("malicious", 0),
        "votes_harmless": votes.get("harmless", 0),
    }

    if ioc.type == "ip":
        # Crowdsourced context: Talos, MalBeacon, threat actor reports, CVE references
        raw_ctx = attrs.get("crowdsourced_context", [])
        ctx_items = []
        for ctx in raw_ctx[:10]:
            ctx_items.append({
                "source": ctx.get("source", ""),
                "title": ctx.get("title", ""),
                "severity": ctx.get("severity", ""),
                "details": (ctx.get("details") or "")[:400],
                "timestamp": (ctx.get("timestamp") or "")[:10],
            })

        # IDS/IPS rules that fired (Suricata, Snort — CVEs, attack patterns)
        raw_ids = attrs.get("crowdsourced_ids_results", [])
        ids_rules = []
        seen_msgs: set[str] = set()
        for rule in raw_ids:
            msg = rule.get("rule_msg") or rule.get("rule_name") or ""
            if msg and msg not in seen_msgs:
                seen_msgs.add(msg)
                ids_rules.append({
                    "rule_source": rule.get("rule_source", ""),
                    "rule_name": rule.get("rule_name", ""),
                    "severity": rule.get("alert_severity", ""),
                    "rule_msg": msg,
                })
            if len(ids_rules) >= 15:
                break

        data.update({
            "country": attrs.get("country"),
            "as_owner": attrs.get("as_owner"),
            "asn": attrs.get("asn"),
            "network": attrs.get("network"),
            "regional_internet_registry": attrs.get("regional_internet_registry"),
            "crowdsourced_context": ctx_items,
            "ids_rules": ids_rules,
        })

        comm_files = _get_related_files(ioc.value, api_key)
        if comm_files:
            data["communicating_files"] = comm_files

    elif ioc.type == "domain":
        data.update({
            "registrar": attrs.get("registrar"),
            "creation_date": attrs.get("creation_date"),
            "categories": attrs.get("categories", {}),
            "whois": (attrs.get("whois", "") or "")[:500],
        })
    elif ioc.type == "hash":
        data.update({
            "meaningful_name": attrs.get("meaningful_name"),
            "type_description": attrs.get("type_description"),
            "magic": attrs.get("magic"),
            "sha256": attrs.get("sha256"),
            "md5": attrs.get("md5"),
            "file_size": attrs.get("size"),
        })

    return EnrichmentResult(source="VirusTotal", ioc=ioc, data=data)
