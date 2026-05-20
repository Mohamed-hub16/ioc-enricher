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


_HASH_RELATIONSHIPS = [
    ("execution_parents",    5),
    ("pe_resource_parents",  5),
    ("contacted_urls",       5),
    ("contacted_domains",    8),
    ("contacted_ips",        8),
    ("dropped_files",        8),
    ("bundled_files",        5),
    ("pe_resource_children", 5),
]


def _get_file_relationships(file_hash: str, api_key: str) -> dict:
    """Fetch top related entities for a hash: parents, network contacts, children."""
    result = {}
    for rel_type, limit in _HASH_RELATIONSHIPS:
        try:
            resp = httpx.get(
                f"{_BASE}/files/{file_hash}/{rel_type}",
                headers={"x-apikey": api_key},
                params={"limit": limit},
                timeout=_TIMEOUT,
            )
            if resp.status_code != 200:
                continue
            body = resp.json()
            meta = body.get("meta") or {}
            total = meta.get("total_hits") or meta.get("count") or len(body.get("data", []))
            items = []
            for item in body.get("data", []):
                attrs = item.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                mal = stats.get("malicious", 0)
                tot = sum(stats.values()) if stats else 0
                if rel_type == "contacted_urls":
                    name = attrs.get("url", "")
                elif rel_type in ("contacted_domains", "contacted_ips"):
                    name = item.get("id", "")
                else:
                    name = (attrs.get("meaningful_name") or
                            attrs.get("name") or
                            item.get("id", "")[:20])
                items.append({
                    "name": (name or "")[:100],
                    "malicious": mal,
                    "total": tot,
                    "type": attrs.get("type_description") or attrs.get("type_tag") or "",
                })
            if total or items:
                result[rel_type] = {"total": total, "items": items}
        except Exception:
            continue
    return result


def enrich(ioc: IOC, keys: dict | None = None) -> EnrichmentResult:
    api_key = keys.get("VIRUSTOTAL_API_KEY", "") if keys is not None else os.getenv("VIRUSTOTAL_API_KEY", "")
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
                "details": str(ctx.get("details") or "")[:400],
                "timestamp": str(ctx.get("timestamp") or "")[:10],
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
        import datetime as _dt

        def _ts(v):
            if not v:
                return None
            try:
                return _dt.datetime.utcfromtimestamp(int(v)).strftime("%Y-%m-%d")
            except Exception:
                return str(v)

        data.update({
            "meaningful_name": attrs.get("meaningful_name"),
            "names": (attrs.get("names") or [])[:10],
            "type_description": attrs.get("type_description"),
            "magic": attrs.get("magic"),
            "sha256": attrs.get("sha256"),
            "sha1": attrs.get("sha1"),
            "md5": attrs.get("md5"),
            "file_size": attrs.get("size"),
            "ssdeep": attrs.get("ssdeep"),
            "tlsh": attrs.get("tlsh"),
            "vhash": attrs.get("vhash"),
            "first_submission_date": _ts(attrs.get("first_submission_date")),
            "last_submission_date": _ts(attrs.get("last_submission_date")),
            "times_submitted": attrs.get("times_submitted"),
            "unique_sources": attrs.get("unique_sources"),
        })

        # Code signing
        sig = attrs.get("signature_info", {})
        if sig:
            data["signature_info"] = {k: v for k, v in {
                "subject": sig.get("subject"),
                "issuer": sig.get("issuer"),
                "valid_from": sig.get("valid from"),
                "valid_to": sig.get("valid to"),
                "verified": sig.get("verified"),
                "signers": sig.get("signers"),
            }.items() if v}

        # PE metadata
        pe = attrs.get("pe_info", {})
        if pe:
            data["pe_compilation_date"] = pe.get("compilation-date") or pe.get("compilation_timestamp")
            data["pe_imphash"] = pe.get("imphash")
            sections = pe.get("sections", [])
            if sections:
                data["pe_sections"] = [
                    {"name": s.get("name"), "entropy": s.get("entropy"), "md5": s.get("md5")}
                    for s in sections[:8]
                ]

        # Exiftool (CompanyName, ProductName, version…)
        exif = attrs.get("exiftool", {})
        if exif:
            relevant = {f: exif[f] for f in [
                "CompanyName", "ProductName", "FileVersion", "OriginalFilename",
                "InternalName", "FileDescription", "LegalCopyright", "ProductVersion",
                "FileType", "MIMEType",
            ] if exif.get(f)}
            if relevant:
                data["exiftool"] = relevant

        # Popular threat classification
        tc = attrs.get("popular_threat_classification", {})
        if tc:
            data["popular_threat_label"] = tc.get("suggested_threat_label")
            cats = [c.get("value") for c in tc.get("popular_threat_category", []) if c.get("value")]
            if cats:
                data["threat_categories"] = cats
            names = [n.get("value") for n in tc.get("popular_threat_name", []) if n.get("value")]
            if names:
                data["threat_names"] = names

        # Crowdsourced context
        ctx_items = []
        for ctx in (attrs.get("crowdsourced_context") or [])[:10]:
            ctx_items.append({
                "source": ctx.get("source", ""),
                "title": ctx.get("title", ""),
                "severity": ctx.get("severity", ""),
                "details": str(ctx.get("details") or "")[:400],
                "timestamp": str(ctx.get("timestamp") or "")[:10],
            })
        if ctx_items:
            data["crowdsourced_context"] = ctx_items

        # YARA rules
        yara = (attrs.get("crowdsourced_yara_results") or [])[:10]
        if yara:
            data["yara_rules"] = [
                {
                    "rule_name": y.get("rule_name"),
                    "ruleset_name": y.get("ruleset_name"),
                    "description": (y.get("description") or "")[:200],
                    "source": y.get("source"),
                }
                for y in yara
            ]

        # Sandbox verdicts
        sb = attrs.get("sandbox_verdicts", {})
        if sb:
            data["sandbox_verdicts"] = [
                {
                    "sandbox": name,
                    "category": v.get("category"),
                    "malware_names": v.get("malware_classification", []),
                }
                for name, v in list(sb.items())[:6]
            ]

        # Relationship graph data
        rels = _get_file_relationships(ioc.value, api_key)
        if rels:
            data["relationships"] = rels

    return EnrichmentResult(source="VirusTotal", ioc=ioc, data=data)
