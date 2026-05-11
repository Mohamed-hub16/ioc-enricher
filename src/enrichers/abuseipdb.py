"""AbuseIPDB enricher — IP reputation via https://www.abuseipdb.com/"""

import os
import httpx
from src.models import IOC, EnrichmentResult

_BASE_URL = "https://api.abuseipdb.com/api/v2/check"
_TIMEOUT = 10.0

_CATEGORIES = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
    12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


def enrich(ioc: IOC, keys: dict | None = None) -> EnrichmentResult:
    api_key = (keys or {}).get("ABUSEIPDB_API_KEY") or os.getenv("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return EnrichmentResult(source="AbuseIPDB", ioc=ioc, error="ABUSEIPDB_API_KEY not set")

    try:
        resp = httpx.get(
            _BASE_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ioc.value, "maxAgeInDays": 90, "verbose": True},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        payload = resp.json().get("data", {})
    except httpx.HTTPStatusError as exc:
        return EnrichmentResult(source="AbuseIPDB", ioc=ioc, error=f"HTTP {exc.response.status_code}")
    except Exception as exc:
        return EnrichmentResult(source="AbuseIPDB", ioc=ioc, error=str(exc))

    # Collect unique abuse categories from the verbose reports list
    seen_cats: set[int] = set()
    for report in payload.get("reports", []):
        for cat_id in report.get("categories", []):
            seen_cats.add(cat_id)
    abuse_categories = [_CATEGORIES[c] for c in sorted(seen_cats) if c in _CATEGORIES]

    return EnrichmentResult(
        source="AbuseIPDB",
        ioc=ioc,
        data={
            "abuse_confidence_score": payload.get("abuseConfidenceScore"),
            "country_code": payload.get("countryCode"),
            "country_name": payload.get("countryName"),
            "isp": payload.get("isp"),
            "domain": payload.get("domain"),
            "usage_type": payload.get("usageType"),
            "total_reports": payload.get("totalReports"),
            "num_distinct_users": payload.get("numDistinctUsers"),
            "last_reported_at": payload.get("lastReportedAt"),
            "is_whitelisted": payload.get("isWhitelisted"),
            "abuse_categories": abuse_categories,
        },
    )
