"""
Enricher registry.
Each function signature: enrich(ioc: IOC) -> EnrichmentResult
"""

from src.enrichers import abuseipdb, virustotal, urlscan, ipapi

ENRICHERS_BY_TYPE: dict[str, list] = {
    "ip":     [abuseipdb.enrich, virustotal.enrich, urlscan.enrich, ipapi.enrich],
    "domain": [virustotal.enrich, urlscan.enrich],
    "hash":   [virustotal.enrich],
}
