"""
Enricher registry.
Each function signature: enrich(ioc: IOC) -> EnrichmentResult
"""

from src.enrichers import abuseipdb, virustotal, urlscan, shodan, mxtoolbox

ENRICHERS_BY_TYPE: dict[str, list] = {
    "ip":     [abuseipdb.enrich, virustotal.enrich, urlscan.enrich, shodan.enrich, mxtoolbox.enrich],
    "domain": [virustotal.enrich, urlscan.enrich, shodan.enrich, mxtoolbox.enrich],
    "hash":   [virustotal.enrich],
}
