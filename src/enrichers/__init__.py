"""
Enricher registry.
Each function signature: enrich(ioc: IOC) -> EnrichmentResult
"""

from src.enrichers import (
    abuseipdb, virustotal, urlscan, ipapi,
    shodan_internetdb, greynoise, urlhaus, threatfox, malwarebazaar,
)

ENRICHERS_BY_TYPE: dict[str, list] = {
    "ip":     [abuseipdb.enrich, virustotal.enrich, urlscan.enrich, ipapi.enrich,
               shodan_internetdb.enrich, greynoise.enrich, urlhaus.enrich, threatfox.enrich],
    "domain": [virustotal.enrich, urlscan.enrich, urlhaus.enrich, threatfox.enrich],
    "hash":   [virustotal.enrich, threatfox.enrich, malwarebazaar.enrich],
}
