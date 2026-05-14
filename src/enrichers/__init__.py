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

# Maps each enricher function → the source name it sets in EnrichmentResult.source
# Used by patch_enrich.py to detect which sources are missing on existing records.
ENRICHER_SOURCE_NAME: dict = {
    abuseipdb.enrich:         "AbuseIPDB",
    virustotal.enrich:        "VirusTotal",
    urlscan.enrich:           "urlscan.io",
    ipapi.enrich:             "ip-api.com",
    shodan_internetdb.enrich: "Shodan InternetDB",
    greynoise.enrich:         "GreyNoise",
    urlhaus.enrich:           "URLhaus",
    threatfox.enrich:         "ThreatFox",
    malwarebazaar.enrich:     "MalwareBazaar",
}
