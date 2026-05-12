"""
Enricher registry.

Each function signature: enrich(ioc: IOC, keys: dict | None = None) -> EnrichmentResult.

Sources cared about (the ones really wired below):
  - AbuseIPDB         IP reputation (clé requise)
  - VirusTotal        AV agregat + signature/PE/exiftool/YARA/sandbox/relations
  - ip-api.com        géo + ASN + flags hosting/proxy/mobile (pas de clé)
  - urlscan.io        scans publics (clé optionnelle)
  - Shodan InternetDB ports/CVE/CPE/hostnames (pas de clé)
  - GreyNoise         noise/RIOT/classification (clé Community gratuite)
  - URLhaus           hosts/payloads malveillants (abuse.ch Auth-Key)
  - ThreatFox         IOC tagué par famille malware (abuse.ch Auth-Key)
  - MalwareBazaar     lookup hash (abuse.ch Auth-Key)
"""

from src.enrichers import (
    abuseipdb,
    virustotal,
    urlscan,
    ipapi,
    shodan_internetdb,
    greynoise,
    urlhaus,
    threatfox,
    malwarebazaar,
)

ENRICHERS_BY_TYPE: dict[str, list] = {
    "ip": [
        abuseipdb.enrich,
        virustotal.enrich,
        urlscan.enrich,
        ipapi.enrich,
        shodan_internetdb.enrich,
        greynoise.enrich,
        urlhaus.enrich,
        threatfox.enrich,
    ],
    "domain": [
        virustotal.enrich,
        urlscan.enrich,
        urlhaus.enrich,
        threatfox.enrich,
    ],
    "hash": [
        virustotal.enrich,
        malwarebazaar.enrich,
        threatfox.enrich,
        urlhaus.enrich,
    ],
}
