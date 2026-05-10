# ioc-enricher

CLI tool for SOC analysts — enriches IOCs (IPs, domains, file hashes) by querying
free-tier threat intelligence APIs and generates a self-contained HTML report.

## Supported APIs

| API | IOC types | Free tier |
|-----|-----------|-----------|
| AbuseIPDB | IP | 1 000 req/day |
| VirusTotal | IP, domain, hash | 500 req/day |
| urlscan.io | Domain, URL | 1 000 req/day |

## Setup

```bash
# 1. Clone and install dependencies
pip install -r requirements.txt

# 2. Copy the env template and fill in your API keys
cp .env.example .env
# edit .env with your keys

# 3. Run
python main.py --file iocs.txt
```

## Usage

```bash
# Enrich IOCs from a file (one per line, comments with # are ignored)
python main.py --file iocs.txt

# Enrich a single IOC
python main.py --ioc 8.8.8.8

# Enrich several IOCs inline
python main.py --ioc 1.2.3.4 evil.example.com d41d8cd98f00b204e9800998ecf8427e

# Choose output path
python main.py --file iocs.txt --output report.html
```

## Input file format

```
# IPs
1.2.3.4
185.220.101.45

# Domains
evil.example.com

# MD5 / SHA1 / SHA256 hashes
d41d8cd98f00b204e9800998ecf8427e
```

## Getting API keys

- **AbuseIPDB**: https://www.abuseipdb.com/account/api
- **VirusTotal**: https://www.virustotal.com/gui/my-apikey
- **urlscan.io**: https://urlscan.io/user/signup (optional for public searches)

## Output

Reports are saved to `output/<YYYYMMDD_HHMMSS>.html` by default.
Open the file in any browser — no external dependencies, everything is inline.
