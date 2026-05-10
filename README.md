# IOC Enricher

A threat intelligence tool for SOC analysts. Enriches IPs, domains, and file hashes by querying free-tier APIs, generates an AI-written analysis paragraph, and stores everything in a searchable web interface accessible to your team.

---

## Features

- **Multi-source enrichment** — AbuseIPDB, VirusTotal, urlscan.io
- **AI synthesis** — generates a SOC-ready paragraph per IOC via Groq (llama-3.3-70b), in French
- **Web interface** — browse history, search past IOCs, re-enrich stale data
- **Smart cache** — results stored in SQLite; IOCs under 7 days old are served instantly
- **Team access** — read-only for everyone, enrichment requires an approved account
- **Admin panel** — approve / revoke analyst accounts
- **CLI mode** — still works as a standalone script for quick offline use

---

## Supported sources

| Source | IOC types | Free tier |
|---|---|---|
| AbuseIPDB | IP | 1 000 req / day |
| VirusTotal | IP, domain, hash | 500 req / day |
| urlscan.io | Domain | 1 000 req / day |
| Groq | All (AI synthesis) | Free tier available |

---

## Project structure

```
app.py                  # Flask entry point (web app)
main.py                 # CLI entry point
webapp/
  __init__.py           # Flask app factory
  models.py             # SQLAlchemy models (User, IOCRecord)
  auth.py               # /login  /register  /logout
  ioc_routes.py         # /  /ioc/<value>  /enrich
  admin_routes.py       # /admin/users  approve  revoke
  templates/            # Bootstrap 5 dark-themed templates
src/
  enrichers/            # One module per API (abuseipdb, virustotal, urlscan)
  parsers/              # IOC type detection (IP / domain / hash)
  synthesis/            # Groq AI paragraph generator
  models.py             # Shared dataclasses (IOC, EnrichmentResult)
instance/               # SQLite database (git-ignored)
output/                 # CLI-generated HTML reports (git-ignored)
```

---

## Setup

### 1. Clone and install dependencies

```bash
git clone https://github.com/Mohamed-hub16/ioc-enricher.git
cd ioc-enricher
pip install -r requirements.txt
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` with your API keys:

```env
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
URLSCAN_API_KEY=your_key_here
GROQ_API_KEY=your_key_here

SECRET_KEY=your_flask_secret_key   # python -c "import secrets; print(secrets.token_hex(32))"
ADMIN_EMAIL=your@email.com         # this account gets admin rights automatically on first registration
```

### 3. Get your API keys (all free)

| Service | URL |
|---|---|
| AbuseIPDB | https://www.abuseipdb.com/account/api |
| VirusTotal | https://www.virustotal.com/gui/my-apikey |
| urlscan.io | https://urlscan.io/user/signup |
| Groq | https://console.groq.com/keys |

---

## Web app

```bash
python3 app.py
# → http://localhost:5000
```

**First run:** register with the email set in `ADMIN_EMAIL` — your account is automatically approved as admin.

**For colleagues:** they register at `/register`, you approve them from `/admin/users`.

### Access levels

| Action | Anonymous | Approved analyst | Admin |
|---|---|---|---|
| Browse IOC history | ✅ | ✅ | ✅ |
| Search past IOCs | ✅ | ✅ | ✅ |
| Submit / enrich IOCs | ❌ | ✅ | ✅ |
| Approve accounts | ❌ | ❌ | ✅ |

---

## CLI

The original CLI is still available for quick offline use or scripting:

```bash
# Single IOC
python3 main.py --ioc 8.8.8.8

# Multiple IOCs inline
python3 main.py --ioc 1.2.3.4 evil.example.com d41d8cd98f00b204e9800998ecf8427e

# From a file (one IOC per line, # lines ignored)
python3 main.py --file iocs.txt

# Custom output path
python3 main.py --file iocs.txt --output report.html

# Skip AI synthesis
python3 main.py --ioc 1.2.3.4 --no-ai
```

Reports are saved to `output/<YYYYMMDD_HHMMSS>.html` by default.

### Input file format

```
# IPs
185.220.101.45
1.2.3.4

# Domains
phishing.example.com

# Hashes (MD5 / SHA1 / SHA256)
d41d8cd98f00b204e9800998ecf8427e
```

---

## Deploy (Railway — free)

1. Push the repo to GitHub
2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
3. Add all environment variables from `.env`
4. Railway auto-detects the `Procfile` and deploys

---

## Adding a new enricher

1. Create `src/enrichers/<name>.py` with an `enrich(ioc: IOC) -> EnrichmentResult` function
2. Register it in `src/enrichers/__init__.py` under `ENRICHERS_BY_TYPE`
3. Add the API key variable to `.env.example`

---

## Tests

```bash
pytest tests/
```
