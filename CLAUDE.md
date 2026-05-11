# CLAUDE.md — ioc-enricher

## Project purpose
Web application + CLI tool for SOC analysts to enrich IOCs (IPs, domains, hashes) by querying
AbuseIPDB, VirusTotal, and urlscan.io, then generating an AI analysis paragraph and storing
results in a searchable team interface.

## Layout
```
app.py                    # Flask entry point (calls create_app())
main.py                   # CLI entry point
webapp/
  __init__.py             # Flask factory: SQLAlchemy, CSRF, LoginManager, blueprint registration
  models.py               # SQLAlchemy models: User, IOCRecord
  auth.py                 # Blueprints: /login /register /logout
  ioc_routes.py           # Blueprints: / /ioc/<value> /enrich — core enrichment flow
  admin_routes.py         # Blueprint: /admin/users approve/revoke
  deploy_routes.py        # Blueprint: POST /webhook/deploy — GitHub auto-deploy webhook
  templates/              # Jinja2 + Bootstrap 5 dark theme
    base.html
    index.html            # IOC list with search and filters
    ioc_detail.html       # Full IOC detail: score gauge, AI paragraph, raw source accordions
    enrich.html           # Submission form
    admin.html            # User approval panel
    login.html / register.html
src/
  enrichers/              # One module per threat-intel API
  parsers/                # IOC input parsing and type detection
  reporters/              # Output formatters (HTML) — CLI only
  synthesis/              # Groq LLM paragraph generator
  models.py               # Shared dataclasses (IOC, EnrichmentResult)
instance/                 # SQLite database (git-ignored)
output/                   # CLI-generated HTML reports (git-ignored)
.env                      # API keys — never committed
.env.example              # Template for .env
```

## Key conventions
- All enrichers implement the same interface: `enrich(ioc: IOC) -> EnrichmentResult`
- IOC types: `ip`, `domain`, `hash` — detected automatically by the parser
- API keys loaded exclusively from `.env` via `python-dotenv`; missing keys skip that enricher gracefully
- HTTP calls use `httpx` with a shared timeout (10–15 s)

## Enrichers by IOC type
```python
ENRICHERS_BY_TYPE = {
    "ip":     [abuseipdb.enrich, virustotal.enrich, urlscan.enrich],
    "domain": [virustotal.enrich, urlscan.enrich],
    "hash":   [virustotal.enrich],   # hashes: VT only, but very rich extraction
}
```

## VirusTotal hash extraction (rich)
For hashes, `virustotal.enrich` extracts all of: names, sha256/sha1/md5, ssdeep/tlsh/vhash,
file size/type, first_submission_date, last_submission_date, times_submitted, unique_sources,
`signature_info` (signer, issuer, validity), `pe_info` (compilation date, imphash, sections),
`exiftool` (CompanyName, ProductName, FileVersion, OriginalFilename, FileDescription…),
`popular_threat_classification` (label, categories, names), `crowdsourced_context`,
`yara_rules` (crowdsourced), `sandbox_verdicts`.

## Threat score (0–100)
Computed in `ioc_routes._compute_threat_score()`:
- IP/domain: `round(abuse_confidence * 0.5 + vt_detection_ratio * 0.5)`
- Hash (no AbuseIPDB): 100% based on VT detection ratio
- Clamped to [0, 100]

## Groq synthesis
`src/synthesis/groq_synthesizer.synthesize(results, threat_score)` selects the system prompt
based on `ioc.type` AND `threat_score > 0`:
- IP/domain malicious → `_SYSTEM_MALICIOUS` (AbuseIPDB + VT + IDS rules + crowdsourced)
- IP/domain legitimate → `_SYSTEM_LEGITIMATE` (network info, confirm no detections)
- Hash malicious → `_SYSTEM_HASH_MALICIOUS` (file identity, signing, PE, YARA, sandboxes)
- Hash legitimate → `_SYSTEM_HASH_LEGITIMATE` (file identity, signing, confirm clean)

Model: `llama-3.3-70b-versatile` via Groq free tier. All output in French.

## Database models
**User**: id, email, password_hash, role (`admin`|`analyst`|`pending`), created_at
**IOCRecord**: id, value, ioc_type, enriched_at, enriched_by, raw_results (JSON), paragraph, threat_score, view_count

IOCRecord.is_stale = age > 7 days → triggers re-enrichment prompt on detail page.

## Auto-deploy (GitHub → PythonAnywhere)
`webapp/deploy_routes.py` exposes `POST /webhook/deploy`:
1. Verifies HMAC-SHA256 signature using `DEPLOY_SECRET`
2. Runs `git pull origin main` in the repo root
3. Calls PythonAnywhere API `POST /api/v0/user/{PA_USERNAME}/webapps/{PA_DOMAIN}/reload/`

Required env vars: `DEPLOY_SECRET`, `PA_API_TOKEN`, `PA_USERNAME`, `PA_DOMAIN`.

## Running
```bash
# Web app
python3 app.py              # → http://localhost:5000

# CLI
python3 main.py --file iocs.txt
python3 main.py --ioc 1.2.3.4
python3 main.py --ioc 1.2.3.4 8.8.8.8
```

## Tests
```bash
pytest tests/
```

## Adding a new enricher
1. Create `src/enrichers/<name>.py` with an `enrich(ioc: IOC) -> EnrichmentResult` function
2. Register it in `src/enrichers/__init__.py` in `ENRICHERS_BY_TYPE`
3. Add the API key variable to `.env.example`
