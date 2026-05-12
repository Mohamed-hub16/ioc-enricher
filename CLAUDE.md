# CLAUDE.md — ioc-enricher

## Project purpose
Web application + CLI tool for SOC analysts to enrich IOCs (IPs, domains, hashes) by querying
AbuseIPDB, VirusTotal, ip-api.com and urlscan.io, then generating an AI analysis paragraph and
storing results in a searchable team interface. Exposes a REST API for programmatic access.

## Layout
```
app.py                    # Flask entry point (calls create_app())
main.py                   # CLI entry point
webapp/
  __init__.py             # Flask factory: SQLAlchemy, CSRF, LoginManager, blueprint registration
  models.py               # SQLAlchemy models: User, IOCRecord, Comment
  auth.py                 # Blueprints: /login /register /logout /settings/api-keys
                          #             /settings/api-token/generate|revoke
  ioc_routes.py           # Blueprints: / /ioc/<value> /enrich /export/excel
                          #             /ioc/<value>/delete /ioc/<value>/comment
  admin_routes.py         # Blueprint: /admin/users approve/revoke
  deploy_routes.py        # Blueprint: POST /webhook/deploy — GitHub auto-deploy webhook
  api_routes.py           # Blueprint: /api/v1/ — REST API (X-API-Key auth, CSRF-exempt)
  templates/              # Jinja2 + Bootstrap 5 dark theme
    base.html
    index.html            # IOC list with search, filters, Export Excel button
    ioc_detail.html       # Score gauge, AI paragraph, vis-network graph, raw accordions,
                          # malicious vendors (badges rouges), comments section
    enrich.html           # Submission form
    admin.html            # User approval panel
    api_keys.html         # Per-user 3rd-party keys + REST API token management
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
- API keys loaded from `.env` (admin) or from per-user encrypted columns (analysts)
- HTTP calls use `httpx` with a shared timeout (10–15 s)

## Enrichers by IOC type
```python
ENRICHERS_BY_TYPE = {
    "ip":     [abuseipdb.enrich, virustotal.enrich, ipapi.enrich, urlscan.enrich],
    "domain": [virustotal.enrich, urlscan.enrich],
    "hash":   [virustotal.enrich],   # hashes: VT only, but very rich extraction
}
```

`ip-api.com` (free, no API key required) returns: country, city, ISP, ASN, as_name,
network_type, reverse_dns.

## VirusTotal extraction

### IPs and domains
`malicious_vendors` (list[str]) and `threat_labels` (list[str]) are extracted from
`last_analysis_results` for all types. For IPs: also `crowdsourced_context`,
`crowdsourced_ids_results` (Suricata/Snort rules), `communicating_files`.
For domains: `registrar`, `creation_date`, `categories`, `whois`.

### Hashes (rich)
Names, sha256/sha1/md5, ssdeep/tlsh/vhash, file size/type, first/last submission dates,
`signature_info` (signer, issuer, validity), `pe_info` (compilation date, imphash, sections),
`exiftool` (CompanyName, ProductName, FileVersion, OriginalFilename…),
`popular_threat_classification` (label, categories, names), `crowdsourced_context`,
`yara_rules` (crowdsourced), `sandbox_verdicts`, relationship graph data
(execution_parents, contacted_urls/domains/ips, dropped_files, bundled_files…).

## Threat score (0–100)
Computed in `ioc_routes._compute_threat_score()`:
- IP/domain: `round(abuse_confidence * 0.5 + vt_detection_ratio * 0.5)`
- Hash (no AbuseIPDB): 100% based on VT detection ratio
- MXToolBox blacklist bonus: `min(20, blacklisted_count * 4)`
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
**User**: id, email, password_hash, role (`admin`|`analyst`|`pending`), created_at,
  rest_api_key_hash (SHA-256 of the REST token, shown once at generation),
  virustotal_key_enc, abuseipdb_key_enc, urlscan_key_enc, groq_key_enc (AES-128-GCM)

**IOCRecord**: id, value, ioc_type, enriched_at, enriched_by, raw_results (JSON),
  paragraph, threat_score, view_count

**Comment**: id, ioc_record_id (FK), author, content, created_at, enriched_at_snapshot

`IOCRecord.is_stale` = age > 14 days → triggers re-enrichment prompt on detail page.

## REST API v1
Blueprint: `webapp/api_routes.py` — prefix `/api/v1/`, CSRF-exempt.
Authentication: `X-API-Key: <token>` header (token generated in Paramètres → Token API REST).
Token stored as SHA-256 hash in `users.rest_api_key_hash`.

| Method | Endpoint | Auth | Notes |
|--------|----------|------|-------|
| GET | `/api/v1/iocs` | approved | Paginated list; params: q, type, min_score, sort, page, per_page |
| GET | `/api/v1/ioc/<value>` | approved | Full detail including raw_results + paragraph |
| POST | `/api/v1/enrich` | approved | Body: `{"ioc": "…", "force": false}` — uses caller's API keys |
| DELETE | `/api/v1/ioc/<value>` | admin | Deletes IOC and its comments |

## Excel export
`GET /export/excel` (login required, approved) — downloads
`ioc_export_YYYYMMDD_HHMM.xlsx` with 3 sheets (IPs, DOMAINs, HASHs).
Columns: Valeur, Score global, Score AbuseIPDB, Score VirusTotal, Vues, Malveillant,
Enrichi le, Enrichi par. Malicious rows highlighted in red.
Score AbuseIPDB is empty for hashes (AbuseIPDB does not cover hashes).

## Relation graph (vis-network)
`ioc_detail.html` embeds a vis-network graph:
- **Hash** — hierarchical LR layout: execution parents, PE resource parents,
  contacted URLs/domains/IPs, dropped/bundled files, PE children, file identity,
  signature, PE info, ExifTool, threat classification, detection vendors, sandboxes,
  YARA, crowdsourced context.
- **IP/domain** — force-directed: geo, ASN/ISP, VT tags, IDS rules, crowdsourced
  context, detection vendors hub (malicious_vendors → up to 8 scanner nodes),
  communicating files, blacklists, urlscan domains.

## Comments
Analysts can leave comments on any IOC detail page. A badge warns if the IOC was
re-enriched after the comment was written (enriched_at_snapshot comparison).

## Malicious vendors display
In the raw data accordion (VirusTotal section), the `malicious_vendors` key is rendered
as red `bg-danger` badges labelled "Scanners détecteurs".
In the graph, a "Détections (X/Y)" hub node groups the scanner nodes for IP and domain
types (same as the existing hash graph behaviour).

## Per-user API key management
Analysts configure their own 3rd-party keys at `/settings/api-keys` (AES-128-GCM encrypted).
Admin accounts use the global `.env` keys.
The REST API token (for the `/api/v1/` endpoints) is managed separately in the same page.

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
