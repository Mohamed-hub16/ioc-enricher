# CLAUDE.md — ioc-enricher

## Project purpose
CLI tool for SOC analysts to enrich IOCs (IPs, domains, hashes) by querying
AbuseIPDB, VirusTotal, and urlscan.io, then generating an HTML report.

## Layout
```
src/
  enrichers/     # One module per threat-intel API
  parsers/       # IOC input parsing and type detection
  reporters/     # Output formatters (HTML)
  models.py      # Shared dataclasses (IOC, EnrichmentResult)
main.py          # CLI entry point
tests/           # Unit tests (pytest)
output/          # Generated HTML reports (git-ignored)
.env             # API keys — never committed
.env.example     # Template for .env
```

## Key conventions
- All enrichers implement the same interface: `enrich(ioc: IOC) -> EnrichmentResult`
- IOC types: `ip`, `domain`, `hash` — detected automatically by the parser
- API keys loaded exclusively from `.env` via `python-dotenv`; missing keys skip that enricher gracefully
- HTTP calls use `httpx` with a shared timeout (10 s default)
- Reports written to `output/<timestamp>.html`

## Adding a new enricher
1. Create `src/enrichers/<name>.py` with an `enrich(ioc)` function
2. Register it in `src/enrichers/__init__.py` in `ENRICHERS_BY_TYPE`
3. Add the API key variable to `.env.example`

## Running
```bash
python main.py --file iocs.txt          # from file
python main.py --ioc 1.2.3.4            # single IOC
python main.py --ioc 1.2.3.4 8.8.8.8   # multiple
```

## Tests
```bash
pytest tests/
```
