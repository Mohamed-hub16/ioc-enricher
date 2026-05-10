#!/usr/bin/env python3
"""ioc-enricher — CLI entry point."""

import argparse
import sys
from datetime import datetime
from dotenv import load_dotenv

from src.parsers.ioc_parser import parse_iocs, parse_file
from src.enrichers import ENRICHERS_BY_TYPE
from src.reporters import html_reporter
from src.synthesis import groq_synthesizer

load_dotenv()


def main():
    parser = argparse.ArgumentParser(
        description="Enrich IOCs via AbuseIPDB, VirusTotal, urlscan.io"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", metavar="PATH", help="Fichier texte avec un IOC par ligne")
    group.add_argument("--ioc", nargs="+", metavar="IOC", help="Un ou plusieurs IOCs en ligne")
    parser.add_argument("--output", metavar="PATH", help="Chemin du rapport HTML (défaut: output/<timestamp>.html)")
    parser.add_argument("--no-ai", action="store_true", help="Désactiver l'analyse IA (Groq)")
    args = parser.parse_args()

    if args.file:
        iocs, unknown = parse_file(args.file)
    else:
        iocs, unknown = parse_iocs(args.ioc)

    if unknown:
        print(f"[!] {len(unknown)} entrée(s) non reconnue(s) ignorée(s) : {', '.join(unknown)}", file=sys.stderr)

    if not iocs:
        print("[!] Aucun IOC valide trouvé. Arrêt.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Enrichissement de {len(iocs)} IOC(s)...")

    results = []
    grouped: dict = {}
    for ioc in iocs:
        enrichers = ENRICHERS_BY_TYPE.get(ioc.type, [])
        if not enrichers:
            print(f"    [-] {ioc.value} ({ioc.type}) — aucun enrichisseur disponible", file=sys.stderr)
            continue
        ioc_results = []
        for fn in enrichers:
            source = fn.__module__.split(".")[-1]
            print(f"    [>] {ioc.value} → {source}")
            r = fn(ioc)
            results.append(r)
            ioc_results.append(r)
        grouped[ioc.value] = ioc_results

    if not results:
        print("[!] Aucun résultat à afficher.", file=sys.stderr)
        sys.exit(1)

    synthesis: dict[str, str | None] = {}
    if not args.no_ai:
        import os
        if os.getenv("GROQ_API_KEY"):
            print("[*] Génération des analyses IA (Groq)...")
            for ioc_value, ioc_results in grouped.items():
                print(f"    [>] {ioc_value} → Groq")
                synthesis[ioc_value] = groq_synthesizer.synthesize(ioc_results)
        else:
            print("[~] GROQ_API_KEY absent — analyse IA ignorée (--no-ai pour masquer ce message)")

    html = html_reporter.render(results, unknown, synthesis=synthesis)

    if args.output:
        out_path = args.output
    else:
        import os
        os.makedirs("output", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join("output", f"{timestamp}.html")

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    print(f"\n[+] Rapport généré → {out_path}")

    import pathlib, subprocess
    abs_path = str(pathlib.Path(out_path).resolve())
    try:
        win_path = subprocess.check_output(["wslpath", "-w", abs_path]).decode().strip()
        subprocess.Popen(["cmd.exe", "/c", "start", "", win_path])
    except Exception:
        import webbrowser
        webbrowser.open(pathlib.Path(abs_path).as_uri())


if __name__ == "__main__":
    main()
