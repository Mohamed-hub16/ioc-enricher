"""Groq-based SOC narrative synthesizer (free tier)."""

import os
from src.models import EnrichmentResult

_SYSTEM = """Tu es un analyste SOC sénior spécialisé en threat intelligence. \
Tu reçois des données structurées sur un IOC (IP, domaine, ou hash) extraites de AbuseIPDB, VirusTotal et urlscan.io.

Rédige un paragraphe de description factuelle en français (5 à 7 phrases). \
NE FOURNIS AUCUNE RECOMMANDATION — uniquement une description technique de l'IOC.

Tu DOIS inclure dans ta description, si les données sont disponibles :
- La nature précise de l'indicateur (nœud Tor, proxy, serveur C2, domaine de phishing, fichier malveillant, etc.) \
avec ses attributs réseau : organisation opératrice, ASN, pays, bloc CIDR, registre Internet (RIPE/ARIN/etc.)
- Les chiffres exacts : score AbuseIPDB (%), nombre total de signalements, nombre de sources distinctes
- Les catégories de comportement malveillant observées (SSH, Brute-Force, Web App Attack, DDoS, etc.)
- Le ratio VirusTotal exact (ex : "17 moteurs sur 92") en citant nommément les éditeurs de sécurité \
qui ont détecté l'IOC et les labels de menace retournés
- Les contextes communautaires (crowdsourced_context) : cite les sources (Cisco Talos, MalBeacon, etc.), \
les CVE référencées (Log4Shell, Spring4Shell, etc.), les familles de malware, les acteurs de menace mentionnés
- Les règles IDS/IPS qui ont matché (Suricata, Snort) : cite les noms de règles et patterns d'attaque détectés
- Les fichiers malveillants associés à l'IP (stealers, droppers, etc.) avec leur ratio de détection

Style : factuel, précis, vocabulaire SOC standard. Un seul paragraphe fluide, pas de listes ni de titres."""


def _format_context(results: list[EnrichmentResult]) -> str:
    ioc = results[0].ioc
    lines = [f"IOC : {ioc.value}  (type : {ioc.type})", ""]

    for r in results:
        lines.append(f"=== {r.source} ===")
        if r.error:
            lines.append(f"Erreur : {r.error}")
            lines.append("")
            continue

        for k, v in r.data.items():
            if v is None or v == "" or v == [] or v == {}:
                continue

            # Lists of dicts (crowdsourced_context, ids_rules, communicating_files)
            if isinstance(v, list) and v and isinstance(v[0], dict):
                lines.append(f"{k} :")
                for item in v:
                    parts = [f"{ik}={iv}" for ik, iv in item.items() if iv]
                    lines.append("  - " + " | ".join(parts))

            # Plain lists (vendors, labels, categories, tags)
            elif isinstance(v, list):
                lines.append(f"{k} : {', '.join(str(x) for x in v)}")

            # Dicts (vt categories)
            elif isinstance(v, dict):
                lines.append(f"{k} : {v}")

            else:
                lines.append(f"{k} : {v}")

        lines.append("")

    return "\n".join(lines)


def synthesize(results: list[EnrichmentResult]) -> str | None:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return None
    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": _SYSTEM},
                {"role": "user", "content": f"Décris cet IOC :\n\n{_format_context(results)}"},
            ],
            temperature=0.2,
            max_tokens=550,
        )
        return response.choices[0].message.content.strip()
    except Exception as exc:
        print(f"    [!] Groq synthesis error : {exc}")
        return None
