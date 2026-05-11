"""Groq-based SOC narrative synthesizer (free tier)."""

import os
from src.models import EnrichmentResult

_SYSTEM_MALICIOUS = """Tu es un analyste SOC sénior spécialisé en threat intelligence. \
Tu reçois des données structurées sur un IOC (IP, domaine, ou hash) extraites de AbuseIPDB, VirusTotal et urlscan.io. \
Le score de menace global de cet IOC est supérieur à 0 : il présente des indicateurs malveillants.

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

_SYSTEM_LEGITIMATE = """Tu es un analyste SOC sénior spécialisé en threat intelligence. \
Tu reçois des données structurées sur un IOC (IP, domaine, ou hash) extraites de AbuseIPDB, VirusTotal et urlscan.io. \
Le score de menace global de cet IOC est de 0 : aucun indicateur de compromission n'a été détecté.

Rédige un paragraphe factuel en français (3 à 5 phrases) décrivant l'IOC. \
NE FOURNIS AUCUNE RECOMMANDATION — uniquement une description technique neutre.

Tu DOIS inclure dans ta description, si les données sont disponibles :
- L'appartenance réseau : organisation, ASN, pays, bloc CIDR, registre Internet (RIPE/ARIN/etc.)
- L'usage connu : hébergement, cloud, CDN, FAI résidentiel, infrastructure d'entreprise, etc.
- Confirmer explicitement l'absence de détections ou de signalements significatifs dans les sources consultées
- Le score AbuseIPDB (0%) et le ratio VirusTotal (0 détection sur N moteurs)

NE mentionne PAS : fichiers associés, patterns d'attaque, règles IDS/IPS, acteurs de menace, CVE, \
contextes communautaires malveillants. Ces sections ne sont pas pertinentes pour un IOC légitime.

Style : factuel, précis, vocabulaire SOC standard. Un seul paragraphe fluide, pas de listes ni de titres."""


def _format_context(results: list[EnrichmentResult], is_malicious: bool) -> str:
    ioc = results[0].ioc
    lines = [f"IOC : {ioc.value}  (type : {ioc.type})", ""]

    # Fields to exclude for legitimate IOCs (not relevant, avoids confusing the LLM)
    _LEGITIMATE_EXCLUDE = {
        "crowdsourced_context", "ids_rules", "communicating_files",
        "malicious_vendors", "threat_labels", "abuse_categories",
    }

    for r in results:
        lines.append(f"=== {r.source} ===")
        if r.error:
            lines.append(f"Erreur : {r.error}")
            lines.append("")
            continue

        for k, v in r.data.items():
            if v is None or v == "" or v == [] or v == {}:
                continue
            if not is_malicious and k in _LEGITIMATE_EXCLUDE:
                continue

            if isinstance(v, list) and v and isinstance(v[0], dict):
                lines.append(f"{k} :")
                for item in v:
                    parts = [f"{ik}={iv}" for ik, iv in item.items() if iv]
                    lines.append("  - " + " | ".join(parts))
            elif isinstance(v, list):
                lines.append(f"{k} : {', '.join(str(x) for x in v)}")
            elif isinstance(v, dict):
                lines.append(f"{k} : {v}")
            else:
                lines.append(f"{k} : {v}")

        lines.append("")

    return "\n".join(lines)


def synthesize(results: list[EnrichmentResult], threat_score: int = 0) -> str | None:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return None
    try:
        from groq import Groq
        is_malicious = threat_score > 0
        system_prompt = _SYSTEM_MALICIOUS if is_malicious else _SYSTEM_LEGITIMATE
        context = _format_context(results, is_malicious)

        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Décris cet IOC :\n\n{context}"},
            ],
            temperature=0.2,
            max_tokens=550,
        )
        return response.choices[0].message.content.strip()
    except Exception as exc:
        print(f"    [!] Groq synthesis error : {exc}")
        return None
