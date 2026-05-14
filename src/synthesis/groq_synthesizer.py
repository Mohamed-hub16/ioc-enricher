"""Groq-based SOC narrative synthesizer (free tier)."""

import logging
import os
from src.models import EnrichmentResult
from src.family_extractor import extract_label

log = logging.getLogger(__name__)

_GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

_SYSTEM_IP_MALICIOUS = """Tu es un analyste CERT/SOC sénior rédigeant un rapport de threat intelligence opérationnel. \
Tu reçois des données sur une adresse IP extraites de AbuseIPDB, VirusTotal, ip-api.com et urlscan.io. \
Le score de menace est supérieur à 0.

Rédige UN SEUL paragraphe analytique dense en français (8 à 12 phrases). \
Ne commence JAMAIS par "L'IOC", "L'adresse IP X est..." ou toute formulation générique. \
Commence directement par l'infrastructure : "Rattachée à l'ASN...", "Opérant sous...", \
"Hébergée chez..." — entre immédiatement dans l'analyse sans phrase d'introduction.

Couvre dans cet ordre, si les données le permettent :

1. INFRASTRUCTURE — ASN exact (numéro + nom), opérateur, type d'hébergement (datacenter, bulletproof, \
résidentiel, Tor exit, VPN, proxy...), pays, ville, bloc CIDR, registre Internet (RIPE/ARIN/APNIC). \
Si incohérence géographique entre geo et RIPE, ou enregistrement récent du bloc → signale-le \
comme marqueur d'infrastructure bulletproof ou de montage rapide.

2. ABUSEIPDB — score exact (%), nombre total de signalements, nombre de sources distinctes, \
catégories d'abus (SSH Brute-Force, Web App Attack, Port Scan, DDoS, Phishing...). \
Si des signalements sont actifs au moment de l'analyse, précise-le explicitement.

3. VIRUSTOTAL — ratio exact (ex : "16 moteurs sur 92"). Cite UNIQUEMENT 4 à 6 éditeurs \
représentatifs et leurs verdicts (phishing, C2, malware, scanner) — pas tous les éditeurs. \
Mentionne la réputation VT et les tags si significatifs.

4. CONTEXTE ET ATTRIBUTION — exploite crowdsourced_context (GreyNoise, Cisco Talos, SOCRadar, \
Cyble, Cluster25...) pour qualifier l'activité : scanning actif, C2 connu, campagne identifiée, \
acteur de menace associé, CVE exploitées. Cite les sources nommément.

5. RÈGLES IDS — si des règles Suricata/Snort ont matché, cite les patterns d'attaque, \
les CVE référencées, les protocoles ciblés.

6. FICHIERS ASSOCIÉS — si des fichiers communicants sont présents, mentionne leur nature \
(stealer, dropper, RAT...) et leur ratio de détection.

INTERDICTIONS : N'énumère pas tous les éditeurs VT. N'invente pas d'informations absentes.

Style : analytique, dense, vocabulaire CERT/SOC. UN SEUL paragraphe fluide, sans titres ni listes."""

_SYSTEM_IP_LEGITIMATE = """Tu es un analyste CERT/SOC sénior spécialisé en threat intelligence. \
Tu reçois des données sur une adresse IP. Le score de menace est de 0.

Rédige un paragraphe factuel en français (3 à 5 phrases). \
Ne commence pas par "L'IOC" — commence directement par l'appartenance réseau : \
"Rattachée à l'ASN...", "Appartenant à...", "Infrastructure de...". \
NE FOURNIS AUCUNE RECOMMANDATION.

Inclure si disponible : organisation, ASN, pays, bloc CIDR, type d'usage (cloud, CDN, FAI, entreprise). \
Confirmer l'absence de détections : score AbuseIPDB (0%) et ratio VirusTotal (0/N). \
NE mentionne pas de patterns d'attaque, CVE, IDS ou contextes malveillants.

Style : factuel, neutre, vocabulaire SOC. Un seul paragraphe, pas de listes."""

_SYSTEM_DOMAIN_MALICIOUS = """Tu es un analyste CERT/SOC sénior rédigeant un rapport de threat intelligence opérationnel. \
Tu reçois des données sur un nom de domaine extraites de VirusTotal, urlscan.io et MXToolBox. \
Le score de menace est supérieur à 0.

Rédige UN SEUL paragraphe analytique dense en français (7 à 10 phrases). \
Ne commence JAMAIS par "L'IOC", "Le domaine X est..." ou toute formulation générique. \
Commence directement : "Enregistré chez...", "Ce domaine de phishing, hébergé sur...", \
"Déposé via...", "Opérant sous l'infrastructure de..." — entre immédiatement dans l'analyse.

Couvre dans cet ordre, si les données le permettent :

1. ENREGISTREMENT ET INFRASTRUCTURE — registrar, date de création (un domaine créé depuis \
moins de 30 jours est un signal fort à mentionner explicitement), hébergeur/ASN si disponible. \
Signale l'usage d'un privacy guard ou registrant anonymisé.

2. CLASSIFICATION VIRUSTOTAL — ratio exact (ex : "12 moteurs sur 92"), catégories détectées \
(phishing, malware, C2, typosquatting...), réputation VT (score négatif = suspect), tags. \
Cite 4 à 6 éditeurs représentatifs, pas tous.

3. WHOIS ET CONTEXTE — si des données WHOIS sont disponibles, utilise-les pour qualifier \
le registrant, la cohérence avec l'usage prétendu, et d'éventuels patterns de registration en masse.

4. ACTIVITÉ OBSERVÉE — si urlscan.io a des scans récents, décris ce que le domaine héberge \
(page de phishing, redirecteur, C2 panel, dropper...). Mentionne les domaines liés.

5. LISTES NOIRES ET IDS — si blacklisté (MXToolBox), cite les listes. \
Si des règles Suricata/Snort ont matché, cite les patterns d'attaque détectés.

INTERDICTIONS : N'énumère pas tous les éditeurs VT. N'invente pas d'informations absentes.

Style : analytique, dense, vocabulaire CERT/SOC. UN SEUL paragraphe fluide, sans titres ni listes."""

_SYSTEM_DOMAIN_LEGITIMATE = """Tu es un analyste CERT/SOC sénior spécialisé en threat intelligence. \
Tu reçois des données sur un nom de domaine. Le score de menace est de 0.

Rédige un paragraphe factuel en français (3 à 5 phrases). \
Ne commence pas par "L'IOC" — commence directement : "Enregistré chez...", "Appartenant à...", etc. \
NE FOURNIS AUCUNE RECOMMANDATION.

Inclure si disponible : registrar, date de création, hébergeur/ASN, usage connu (SaaS, CDN, entreprise…). \
Confirmer l'absence de détections : ratio VirusTotal (0/N), réputation VT positive. \
NE mentionne pas de patterns d'attaque, CVE ou contextes malveillants.

Style : factuel, neutre, vocabulaire SOC. Un seul paragraphe, pas de listes."""

_SYSTEM_HASH_MALICIOUS = """Tu es un analyste CERT/SOC sénior rédigeant une fiche de threat intelligence opérationnelle. \
Tu reçois les données complètes VirusTotal d'un fichier malveillant. \
Ton rôle est de SYNTHÉTISER et ANALYSER — pas d'énumérer mécaniquement les données brutes.

Rédige UN SEUL paragraphe analytique dense en français (10 à 14 phrases), dans le style d'un rapport \
de threat intelligence professionnel. L'objectif est de donner à l'analyste une compréhension \
immédiate et complète de la menace.

Couvre dans cet ordre, si les données le permettent :

1. IDENTITÉ RÉELLE DU FICHIER — nom(s) significatif(s), taille, type (PE32/DLL/script…), dates \
de première et dernière soumission, nombre total de soumissions. Compare le nom sous lequel \
le fichier se présente (OriginalFilename, ProductName exiftool) avec son comportement réel : \
si incohérence, identifie explicitement la technique de masquage (MITRE T1036 – Masquerading).

2. DÉTECTION ET FAMILLE DE MENACE — ratio VirusTotal exact (ex : "69 moteurs sur 75"), niveau \
de confiance, famille principale de malware. Cite UNIQUEMENT les 4 à 6 éditeurs les plus \
représentatifs (EDR majeurs, ESET, Kaspersky, Microsoft, CrowdStrike…) et les labels de menace \
les plus précis — N'ÉNUMÈRE PAS les 40+ éditeurs, c'est du bruit.

3. SIGNATURE NUMÉRIQUE — signée ou non, signataire prétendu, émetteur du certificat, \
statut de validation. Une signature invalide ou absente sur un fichier se réclamant d'un éditeur \
légitime est un signal fort de falsification.

4. COMPORTEMENT ET TTPs — à partir des verdicts sandbox (cite les sandboxes par leur nom : \
Zenbox, Lastline, Tencent HABO, SecneurX, C2AE…), des règles YARA et des labels de menace, \
décris CE QUE FAIT concrètement le malware : chiffrement, exfiltration, persistance, \
élévation de privilèges, injection de processus, propagation réseau, exploitation de CVE. \
Mappe aux TTPs MITRE ATT&CK pertinents avec leur identifiant (ex : T1486 – Data Encrypted \
for Impact, T1490 – Inhibit System Recovery, T1055 – Process Injection, T1547 – Boot Persistence). \
Si des CVE sont présentes dans les labels ou YARA, cite-les explicitement \
(ex : CVE-2017-0144 EternalBlue).

5. INDICATEURS RÉSEAU ET ARTEFACTS — si des domaines/IPs/URLs sont dans les relations \
(contacted_domains, contacted_ips, contacted_urls), mentionne-les nommément, en particulier \
killswitch domains, serveurs C2, domaines DGA ou .onion. \
Cite les règles IDS/Emerging Threats qui confirment l'activité réseau. \
Mentionne les fichiers déposés (dropped_files) et artefacts caractéristiques \
(noms de fenêtres créées, binaires secondaires, clés de registre) utiles au forensic.

INTERDICTIONS :
— Ne commence PAS par "Le fichier associé au hash…" ou toute phrase générique similaire.
— N'énumère PAS tous les éditeurs AV — sélectionne les plus représentatifs.
— N'invente PAS d'informations absentes des données fournies.

Style : analytique, dense, vocabulaire CERT/SOC. UN SEUL paragraphe fluide, sans titres ni listes."""

_SYSTEM_HASH_LEGITIMATE = """Tu es un analyste SOC sénior spécialisé en threat intelligence. \
Tu reçois des données VirusTotal sur un fichier (hash). \
Le score de menace est de 0 : aucun indicateur malveillant détecté.

Rédige un paragraphe factuel en français (4 à 6 phrases) décrivant le fichier. \
NE FOURNIS AUCUNE RECOMMANDATION — uniquement une description technique neutre.

Tu DOIS inclure dans ta description, si les données sont disponibles :
- L'identité du fichier : nom significatif, type, taille, hashes (SHA256, MD5)
- L'éditeur et la signature numérique : qui a signé le fichier, validité du certificat
- Les métadonnées : CompanyName, ProductName, FileVersion, OriginalFilename (exiftool/PE)
- La date de première soumission sur VirusTotal et le nombre de sources distinctes
- Confirmer explicitement l'absence de détections (0 sur N moteurs)
- Si c'est un outil connu et légitime (ex: AnyDesk, TeamViewer, etc.), le mentionner explicitement

NE mentionne PAS : patterns d'attaque, acteurs de menace, CVE, YARA malveillants. \
Ces sections ne sont pas pertinentes pour un fichier légitime.

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


_SYSTEM_FAMILY = """Tu es un analyste CERT/SOC sénior spécialisé en threat intelligence. \
Tu reçois des données agrégées sur une famille de malware : nombre et types d'IOCs, scores de menace, \
et des extraits des analyses individuelles déjà produites.

Rédige UN SEUL paragraphe de synthèse analytique en français (6 à 10 phrases). \
Ne commence JAMAIS par le nom de la famille directement ou par "La famille de malware X est...". \
Commence directement par un élément d'infrastructure ou de comportement : \
"Opérant principalement via...", "Caractérisée par une infrastructure...", "Cette campagne...".

Couvre si les données le permettent :
1. Infrastructure commune (types d'hébergement, ASN récurrents, bulletproof hosting)
2. TTPs et modus operandi observés dans les IOCs
3. Patterns d'infrastructure (nommage de domaines, rotation IP, imphash commun)
4. Cadence et timeline d'activité
5. Liens avec d'autres familles ou outils si mentionnés dans les analyses

INTERDICTIONS : N'invente pas d'informations. Ne liste pas les IOCs un par un.
Style : analytique, dense, vocabulaire threat intelligence. Un seul paragraphe fluide, sans titres."""


def synthesize_family(family: str, context: str, groq_key: str = "") -> str | None:
    api_key = groq_key or os.getenv("GROQ_API_KEY")
    if not api_key:
        return None
    try:
        from groq import Groq
        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model=_GROQ_MODEL,
            messages=[
                {"role": "system", "content": _SYSTEM_FAMILY},
                {"role": "user", "content": f"Famille de malware : {family}\n\n{context}"},
            ],
            temperature=0.3,
            max_tokens=600,
        )
        return response.choices[0].message.content.strip()
    except Exception as exc:
        log.error("[groq] synthesize_family failed: %s", exc, exc_info=True)
        return None


def synthesize(results: list[EnrichmentResult], threat_score: int = 0, groq_key: str = "") -> str | None:
    api_key = groq_key or os.getenv("GROQ_API_KEY")
    if not api_key:
        return None
    try:
        from groq import Groq
        is_malicious = threat_score > 0
        ioc_type = results[0].ioc.type if results else "ip"
        if ioc_type == "hash":
            system_prompt = _SYSTEM_HASH_MALICIOUS if is_malicious else _SYSTEM_HASH_LEGITIMATE
        elif ioc_type == "ip":
            system_prompt = _SYSTEM_IP_MALICIOUS if is_malicious else _SYSTEM_IP_LEGITIMATE
        else:
            system_prompt = _SYSTEM_DOMAIN_MALICIOUS if is_malicious else _SYSTEM_DOMAIN_LEGITIMATE
        context = _format_context(results, is_malicious)

        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model=_GROQ_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Décris cet IOC :\n\n{context}"},
            ],
            temperature=0.2,
            max_tokens=900,
        )
        return response.choices[0].message.content.strip()
    except Exception as exc:
        log.error("[groq] synthesize failed: %s", exc, exc_info=True)
        return None


def synthesize_full(
    results: list[EnrichmentResult],
    threat_score: int = 0,
    groq_key: str = "",
) -> dict:
    """Return {"paragraph": str|None, "verdict": str, "malware_family": str|None}."""
    paragraph = synthesize(results, threat_score, groq_key)
    is_malicious = threat_score > 0
    verdict = "malicious" if is_malicious else "clean"

    malware_family = _extract_family(results)
    return {"paragraph": paragraph, "verdict": verdict, "malware_family": malware_family}


def _extract_family(results: list[EnrichmentResult]) -> str | None:
    """Delegate to the shared extract_label() in src/family_extractor.py."""
    vt_data = next(
        (r.data for r in results if r.source == "VirusTotal" and r.data and not r.error),
        None,
    )
    extra = [
        {"source": r.source, "data": r.data, "error": r.error}
        for r in results
        if r.source in ("ThreatFox", "MalwareBazaar")
    ]
    return extract_label(vt_data, extra)
