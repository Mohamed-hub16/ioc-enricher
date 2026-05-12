"""Groq-based SOC narrative + structured output synthesizer.

Two entry points :
  - `synthesize(results, threat_score)` : retourne juste le paragraphe (texte FR).
    Rétro-compatible avec le CLI.
  - `synthesize_full(results, threat_score)` : retourne le paragraphe **et** un
    dict structuré { verdict, malware_family, ttps, confidence, ... }
    via le JSON mode de Groq (`response_format={"type": "json_object"}`).
"""

import json
import os
from src.models import EnrichmentResult

_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# ─────────────────────────────────────────────────────────────────────────────
# System prompts — paragraphe SOC (legacy, conservés)
# ─────────────────────────────────────────────────────────────────────────────

_SYSTEM_IP_MALICIOUS = """Tu es un analyste CERT/SOC sénior rédigeant un rapport de threat intelligence opérationnel. \
Tu reçois des données sur une adresse IP extraites de AbuseIPDB, VirusTotal, ip-api.com, urlscan.io, \
Shodan InternetDB, GreyNoise, URLhaus et ThreatFox. Le score de menace est supérieur à 0.

Rédige UN SEUL paragraphe analytique dense en français (8 à 12 phrases). \
Ne commence JAMAIS par "L'IOC", "L'adresse IP X est..." ou toute formulation générique. \
Commence directement par l'infrastructure : "Rattachée à l'ASN...", "Opérant sous...", \
"Hébergée chez..." — entre immédiatement dans l'analyse sans phrase d'introduction.

Couvre dans cet ordre, si les données le permettent :

1. INFRASTRUCTURE — ASN exact (numéro + nom), opérateur, type d'hébergement (datacenter, bulletproof, \
résidentiel, Tor exit, VPN, proxy...), pays, ville, bloc CIDR, registre Internet (RIPE/ARIN/APNIC). \
Si Shodan InternetDB révèle des ports/CVE notables, mentionne-les (ex : SMB exposé + CVE-2017-0144). \
Si GreyNoise classe l'IP en "noise" → indique qu'il s'agit d'un scanner Internet de masse ; \
si GreyNoise indique "RIOT" → service légitime connu (anomalie).

2. ABUSEIPDB — score exact (%), nombre total de signalements, nombre de sources distinctes, \
catégories d'abus (SSH Brute-Force, Web App Attack, Port Scan, DDoS, Phishing...). \
Si des signalements sont actifs au moment de l'analyse, précise-le explicitement.

3. VIRUSTOTAL — ratio exact (ex : "16 moteurs sur 92"). Cite UNIQUEMENT 4 à 6 éditeurs \
représentatifs et leurs verdicts (phishing, C2, malware, scanner) — pas tous les éditeurs. \
Mentionne la réputation VT et les tags si significatifs.

4. THREATFOX / URLhaus — si présents, cite la famille de malware (ex: "tagué Cobalt Strike"), \
le nombre d'URLs malveillantes en ligne, et les tags de campagne.

5. CONTEXTE ET ATTRIBUTION — exploite crowdsourced_context (GreyNoise, Cisco Talos, SOCRadar, \
Cyble, Cluster25...) pour qualifier l'activité : scanning actif, C2 connu, campagne identifiée, \
acteur de menace associé, CVE exploitées. Cite les sources nommément.

6. RÈGLES IDS — si des règles Suricata/Snort ont matché, cite les patterns d'attaque, \
les CVE référencées, les protocoles ciblés.

7. FICHIERS ASSOCIÉS — si des fichiers communicants sont présents, mentionne leur nature \
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
Si GreyNoise renvoie un statut RIOT (service légitime connu) ou la classification "benign", \
mentionne-le. Confirmer l'absence de détections : score AbuseIPDB (0%) et ratio VirusTotal (0/N). \
NE mentionne pas de patterns d'attaque, CVE, IDS ou contextes malveillants.

Style : factuel, neutre, vocabulaire SOC. Un seul paragraphe, pas de listes."""

_SYSTEM_DOMAIN_MALICIOUS = """Tu es un analyste CERT/SOC sénior rédigeant un rapport de threat intelligence opérationnel. \
Tu reçois des données sur un nom de domaine extraites de VirusTotal, urlscan.io, URLhaus et ThreatFox. \
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

3. URLHAUS / THREATFOX — si présents : nombre d'URLs malveillantes (online vs offline), \
famille de malware distribuée (ex: "distribue Emotet depuis 2024-10"), tags de campagne, \
références d'attribution.

4. WHOIS ET CONTEXTE — si des données WHOIS sont disponibles, utilise-les pour qualifier \
le registrant, la cohérence avec l'usage prétendu, et d'éventuels patterns de registration en masse.

5. ACTIVITÉ OBSERVÉE — si urlscan.io a des scans récents, décris ce que le domaine héberge \
(page de phishing, redirecteur, C2 panel, dropper...). Mentionne les domaines liés.

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
Tu reçois les données complètes VirusTotal + MalwareBazaar + ThreatFox d'un fichier malveillant. \
Ton rôle est de SYNTHÉTISER et ANALYSER — pas d'énumérer mécaniquement les données brutes.

Rédige UN SEUL paragraphe analytique dense en français (10 à 14 phrases), dans le style d'un rapport \
de threat intelligence professionnel. L'objectif est de donner à l'analyste une compréhension \
immédiate et complète de la menace.

Couvre dans cet ordre, si les données le permettent :

1. IDENTITÉ RÉELLE DU FICHIER — nom(s) significatif(s), taille, type (PE32/DLL/script…), dates \
de première et dernière soumission, nombre total de soumissions. Compare le nom sous lequel \
le fichier se présente (OriginalFilename, ProductName exiftool) avec son comportement réel : \
si incohérence, identifie explicitement la technique de masquage (MITRE T1036 – Masquerading).

2. FAMILLE DE MENACE — si MalwareBazaar ou ThreatFox renvoient une signature (ex: "Lockbit", \
"Emotet", "Cobalt Strike"), mentionne-la explicitement en premier. Sinon dériver de la \
popular_threat_label VT. Ratio VirusTotal exact (ex : "69 moteurs sur 75"). \
Cite UNIQUEMENT les 4 à 6 éditeurs les plus représentatifs (EDR majeurs, ESET, Kaspersky, \
Microsoft, CrowdStrike…) et les labels de menace les plus précis — \
N'ÉNUMÈRE PAS les 40+ éditeurs, c'est du bruit.

3. SIGNATURE NUMÉRIQUE — signée ou non, signataire prétendu, émetteur du certificat, \
statut de validation. Une signature invalide ou absente sur un fichier se réclamant d'un éditeur \
légitime est un signal fort de falsification.

4. COMPORTEMENT ET TTPs — à partir des verdicts sandbox (cite les sandboxes par leur nom : \
Triage, Zenbox, Lastline, Tencent HABO, SecneurX, C2AE…), des règles YARA et des labels de menace, \
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


# ─────────────────────────────────────────────────────────────────────────────
# System prompt — JSON structuré (mode strict)
# ─────────────────────────────────────────────────────────────────────────────

_SYSTEM_STRUCTURED = """Tu es un analyste CERT/SOC qui produit UNIQUEMENT du JSON valide.

Schéma OBLIGATOIRE (toutes les clés doivent être présentes, tableaux vides autorisés) :

{
  "verdict":          "malicious" | "suspicious" | "legitimate" | "inconclusive",
  "malware_family":   "string ou null — ex: 'Lockbit 3.0', 'Emotet', 'Cobalt Strike'",
  "campaign_or_actor": "string ou null — ex: 'APT28', 'campagne Lazarus oct-2025'",
  "ttps": [
    {"technique_id": "T1486", "name": "Data Encrypted for Impact"}
  ],
  "iocs_observed": [
    {"type": "ip|domain|hash|url", "value": "...", "context": "C2 server | dropper | etc"}
  ],
  "key_observations": ["string", "string", ...],
  "recommended_actions": ["string", "string", ...],
  "confidence": 0.0
}

CONSIGNES :
- `verdict` reflète l'analyse globale (pas juste le score numérique).
- `malware_family` : nom canonique de famille SEULEMENT si attesté par VT/MalwareBazaar/ThreatFox/YARA.
  Sinon null. Pas d'attribution conjecturale.
- `campaign_or_actor` : SEULEMENT si attesté nommément dans crowdsourced_context / threatfox_tags. Sinon null.
- `ttps` : entre 0 et 12 entrées, identifiants ATT&CK valides (Txxxx ou Txxxx.yyy). Inclure les
  techniques implicites (ex: malware ransomware → T1486 même si pas explicite).
- `iocs_observed` : extraire les IPs/domaines/hashes/URLs présents dans `contacted_*`,
  `dropped_files`, `relationships`. Max 10 entrées.
- `key_observations` : 3-6 bullets factuels, en français, max 25 mots chacun.
- `recommended_actions` : 2-5 actions concrètes (block_ip, hunt_imphash_in_edr, etc), en français.
- `confidence` : 0.0–1.0. 0.95+ si famille attestée par sandbox + AV consensus. <0.5 si peu de données.

Réponds UNIQUEMENT par le JSON, sans markdown ni commentaire."""


# ─────────────────────────────────────────────────────────────────────────────
# Context builder (shared)
# ─────────────────────────────────────────────────────────────────────────────

_LEGITIMATE_EXCLUDE = {
    "crowdsourced_context", "ids_rules", "communicating_files",
    "malicious_vendors", "threat_labels", "abuse_categories",
}


def _format_context(results: list[EnrichmentResult], is_malicious: bool) -> str:
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


def _pick_paragraph_prompt(ioc_type: str, is_malicious: bool) -> str:
    if ioc_type == "hash":
        return _SYSTEM_HASH_MALICIOUS if is_malicious else _SYSTEM_HASH_LEGITIMATE
    if ioc_type == "ip":
        return _SYSTEM_IP_MALICIOUS if is_malicious else _SYSTEM_IP_LEGITIMATE
    return _SYSTEM_DOMAIN_MALICIOUS if is_malicious else _SYSTEM_DOMAIN_LEGITIMATE


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def synthesize(results: list[EnrichmentResult], threat_score: int = 0,
               groq_key: str = "") -> str | None:
    """Renvoie un paragraphe d'analyse SOC en français (texte). None si Groq KO."""
    api_key = groq_key or os.getenv("GROQ_API_KEY")
    if not api_key:
        return None
    try:
        from groq import Groq

        is_malicious = threat_score > 0
        ioc_type = results[0].ioc.type if results else "ip"
        system_prompt = _pick_paragraph_prompt(ioc_type, is_malicious)
        context = _format_context(results, is_malicious)

        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model=_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Décris cet IOC :\n\n{context}"},
            ],
            temperature=0.2,
            max_tokens=900,
        )
        return response.choices[0].message.content.strip()
    except Exception as exc:
        print(f"    [!] Groq synthesis error : {exc}")
        return None


def synthesize_structured(results: list[EnrichmentResult], threat_score: int = 0,
                          groq_key: str = "") -> dict | None:
    """Renvoie un dict structuré conforme au schéma (verdict/family/ttps/...).
    None si Groq KO ou JSON invalide."""
    api_key = groq_key or os.getenv("GROQ_API_KEY")
    if not api_key:
        return None
    try:
        from groq import Groq

        is_malicious = threat_score > 0
        context = _format_context(results, is_malicious=True)  # toujours full context pour le JSON

        client = Groq(api_key=api_key)
        response = client.chat.completions.create(
            model=_MODEL,
            messages=[
                {"role": "system", "content": _SYSTEM_STRUCTURED},
                {"role": "user", "content":
                    f"Score numérique calculé : {threat_score}/100. Analyse cet IOC :\n\n{context}"},
            ],
            temperature=0.1,
            max_tokens=1500,
            response_format={"type": "json_object"},
        )
        raw = response.choices[0].message.content.strip()
        parsed = json.loads(raw)
        return _validate_structured(parsed)
    except Exception as exc:
        print(f"    [!] Groq structured synthesis error : {exc}")
        return None


def synthesize_full(results: list[EnrichmentResult], threat_score: int = 0,
                    groq_key: str = "") -> tuple[str | None, dict | None]:
    """Combine paragraphe + JSON structuré (2 appels Groq).
    Renvoie (paragraphe, structured) — l'un peut être None si erreur."""
    paragraph = synthesize(results, threat_score, groq_key)
    structured = synthesize_structured(results, threat_score, groq_key)
    return paragraph, structured


# ─────────────────────────────────────────────────────────────────────────────
# Validators
# ─────────────────────────────────────────────────────────────────────────────

_VALID_VERDICTS = {"malicious", "suspicious", "legitimate", "inconclusive"}


def _validate_structured(d: dict) -> dict:
    """Normalise et clamp les champs ; ignore les extras."""
    if not isinstance(d, dict):
        return None  # type: ignore[return-value]

    verdict = (d.get("verdict") or "").lower()
    if verdict not in _VALID_VERDICTS:
        verdict = "inconclusive"

    ttps_raw = d.get("ttps") or []
    ttps: list[dict] = []
    if isinstance(ttps_raw, list):
        for t in ttps_raw[:12]:
            if isinstance(t, dict):
                tid = (t.get("technique_id") or "").upper().strip()
                if tid.startswith("T") and tid[1:].replace(".", "").isdigit():
                    ttps.append({"technique_id": tid, "name": (t.get("name") or "").strip()})
            elif isinstance(t, str):
                tid = t.upper().strip()
                if tid.startswith("T") and tid[1:].replace(".", "").isdigit():
                    ttps.append({"technique_id": tid, "name": ""})

    confidence = d.get("confidence")
    try:
        confidence = max(0.0, min(1.0, float(confidence)))
    except (TypeError, ValueError):
        confidence = None

    return {
        "verdict": verdict,
        "malware_family": (d.get("malware_family") or "").strip() or None,
        "campaign_or_actor": (d.get("campaign_or_actor") or "").strip() or None,
        "ttps": ttps,
        "iocs_observed": (d.get("iocs_observed") or [])[:10],
        "key_observations": [str(x).strip() for x in (d.get("key_observations") or [])[:6] if str(x).strip()],
        "recommended_actions": [str(x).strip() for x in (d.get("recommended_actions") or [])[:5] if str(x).strip()],
        "confidence": confidence,
    }
