# IOC Enricher

Outil de threat intelligence pour analystes SOC. Enrichit des IPs, domaines et hashes en interrogeant des APIs gratuites, génère un paragraphe d'analyse rédigé par IA, et stocke tout dans une interface web consultable par l'équipe.

---

## Fonctionnalités

- **Enrichissement multi-sources** — AbuseIPDB, VirusTotal, urlscan.io
- **Synthèse IA** — paragraphe SOC en français généré par Groq (llama-3.3-70b)
- **Interface web** — historique des IOCs, recherche, re-enrichissement
- **Cache intelligent** — résultats stockés en SQLite ; IOCs de moins de 7 jours servis instantanément
- **Accès équipe** — lecture publique, enrichissement réservé aux comptes approuvés
- **Panneau d'administration** — approbation et révocation des comptes analystes
- **Mode CLI** — fonctionne aussi en script autonome pour un usage rapide

---

## Sources supportées

| Source | Types d'IOC | Free tier |
|---|---|---|
| AbuseIPDB | IP | 1 000 req / jour |
| VirusTotal | IP, domaine, hash | 500 req / jour |
| urlscan.io | Domaine | 1 000 req / jour |
| Groq | Tous (synthèse IA) | Free tier disponible |

---

## Structure du projet

```
app.py                  # Point d'entrée Flask (interface web)
main.py                 # Point d'entrée CLI
webapp/
  __init__.py           # Factory Flask
  models.py             # Modèles SQLAlchemy (User, IOCRecord)
  auth.py               # /login  /register  /logout
  ioc_routes.py         # /  /ioc/<valeur>  /enrich
  admin_routes.py       # /admin/users  approve  revoke
  templates/            # Templates Bootstrap 5 dark theme
src/
  enrichers/            # Un module par API (abuseipdb, virustotal, urlscan)
  parsers/              # Détection du type d'IOC (IP / domaine / hash)
  synthesis/            # Générateur de paragraphe IA via Groq
  models.py             # Dataclasses partagés (IOC, EnrichmentResult)
instance/               # Base de données SQLite (ignorée par git)
output/                 # Rapports HTML générés par le CLI (ignorés par git)
```

---

## Installation

### 1. Cloner et installer les dépendances

```bash
git clone https://github.com/Mohamed-hub16/ioc-enricher.git
cd ioc-enricher
pip install -r requirements.txt
```

### 2. Configurer les variables d'environnement

```bash
cp .env.example .env
```

Remplir `.env` avec vos clés :

```env
ABUSEIPDB_API_KEY=votre_clé
VIRUSTOTAL_API_KEY=votre_clé
URLSCAN_API_KEY=votre_clé
GROQ_API_KEY=votre_clé

SECRET_KEY=votre_clé_flask   # python -c "import secrets; print(secrets.token_hex(32))"
ADMIN_EMAIL=votre@email.com  # ce compte obtient automatiquement les droits admin à l'inscription
```

### 3. Obtenir les clés API (toutes gratuites)

| Service | Lien |
|---|---|
| AbuseIPDB | https://www.abuseipdb.com/account/api |
| VirusTotal | https://www.virustotal.com/gui/my-apikey |
| urlscan.io | https://urlscan.io/user/signup |
| Groq | https://console.groq.com/keys |

---

## Interface web

```bash
python3 app.py
# → http://localhost:5000
```

**Premier lancement :** inscrivez-vous avec l'email défini dans `ADMIN_EMAIL` — le compte est automatiquement approuvé en tant qu'administrateur.

**Pour les collègues :** ils s'inscrivent sur `/register`, vous les approuvez depuis `/admin/users`.

### Niveaux d'accès

| Action | Anonyme | Analyste approuvé | Admin |
|---|---|---|---|
| Consulter l'historique des IOCs | ✅ | ✅ | ✅ |
| Rechercher dans les IOCs | ✅ | ✅ | ✅ |
| Soumettre / enrichir un IOC | ❌ | ✅ | ✅ |
| Approuver des comptes | ❌ | ❌ | ✅ |

---

## CLI

Le script original reste disponible pour un usage rapide ou du scripting :

```bash
# IOC unique
python3 main.py --ioc 8.8.8.8

# Plusieurs IOCs en ligne
python3 main.py --ioc 1.2.3.4 evil.example.com d41d8cd98f00b204e9800998ecf8427e

# Depuis un fichier (un IOC par ligne, lignes # ignorées)
python3 main.py --file iocs.txt

# Chemin de sortie personnalisé
python3 main.py --file iocs.txt --output rapport.html

# Désactiver la synthèse IA
python3 main.py --ioc 1.2.3.4 --no-ai
```

Les rapports sont sauvegardés dans `output/<YYYYMMDD_HHMMSS>.html` par défaut.

### Format du fichier d'entrée

```
# IPs
185.220.101.45
1.2.3.4

# Domaines
phishing.example.com

# Hashes (MD5 / SHA1 / SHA256)
d41d8cd98f00b204e9800998ecf8427e
```

---

## Ajouter un nouvel enrichisseur

1. Créer `src/enrichers/<nom>.py` avec une fonction `enrich(ioc: IOC) -> EnrichmentResult`
2. L'enregistrer dans `src/enrichers/__init__.py` sous `ENRICHERS_BY_TYPE`
3. Ajouter la variable de clé API dans `.env.example`

---

## Tests

```bash
pytest tests/
```
