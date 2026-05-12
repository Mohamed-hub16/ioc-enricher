# IOC Enricher

Outil de threat intelligence pour analystes SOC. Enrichit des IPs, domaines et hashes en interrogeant des APIs gratuites, génère un paragraphe d'analyse rédigé par IA, et stocke tout dans une interface web consultable par l'équipe. Expose également une API REST pour l'intégration dans d'autres outils.

---

## Fonctionnalités

- **Enrichissement multi-sources** — AbuseIPDB, VirusTotal, ip-api.com, urlscan.io selon le type d'IOC
- **Analyse hash avancée** — signature numérique, PE/exiftool, YARA, sandboxes, threat classification
- **Synthèse IA adaptative** — paragraphe SOC en français généré par Groq (llama-3.3-70b), prompt différent selon le type d'IOC et son niveau de menace
- **Score de menace 0–100** — combinaison pondérée AbuseIPDB + VirusTotal
- **Scanners détecteurs** — pour les IPs et domaines malveillants, les antivirus ayant détecté l'IOC sont affichés en badges rouges dans les données brutes et dans le graphe
- **Cartographie des relations** — graphe interactif (vis-network) : hiérarchique pour les hashes, force-directed pour les IP/domaines
- **Interface web** — historique, recherche, filtres (malveillant / légitime), tri, re-enrichissement
- **Export Excel** — téléchargement de tous les IOCs avec scores global, AbuseIPDB et VirusTotal (3 feuilles : IPs, DOMAINs, HASHs)
- **API REST v1** — 4 endpoints JSON authentifiés par token personnel (`X-API-Key`)
- **Commentaires analystes** — annotations collaboratives sur chaque fiche IOC
- **Cache intelligent** — résultats stockés en SQLite ; IOCs de moins de 14 jours servis depuis le cache
- **Gestion d'équipe** — lecture publique, enrichissement réservé aux comptes approuvés, panneau d'administration
- **Clés API par utilisateur** — chaque analyste configure ses propres clés, chiffrées AES-128-GCM en base
- **Auto-deploy** — webhook GitHub qui déclenche `git pull` + rechargement PythonAnywhere automatiquement
- **Mode CLI** — fonctionne aussi en script autonome pour un usage rapide

---

## Sources par type d'IOC

| Source | IP | Domaine | Hash | Clé requise |
|---|---|---|---|---|
| AbuseIPDB | ✅ | ❌ | ❌ | Oui (1 000 req/jour) |
| VirusTotal | ✅ | ✅ | ✅ | Oui (500 req/jour) |
| ip-api.com | ✅ | ❌ | ❌ | **Non** — gratuit sans clé |
| urlscan.io | ✅ | ✅ | ❌ | Oui (1 000 req/jour) |
| Groq (IA) | ✅ | ✅ | ✅ | Oui — free tier |

### Données extraites pour les hashes (VirusTotal)

- Identité : noms soumis, type, taille, SHA256/SHA1/MD5, ssdeep/tlsh/vhash
- Dates : première/dernière soumission, nombre de sources distinctes
- **Signature numérique** : éditeur, émetteur, validité du certificat
- **Métadonnées PE** : date de compilation, imphash, sections (entropie élevée flagguée)
- **Exiftool** : CompanyName, ProductName, FileVersion, OriginalFilename…
- **Threat classification** : label suggéré, catégories, noms de famille
- **Sandboxes** : verdicts multi-sandbox (VirusTotal MultiSandbox, Triage…)
- **Règles YARA** : règles communautaires qui ont matché
- **Graphe de relations** : parents d'exécution, fichiers déposés, URLs/domaines/IPs contactés

---

## Structure du projet

```
app.py                    # Point d'entrée Flask (interface web)
main.py                   # Point d'entrée CLI
webapp/
  __init__.py             # Factory Flask (SQLAlchemy, CSRF, LoginManager)
  models.py               # Modèles : User, IOCRecord, Comment
  auth.py                 # /login  /register  /logout  /settings/api-keys
                          # /settings/api-token/generate|revoke
  ioc_routes.py           # /  /ioc/<valeur>  /enrich  /export/excel
                          # /ioc/<valeur>/delete  /ioc/<valeur>/comment
  admin_routes.py         # /admin/users  approve  revoke
  deploy_routes.py        # /webhook/deploy  (auto-deploy GitHub)
  api_routes.py           # /api/v1/  (REST API — auth X-API-Key)
  templates/              # Templates Bootstrap 5 dark theme
src/
  enrichers/              # Un module par API (abuseipdb, virustotal, ipapi, urlscan…)
  parsers/                # Détection du type d'IOC (IP / domaine / hash)
  synthesis/              # Générateur de paragraphe IA via Groq
  models.py               # Dataclasses partagés (IOC, EnrichmentResult)
instance/                 # Base de données SQLite (ignorée par git)
output/                   # Rapports HTML générés par le CLI (ignorés par git)
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

SECRET_KEY=votre_clé_flask   # python3 -c "import secrets; print(secrets.token_hex(32))"
ADMIN_EMAIL=votre@email.com  # ce compte obtient automatiquement les droits admin à l'inscription

# Auto-deploy (optionnel)
DEPLOY_SECRET=votre_secret_webhook
PA_API_TOKEN=votre_token_pythonanywhere
PA_USERNAME=votre_username_pa
PA_DOMAIN=username.pythonanywhere.com
```

> `ip-api.com` ne nécessite aucune clé — il est appelé automatiquement pour les IPs.

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

**Pour les collègues :** ils s'inscrivent sur `/register`, vous les approuvez depuis **Admin** dans la navbar.

### Niveaux d'accès

| Action | Anonyme | Analyste approuvé | Admin |
|---|---|---|---|
| Consulter l'historique | ✅ | ✅ | ✅ |
| Rechercher / filtrer | ✅ | ✅ | ✅ |
| Soumettre / enrichir un IOC | ❌ | ✅ | ✅ |
| Exporter Excel | ❌ | ✅ | ✅ |
| Commenter un IOC | ❌ | ✅ | ✅ |
| Utiliser l'API REST | ❌ | ✅ | ✅ |
| Supprimer un IOC | ❌ | ❌ | ✅ |
| Approuver des comptes | ❌ | ❌ | ✅ |

---

## Export Excel

Le bouton **Exporter Excel** sur la page d'accueil génère un fichier
`ioc_export_YYYYMMDD_HHMM.xlsx` avec trois feuilles (IPs, DOMAINs, HASHs) :

| Colonne | Description |
|---|---|
| Valeur | L'IOC |
| Score global | Score 0–100 (AbuseIPDB + VirusTotal combinés) |
| Score AbuseIPDB | Confidence score brut AbuseIPDB (vide pour les hashes) |
| Score VirusTotal | Ratio détections VT en % |
| Vues | Nombre de consultations de la fiche |
| Malveillant | Oui / Non |
| Enrichi le | Date d'enrichissement |
| Enrichi par | Email de l'analyste |

Les IOCs malveillants apparaissent en rouge dans le fichier.

---

## API REST

### Authentification

1. Connectez-vous → **Paramètres** (navbar) → section **Token d'accès API REST**
2. Cliquez **Générer un token** — copiez-le immédiatement (affiché une seule fois)
3. Passez-le dans l'en-tête `X-API-Key` de chaque requête

### Endpoints

| Méthode | URL | Description |
|---|---|---|
| `GET` | `/api/v1/iocs` | Liste paginée des IOCs |
| `GET` | `/api/v1/ioc/<valeur>` | Détail complet (données brutes + paragraphe IA) |
| `POST` | `/api/v1/enrich` | Enrichir un IOC |
| `DELETE` | `/api/v1/ioc/<valeur>` | Supprimer un IOC (admin uniquement) |

### Paramètres de `/api/v1/iocs`

| Paramètre | Valeurs | Défaut |
|---|---|---|
| `q` | texte libre | — |
| `type` | `ip`, `domain`, `hash` | tous |
| `min_score` | 0–100 | — |
| `sort` | `date`, `score`, `views` | `date` |
| `page` | entier | 1 |
| `per_page` | 1–200 | 50 |

### Exemples

```bash
# Lister les IPs avec score ≥ 50
curl -H "X-API-Key: <token>" \
     "http://localhost:5000/api/v1/iocs?type=ip&min_score=50&sort=score"

# Détail d'un IOC
curl -H "X-API-Key: <token>" \
     "http://localhost:5000/api/v1/ioc/8.8.8.8"

# Enrichir un IOC
curl -X POST \
     -H "X-API-Key: <token>" \
     -H "Content-Type: application/json" \
     -d '{"ioc": "8.8.8.8"}' \
     "http://localhost:5000/api/v1/enrich"

# Forcer le re-enrichissement (ignorer le cache)
curl -X POST \
     -H "X-API-Key: <token>" \
     -H "Content-Type: application/json" \
     -d '{"ioc": "8.8.8.8", "force": true}' \
     "http://localhost:5000/api/v1/enrich"
```

```python
import requests

BASE = "http://localhost:5000/api/v1"
HEADERS = {"X-API-Key": "<token>"}

# Toutes les IPs malveillantes
r = requests.get(f"{BASE}/iocs", headers=HEADERS,
                 params={"type": "ip", "min_score": 1, "sort": "score", "per_page": 200})
for ioc in r.json()["iocs"]:
    print(ioc["value"], ioc["threat_score"])
```

---

## Auto-deploy (PythonAnywhere)

Le webhook `/webhook/deploy` permet de déclencher automatiquement un `git pull` + rechargement du serveur à chaque push sur `main`.

### 1. Générer un secret webhook

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Ajouter dans `.env` : `DEPLOY_SECRET=...`

### 2. Obtenir le token PythonAnywhere

PythonAnywhere → **Account** → **API token** → copier le token.

```env
PA_API_TOKEN=votre_token
PA_USERNAME=votre_username
PA_DOMAIN=votre_username.pythonanywhere.com
```

### 3. Configurer le webhook GitHub

GitHub → repo → **Settings** → **Webhooks** → **Add webhook** :

| Champ | Valeur |
|---|---|
| Payload URL | `https://votre_username.pythonanywhere.com/webhook/deploy` |
| Content type | `application/json` |
| Secret | la valeur de `DEPLOY_SECRET` |
| Events | **Just the push event** |

---

## CLI

```bash
# IOC unique
python3 main.py --ioc 8.8.8.8

# Plusieurs IOCs
python3 main.py --ioc 1.2.3.4 evil.example.com d41d8cd98f00b204e9800998ecf8427e

# Depuis un fichier
python3 main.py --file iocs.txt

# Chemin de sortie personnalisé
python3 main.py --file iocs.txt --output rapport.html

# Désactiver la synthèse IA
python3 main.py --ioc 1.2.3.4 --no-ai
```

Les rapports sont sauvegardés dans `output/<YYYYMMDD_HHMMSS>.html` par défaut.

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
