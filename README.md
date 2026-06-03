# ForenHive

> Plateforme d'analyse forensique automatisée basée sur des honeypots
> Projet de Fin d'Études — ISET Radès × Standard Sharing Software (3S)
> Développé par Zeineb Benrhouma & Ismail Cherif (2025-2026)

ForenHive agrège la télémétrie d'attaques multi-sources (SSH, SMB, HTTP, flux
réseau) à travers une chaîne en 5 couches et produit des profils de suspects
structurés selon la méthodologie criminologique du FBI Behavioral Analysis
Unit : mapping MITRE ATT&CK, score de risque 0–100, triage malware
YARA/VirusTotal, chaîne de custody SHA-256 + RFC 3161, et analyse
comportementale par LLM local (Mistral 7B), sans dépendance LLM externe.

---

## Problématique

Les infrastructures exposées sur Internet subissent un flux continu d'attaques
automatisées (scans, force brute, exploitation de vulnérabilités, dépôt de
malware). Les solutions classiques — pare-feu, IDS, SIEM — se concentrent sur
le **blocage** et génèrent des alertes brutes, sans répondre aux questions
réellement utiles en investigation : *qui* est l'attaquant, *quelles* sont ses
intentions et son niveau de sophistication, *comment* s'est déroulée l'attaque
étape par étape, et *quelles* preuves sont juridiquement exploitables.

Trois verrous concrets se posent :

1. **Fragmentation des données** — la télémétrie d'attaque est dispersée entre
   protocoles et outils (SSH, SMB, HTTP, flux réseau), dans des formats
   hétérogènes, sans corrélation temporelle ni vision unifiée par attaquant.
2. **Absence de contexte forensique** — les logs bruts n'offrent ni profil de
   suspect, ni mapping vers un référentiel reconnu (MITRE ATT&CK), ni score de
   risque exploitable, ni chaîne de custody garantissant l'intégrité des
   preuves.
3. **Dépendance et confidentialité** — l'analyse comportementale par IA repose
   le plus souvent sur des services cloud externes, incompatibles avec la
   sensibilité des données d'incident et les contraintes de souveraineté.

**ForenHive** répond à ces verrous en agrégeant la télémétrie multi-sources de
honeypots dans une chaîne forensique automatisée de bout en bout :
corrélation et reconstruction de timeline, enrichissement et réputation des IP,
triage malware (YARA/VirusTotal), mapping MITRE ATT&CK, score de risque 0–100,
profilage comportemental de suspect par **LLM local** (Mistral 7B, sans
dépendance externe) et scellement des preuves par chaîne de custody
SHA-256 + RFC 3161.

---

## Architecture — 5 couches

```
┌─────────────────────────────────────────────────────────┐
│  1 — HONEYPOTS                                         │
│  Cowrie (SSH:2222, Telnet:2223)  Dionaea (11 protos)    │
│  Galah  (HTTP:8080/8888, LLM)    Zeek (IDS réseau)      │
├─────────────────────────────────────────────────────────┤
│  2 — ETL & STOCKAGE                                    │
│  Filebeat → Logstash:5044 → Elasticsearch:9200          │
│  GeoIP MaxMind │ Grok parsing │ ECS normalize           │
│  PostgreSQL:5432 (forensique structuré)                 │
├─────────────────────────────────────────────────────────┤
│  3 — FORENSIC ENGINE (Python)                          │
│  11 modules │ Risk Score v2.0.0 (9 signaux)             │
│  MITRE ATT&CK hybride │ Suspect Profiler (Mistral 7B)   │
│  Chaîne de Custody SHA-256 / RFC 3161                   │
├─────────────────────────────────────────────────────────┤
│  4 — BACKEND                                           │
│  FastAPI (12 routers) │ PDF WeasyPrint (FR/EN)          │
│  Export STIX 2.1 │ Alertes e-mail + Twilio              │
│  Ollama:11434 (chat + profiling LLM)                    │
├─────────────────────────────────────────────────────────┤
│  5 — FRONTEND                                          │
│  React/Vite (18 pages) │ i18n FR/EN │ JWT Bearer    │
│  Nginx:3000                                             │
└─────────────────────────────────────────────────────────┘
```

**Double stockage** : Elasticsearch (logs bruts, indices journaliers
`honeypot-logs-YYYY.MM.dd`) + PostgreSQL (résultats forensiques structurés,
auth, audit).

## Sprints

| Sprint | Périmètre | Statut |
|--------|-----------|--------|
| S1 | Honeypots (Cowrie, Dionaea, Galah, Zeek) | ✅ |
| S2 | Pipeline ETL (Filebeat → Logstash → Elasticsearch) | ✅ |
| S3 | Forensic Engine (enrichissement, YARA, MITRE, scoring, profiling, CoC) | ✅ |
| S4 | Backend FastAPI (12 routers, PDF WeasyPrint, Export STIX 2.1, alertes) | ✅ |
| S5 | Frontend React/Vite (18 pages, i18n FR/EN, JWT, Nginx) | ✅ |

Tous les sprints sont terminés et mergés sur `main`.

## Prérequis

- Docker ≥ 28.4 + Compose v2.39+
- Ubuntu 24.10 (testé sur Dell PowerEdge R750, 32 Go RAM, 16 cœurs)
- Minimum 16 Go RAM recommandé (Mistral 7B Q4_K_M = 4,4 Go)
- Variables d'environnement : voir [`.env.example`](.env.example)

## Installation & lancement

```bash
git clone <repo> forenhive
cd forenhive
cp .env.example .env          # remplir les clés API et secrets
docker compose up -d          # lancer toute la stack
docker compose ps             # vérifier l'état des conteneurs
```

Initialiser le schéma PostgreSQL (premier lancement) :

```bash
docker compose exec forensic-engine python db/init_db.py
```

Raccourcis `make` (voir [`Makefile`](Makefile)) :

```bash
make up        # docker compose up -d
make status    # docker compose ps
make logs      # docker compose logs -f
make down      # docker compose down
```

> 📖 **Référence complète** de toutes les commandes (docker, engine CLI,
> base de données, pipeline, tests, dépannage) :
> [`docs/COMMANDS.md`](docs/COMMANDS.md).

## Variables d'environnement (extrait)

Toutes les clés sont décrites dans [`.env.example`](.env.example). Les
principales :

| Variable | Rôle |
|----------|------|
| `JWT_SECRET` | Signature des jetons JWT du backend |
| `POSTGRES_PASSWORD` | Mot de passe PostgreSQL (`forenhive`) |
| `ABUSEIPDB_API_KEY` | Réputation IP (enrichissement) |
| `VIRUSTOTAL_API_KEY` | Lookup SHA-256 des payloads |
| `IPLOCATE_API_KEY` | Détection Tor / VPN / proxy |
| `SHODAN_API_KEY` | Enrichissement infrastructure (optionnel) |
| `SMTP_*` / `TWILIO_*` | Alertes e-mail et SMS |
| `ENGINE_INTERVAL_MINUTES` | Cadence de relance auto du forensic engine |

Les clés API sont optionnelles : sans elles, l'enrichissement correspondant
est ignoré (avec suivi de quota via `quota_tracker`).

## Ports exposés

| Service         | Port   | Description                          |
|-----------------|--------|--------------------------------------|
| Cowrie SSH      | 2222   | Honeypot SSH                         |
| Cowrie Telnet   | 2223   | Honeypot Telnet                      |
| Dionaea         | divers | 11 protocoles (SMB:445, MSSQL:1433, …) |
| Galah HTTP      | 8080   | Honeypot HTTP (LLM Mistral)          |
| Galah HTTP      | 8888   | Honeypot HTTP alternatif             |
| Elasticsearch   | 9200   | Logs (127.0.0.1 uniquement)          |
| Ollama          | 11434  | LLM local Mistral 7B (interne)       |
| PostgreSQL      | 5432   | Stockage forensique (interne)        |
| Backend FastAPI | 8000   | API REST                             |
| Forensic Engine | 8001   | Healthcheck / status sidecar         |
| Frontend        | 3000   | SPA (Nginx)                          |

## Forensic Engine — pipeline d'analyse

Le moteur ([`forensic-engine/engine.py`](forensic-engine/engine.py)) exécute
tous ses modules par défaut, ou une étape à la fois via un flag `--*-only` :

```bash
docker compose exec forensic-engine python engine.py            # run complet, 24h
docker compose exec forensic-engine python engine.py --hours 48 # fenêtre custom

# étapes individuelles
python engine.py --enrich-only    # enrichissement IP + GeoIP
python engine.py --yara-only      # scan YARA des payloads Dionaea
python engine.py --smb-only       # analyse forensique SMB
python engine.py --timeline-only  # timeline par IP
python engine.py --ioc-only       # extraction d'IoCs
python engine.py --score-only     # risk scoring + MITRE ATT&CK
python engine.py --profile-only   # profiling LLM (IPs à risque)
python engine.py --coc-only       # scellement chaîne de custody
```

Le sidecar HTTP ([`server.py`](forensic-engine/server.py), port 8001) démarre
automatiquement et relance `engine.py` toutes les `ENGINE_INTERVAL_MINUTES`.

**Modules** : `enricher`, `yara_scanner`, `smb_analyzer`, `timeline_builder`,
`ioc_extractor`, `risk_score`, `mitre_mapper`, `profiler`, `chain_of_custody`,
`virustotal`, `quota_tracker`.

## API REST (backend)

12 routers sous [`backend/routers/`](backend/routers/) :
`auth`, `sessions`, `attacks`, `forensics`, `risk_score`, `profiling`,
`honeypots`, `geo`, `alerts`, `reports`, `audit`, `chat`.

Authentification JWT Bearer. Healthcheck : `GET /health` → `{"status":"ok"}`.
Détail des endpoints : [`docs/api.md`](docs/api.md).

## Tests

```bash
pytest                                              # tous les tests
pytest forensic-engine/tests/test_risk_score.py    # unitaires (modèle de risque)
pytest backend/tests/test_risk_score_integration.py # intégration backend
```

## Structure du dépôt

```
forenhive/
├── honeypots/          # C1 — Configuration des 4 honeypots
├── pipeline/           # C2 — Filebeat + Logstash (ip_map.yml, grok, ECS)
├── geoip/              # C2 — Bases MaxMind GeoLite2
├── forensic-engine/    # C3 — 11 modules d'analyse Python + CLI/sidecar
├── backend/            # C4 — API FastAPI (12 routers, services, alertes)
├── frontend/           # C5 — SPA React/Vite + Nginx (18 pages)
├── scripts/            # Outils (dos_burst.sh — trafic de test)
├── docs/               # Documentation technique + COMMANDS.md
├── docker-compose.yml  # Orchestration complète
├── Makefile            # Raccourcis (up/down/logs/status)
├── pyproject.toml      # Config ruff (dev-only)
└── .env.example        # Template variables d'environnement
```

## Documentation

- [Référence des commandes](docs/COMMANDS.md) — docker, engine, DB, pipeline, tests
- [Architecture détaillée](docs/architecture.md)
- [Guide de déploiement](docs/deployment.md)
- [Forensic Engine — modules, signaux, Suspect Profiler](docs/forensic-engine.md)
- [API REST — endpoints](docs/api.md)

## Workflow de branches

```
zeineb/* ──┐
ismail/* ──┴──► main
```

## Équipe

- **Zeineb Benrhouma** 
- **Ismail Cherif** 

---

*ISET Radès | Licence RSI / Standard Sharing Software (3S), Charguia, Tunis*
