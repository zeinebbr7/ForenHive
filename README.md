# ForenHive

> Plateforme d'analyse forensique automatisée basée sur des honeypots
> Projet de Fin d'Études — ISET Radès × Standard Sharing Software (3S)
> Développé par Zeineb Benrhouma & Ismail Cherif (2025-2026)

ForenHive agrège la télémétrie d'attaques multi-sources (SSH, SMB, HTTP, flux
réseau) à travers une chaîne en 4 couches et produit des profils de suspects
structurés selon la méthodologie criminologique du FBI Behavioral Analysis
Unit : mapping MITRE ATT&CK, score de risque 0–100, triage malware
YARA/VirusTotal, chaîne de custody SHA-256 + RFC 3161, et analyse
comportementale par LLM local (Mistral 7B), sans dépendance LLM externe.

---

## Architecture — 4 couches

```
┌─────────────────────────────────────────────────────────┐
│  C1 — HONEYPOTS                                         │
│  Cowrie (SSH:2222, Telnet:2223)  Dionaea (11 protos)    │
│  Galah  (HTTP:8080/8888, LLM)    Zeek (IDS réseau)      │
├─────────────────────────────────────────────────────────┤
│  C2 — ETL & STOCKAGE                                    │
│  Filebeat → Logstash:5044 → Elasticsearch:9200          │
│  GeoIP MaxMind │ Grok parsing │ ECS normalize           │
│  PostgreSQL:5432 (forensique structuré)                 │
├─────────────────────────────────────────────────────────┤
│  C3 — FORENSIC ENGINE (Python)                          │
│  11 modules │ Risk Score v2.0.0 (9 signaux)             │
│  MITRE ATT&CK hybride │ Suspect Profiler (Mistral 7B)   │
│  Chaîne de Custody SHA-256 / RFC 3161                   │
├─────────────────────────────────────────────────────────┤
│  C4 — BACKEND + SPA + REPORTING                         │
│  FastAPI (13 routers) │ SPA HTML/JS │ Ollama:11434      │
│  PDF WeasyPrint (bilingue FR/EN) │ Export STIX 2.1      │
└─────────────────────────────────────────────────────────┘
```

## Sprints

| Sprint | Périmètre | Statut |
|--------|-----------|--------|
| S1 | Honeypots (Cowrie, Dionaea, Galah, Zeek) | ✅ |
| S2 | Pipeline ETL (Filebeat → Logstash → Elasticsearch) | ✅ |
| S3 | Forensic Engine (enrichissement, YARA, MITRE, scoring, profiling, CoC) | ✅ |
| S4 | Backend FastAPI + SPA + Reporting PDF + STIX | ✅ |

## Prérequis

- Docker ≥ 28.4 + Compose v2.39+
- Ubuntu 24.10 (testé sur Dell PowerEdge R750, 32 Go RAM, 16 cœurs)
- Minimum 16 Go RAM recommandé (Mistral 7B Q4_K_M = 4,4 Go)
- Variables d'environnement : voir [`.env.example`](.env.example)

## Installation & lancement

```bash
git clone <repo> forenhive
cd forenhive
cp .env.example .env          # remplir les clés API
docker compose up -d          # lancer toute la stack
docker compose ps             # vérifier l'état des conteneurs
```

Initialiser le schéma PostgreSQL (premier lancement) :

```bash
docker compose exec forensic-engine python db/init_db.py
```

## Ports exposés

| Service         | Port  | Description                          |
|-----------------|-------|--------------------------------------|
| Cowrie SSH      | 2222  | Honeypot SSH                         |
| Cowrie Telnet   | 2223  | Honeypot Telnet                      |
| Dionaea         | divers | 11 protocoles (SMB:445, MSSQL, …)   |
| Galah HTTP      | 8080  | Honeypot HTTP (LLM Mistral)          |
| Galah HTTP      | 8888  | Honeypot HTTP alternatif             |
| Elasticsearch   | 9200  | Logs + mémoire profils (127.0.0.1)   |
| Ollama          | 11434 | LLM local Mistral 7B (interne)       |
| Backend FastAPI | 8000  | API REST                             |
| Frontend        | 3000  | SPA (HTTP)                           |
| Forensic Engine | 8001  | Healthcheck / status                 |

## Structure du dépôt

```
forenhive/
├── honeypots/          # C1 — Configuration des 4 honeypots
├── pipeline/           # C2 — Filebeat + Logstash
├── geoip/              # C2 — Bases MaxMind (volumes Docker)
├── forensic-engine/    # C3 — 11 modules d'analyse Python
├── backend/            # C4 — API FastAPI (13 routers)
├── frontend/           # C4 — SPA (Vite + nginx)
├── docs/               # Documentation technique
├── archive/            # Prototypes archivés (non actifs)
├── docker-compose.yml  # Orchestration complète
├── pyproject.toml      # Config ruff (dev-only)
└── .env.example        # Template variables d'environnement
```

## Workflow de branches

```
zeineb/* ──┐
           ├──► develop ──► main
ismail/* ──┘
```

Toujours brancher depuis `develop`, jamais commit direct sur `main`.

## Documentation

- [Architecture détaillée](docs/architecture.md)
- [Guide de déploiement](docs/deployment.md)
- [Forensic Engine — modules, signaux, Suspect Profiler](docs/forensic-engine.md)
- [API REST — endpoints](docs/api.md)
- [CHANGELOG](docs/CHANGELOG.md)

## Équipe

- **Zeineb Benrhouma** — Forensic Engine, Backend, Architecture
- **Ismail Cherif** — Frontend, Honeypots, ETL Pipeline

---

*ISET Radès | Licence RSI | Soutenance 2026 | Hébergé chez Standard Sharing Software (3S), Charguia, Tunis*
