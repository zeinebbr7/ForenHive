# Guide de déploiement — ForenHive

## Cible de référence

- **Matériel** : Dell PowerEdge R750 (32 Go RAM, 16 cœurs)
- **OS** : Ubuntu Server 24.10
- **Réseau** : interface `eno12399`, IP statique 172.16.1.100
- **Docker** : 28.4.0
- **Compose** : v2.39.1
- **Accès tests** : VM Kali 192.168.26.128 (sur le sous-réseau honeypot)

## Prérequis logiciels

```bash
# Docker (si non installé)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# Compose v2 est inclus dans Docker Engine moderne
docker compose version
```

## Variables d'environnement (`.env`)

Copier le template et remplir les valeurs :

```bash
cp .env.example .env
```

Variables critiques :

| Variable | Rôle | Exemple |
|----------|------|---------|
| `POSTGRES_PASSWORD` | mot de passe PG | (générer 32+ chars) |
| `JWT_SECRET` | secret signature JWT backend | `openssl rand -hex 32` |
| `BOOTSTRAP_ADMIN_EMAIL` | admin initial créé au premier boot | `admin@forenhive.local` |
| `BOOTSTRAP_ADMIN_PASSWORD` | mot de passe admin initial | (à changer après login) |
| `ABUSEIPDB_API_KEY` | clé AbuseIPDB (gratuit 1000/jour) | — |
| `VIRUSTOTAL_API_KEY` | clé VT Public API (500/jour) | — |
| `MAXMIND_LICENSE_KEY` | clé GeoLite2 (gratuite, registration) | — |
| `OLLAMA_MODEL` | modèle LLM local | `mistral:7b-instruct-q4_K_M` |
| `TWILIO_*` | alertes WhatsApp/SMS (optionnel) | — |
| `ZEEK_INTERFACE` | interface réseau pour Zeek | `eno12399` |

## Séquence de démarrage

```bash
# 1. Pull/build des images
docker compose pull
docker compose build

# 2. Démarrer toute la stack
docker compose up -d

# 3. Initialiser le schéma PostgreSQL (premier boot uniquement)
docker compose exec forensic-engine python db/init_db.py

# 4. Charger le modèle Mistral dans Ollama (premier boot, ~4 Go)
docker compose exec ollama ollama pull mistral:7b-instruct-q4_K_M

# 5. Vérifier l'état
docker compose ps
```

## Vérifications santé

```bash
# Backend
curl -fsS http://localhost:8000/health

# Elasticsearch
curl -fsS http://localhost:9200/_cluster/health

# Forensic Engine
curl -fsS http://localhost:8001/

# Frontend (SPA)
curl -fsSL http://localhost:3000/

# Ollama
curl -fsS http://localhost:11434/api/tags
```

## Accès réseau

| Cible | Depuis le LAN | Depuis la VM Kali (tests) |
|-------|---------------|---------------------------|
| Cowrie SSH | `ssh root@172.16.1.100 -p 2222` | idem |
| SPA HTTP | `http://172.16.1.100:3000` | idem |
| SPA HTTPS | `https://172.16.1.100:3443` | accepter cert auto-signé |
| Backend API | `http://172.16.1.100:8000` | accès via SPA |

## Commandes de debug courantes

```bash
# Logs d'un service
docker compose logs -f forenhive-backend
docker compose logs --tail=200 forensic-engine

# Shell dans un conteneur
docker compose exec forenhive-backend bash
docker compose exec postgresql psql -U forenhive -d forenhive

# État des indices ES
curl -s 'http://localhost:9200/_cat/indices/honeypot-logs-*?v'

# Stats LLM
docker compose exec ollama ollama list

# Relancer un service
docker compose restart forensic-engine
```

## Maintenance

- **Dionaea log full (~424 Mo) :** `docker compose restart dionaea` (problème
  récurrent connu — voir issue).
- **Quota AbuseIPDB épuisé :** réinitialisation à 00:00 UTC.
- **Mise à jour MaxMind :** régénérer les `.mmdb` dans `geoip/` et redémarrer
  `logstash` + `forensic-engine`.
- **Backup PostgreSQL :**
  ```bash
  docker compose exec postgresql pg_dump -U forenhive forenhive > backup.sql
  ```

## Workflow git

Branches courtes par feature, depuis `develop` :

```bash
git checkout develop
git pull
git checkout -b feature/<nom>
# ... travail ...
git push -u origin feature/<nom>
# PR vers develop, jamais directement vers main
```
