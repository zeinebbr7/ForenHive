ForenHive — Plateforme d'Analyse Forensique Automatisée
Python FastAPI React Elasticsearch Docker Ollama License

Détection, analyse forensique automatisée et reporting certifié basés sur honeypots

PFE 2025–2026 • Spécialité RSI • ISET Radès, Tunis
Réalisé en collaboration avec Standard Sharing Software (3S)

📋 Table des matières
Aperçu
Équipe
Architecture
Stack technique
Installation
Utilisation
Configuration
API
Contribuer
Licence
🎯 Aperçu
ForenHive automatise l'intégralité du cycle de vie de l'analyse forensique des cyberattaques capturées par des honeypots. La plateforme intègre détection en temps réel, enrichissement multi-sources, analyse intelligente par LLM local et génération de rapports certifiés.

Flux de données
Attaquant
    ↓
Honeypots (T-Pot Multi)
    ↓
Pipeline ETL (Filebeat → Logstash → Elasticsearch)
    ↓
Enrichissement (GeoIP · Réputation · YARA · VirusTotal)
    ↓
Analyse LLM Local (Ollama + Mistral 7B → MITRE ATT&CK)
    ↓
Interface Web (FastAPI + React)
    ↓
Rapport PDF Certifié (SHA-256 + RFC 3161 Timestamping)
Différenciateurs clés
Aspect	Avantage
LLM Local	Mistral 7B via Ollama — zéro appel API, 100% offline
Mapping MITRE	Automatisation du mapping tactiques/techniques sans supervision cloud
Confidentialité	Toutes données forensiques restent on-premise
Rapport certifié	SHA-256 + RFC 3161 pour l'imputabilité légale
Multi-honeypot	Cowrie, Dionaea, Snare, Zeek sur une seule plateforme
👥 Équipe
Nom	Rôle	Domaines
Zeineb Benrhouma	Infrastructure & Enrichissement	Honeypots · ETL · GeoIP · Réputation · YARA · MITRE
Ismail Cherif	Backend & Frontend	FastAPI · React · PostgreSQL · PDF · Reporting
🏗️ Architecture — 5 Couches
Vue d'ensemble
┌──────────────────────────────────────────────────────────────┐
│ C1 — HONEYPOTS                                               │
│      Cowrie (SSH/Telnet) · Dionaea (Malware)                │
│      Snare+Tanner (Web) · Zeek (Trafic Réseau)              │
├──────────────────────────────────────────────────────────────┤
│ C2 — PIPELINE ETL                                            │
│      Filebeat → Logstash (normalisation ECS) → Elasticsearch │
│      PostgreSQL (auth, audit, métadonnées)                   │
├──────────────────────────────────────────────────────────────┤
│ C3 — ENRICHISSEMENT                                          │
│      MaxMind GeoLite2 · AbuseIPDB API · YARA · VirusTotal   │
├──────────────────────────────────────────────────────────────┤
│ C4 — ANALYSE INTELLIGENCE ★                                 │
│      Ollama + Mistral 7B (MITRE ATT&CK)                     │
│      Timeline Engine · IOC Extractor · Détection d'anomalies │
├──────────────────────────────────────────────────────────────┤
│ C5 — INTERFACE & REPORTING                                   │
│      FastAPI REST · React SPA                                │
│      Leaflet (cartes) · Recharts (graphiques)               │
│      WeasyPrint (PDF) · RFC 3161 Timestamping                │
└──────────────────────────────────────────────────────────────┘
Détail des couches
C1 — Honeypots (Détection)
Composant	Fonction	Ports
Cowrie	SSH/Telnet honeypot — simule serveur Linux vulnérable	22, 23
Dionaea	Low-interaction malware honeypot — capture payloads SMB/FTP/HTTP	445, 21, 80
Snare + Tanner	Web honeypot — détecte SQLi, XSS, LFI, RFI	8080
Zeek	Analyse réseau passive — extraction comportement connexion	—
C2 — Pipeline ETL (Normalisation)
Composant	Rôle	Port
Filebeat	Collecte asynchrone des logs (at-least-once semantics)	→ 5044
Logstash	Parsing/enrichissement · normalisation ECS · filter chaînes	5044
Elasticsearch	Indexation full-text · agrégations temps réel	9200
PostgreSQL	Métadonnées · audit · rapports · authentification	5432
C3 — Enrichissement (Contexte)
Source	Type	Données
MaxMind GeoLite2	Local	Géolocalisation IP (latitude, longitude, pays, AS)
AbuseIPDB API	Réseau	Score réputation attaquant (0–100)
YARA	Local	Détection pattern malwares (règles personnalisées)
VirusTotal API	Réseau	Analyse dynamique hachages SHA-256 (verdicts multi-AV)
C4 — Analyse Intelligence (Mapping MITRE)
Ollama + Mistral 7B (LLM Local)

Input : événements structurés (src IP, commandes shell exécutées, fichiers modifiés, etc.)
Processing : inférence sur contexte MITRE ATT&CK
Output : tactique + technique + subtechnique + confiance
Sous-composants :

Timeline Engine : ordonnancement séquentiel des événements
IOC Extractor : extraction automatique indicateurs de compromission
Détection Anomalies : identification comportements anormaux via statistiques
C5 — Interface & Reporting (Présentation)
Tech	Usage
FastAPI	API REST — authentification OAuth2 · audit logs
React 18	SPA responsive — dashboard time-series · alertes
Leaflet	Cartographie attaquants géolocalisés
Recharts	Graphiques trafic/tentatives/pays d'origine
WeasyPrint	Rendu PDF haute-fidélité
RFC 3161	Timestamping numérique certifié
🛠️ Stack Technique
Backend
Python 3.11+
├── FastAPI 0.111          (REST API · async)
├── SQLAlchemy 2.0         (ORM PostgreSQL)
├── Pydantic 2.0           (validation schémas)
├── PyJWT                  (authentification)
├── elasticsearch-py 8.x   (client Elasticsearch)
├── requests               (requêtes HTTP)
├── ollama-python          (inférence locale LLM)
├── weasyprint             (PDF rendering)
└── python-jose            (signing RFC 3161)
Frontend
Node.js 20+
├── React 18.x
├── TypeScript 5.x
├── Axios                  (HTTP client)
├── Leaflet 1.9            (cartographie)
├── Recharts 2.x           (graphiques)
├── Tailwind CSS 3.x       (styles)
└── React Router 6.x       (navigation SPA)
Infra & Data
Docker Compose 28.4+
├── Elasticsearch 8.x      (moteur recherche)
├── Logstash 8.x           (pipeline)
├── Filebeat 8.x           (collecte)
├── PostgreSQL 15+         (métadonnées)
├── Ollama                 (serveur LLM)
├── T-Pot (honeypots)      (Cowrie, Dionaea, Snare, Zeek)
└── Redis (optionnel)      (cache/queues)
📦 Installation
Prérequis
Docker 28.4+ & Docker Compose 2.20+
RAM : 16 GB minimum (Elasticsearch + Ollama requis)
Disque : 50 GB minimum (indexation Elasticsearch)
Accès réseau : Ports 5044, 5432, 9200, 3000, 8000 libres
1. Cloner le dépôt
git clone https://github.com/Zeineb/forenhive.git
cd forenhive
2. Configuration initiale
Créer .env à partir du template :

cp .env.example .env
Éditer .env avec vos paramètres :

# API
API_HOST=0.0.0.0
API_PORT=8000
API_ENV=production
API_SECRET_KEY=your-secret-key-here-min-32-chars

# PostgreSQL
POSTGRES_USER=forenhive
POSTGRES_PASSWORD=secure-password-change-me
POSTGRES_DB=forenhive
POSTGRES_PORT=5432

# Elasticsearch
ES_HOST=elasticsearch
ES_PORT=9200
ES_USER=elastic
ES_PASSWORD=changeme

# Ollama (LLM)
OLLAMA_BASE_URL=http://ollama:11434
OLLAMA_MODEL=mistral:7b

# Frontend
REACT_APP_API_URL=http://localhost:8000
REACT_APP_ENV=production

# Honeypots
HONEYPOT_SSH_PORT=22
HONEYPOT_HTTP_PORT=8080

# AbuseIPDB API (optionnel)
ABUSEIPDB_API_KEY=your-api-key-here

# VirusTotal API (optionnel)
VIRUSTOTAL_API_KEY=your-api-key-here
3. Déployer avec Docker Compose
docker-compose -f docker-compose.yml up -d
Vérifier les services :

docker-compose ps
# Tous les services doivent être en "Up"
4. Initialiser la base de données
docker exec forenhive-api python -m alembic upgrade head
Créer un compte administrateur :

docker exec -it forenhive-api python -c "
from app.db import create_admin_user
create_admin_user('admin', 'admin@forenhive.local', 'changeme')
"
5. Accéder à l'interface
Frontend : http://localhost:3000
API : http://localhost:8000
API Docs : http://localhost:8000/docs (Swagger)
Elasticsearch : http://localhost:9200
Identifiants par défaut :

Email : admin@forenhive.local
Mot de passe : changeme (à modifier immédiatement)
🚀 Utilisation
Accès via l'interface web
Se connecter : http://localhost:3000
Naviguer vers Dashboard pour voir les attaques capturées
Cliquer sur une attaque pour voir l'analyse forensique détaillée
Exporter le rapport en PDF (avec signature RFC 3161)
Accès via l'API REST
Authentification
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@forenhive.local",
    "password": "changeme"
  }'
Réponse :

{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
Récupérer les événements honeypot
curl -H "Authorization: Bearer <token>" \
  http://localhost:8000/api/events?limit=10&offset=0
Obtenir l'analyse forensique d'un événement
curl -H "Authorization: Bearer <token>" \
  http://localhost:8000/api/events/{event_id}/forensic
Réponse :

{
  "event_id": "evt_12345",
  "timestamp": "2025-03-13T14:32:10Z",
  "source_ip": "192.168.1.100",
  "target_port": 22,
  "geolocation": {
    "country": "Tunisia",
    "city": "Tunis",
    "latitude": 36.8065,
    "longitude": 10.1615
  },
  "abuse_ipdb_score": 85,
  "mitre_mapping": {
    "tactics": ["Reconnaissance", "Credential Access"],
    "techniques": ["T1589.001", "T1110.001"],
    "confidence": 0.92
  }
}
Générer un rapport PDF
curl -H "Authorization: Bearer <token>" \
  -X POST http://localhost:8000/api/reports/generate \
  -H "Content-Type: application/json" \
  -d '{
    "event_ids": ["evt_12345", "evt_12346"],
    "title": "Rapport d'Analyse Forensique",
    "include_signatures": true
  }' \
  --output rapport.pdf
⚙️ Configuration
Configurer les honeypots
Éditer docker-compose.yml pour ajouter/modifier honeypots :

services:
  cowrie:
    image: cowrie/cowrie:latest
    environment:
      - COWRIE_HOSTNAME=LinuxServer
    ports:
      - "22:2222"
  
  dionaea:
    image: dionaea/dionaea:latest
    ports:
      - "445:445"
      - "21:21"
Configurer Ollama
Télécharger le modèle Mistral 7B :

docker exec ollama ollama pull mistral:7b
Vérifier l'installation :

docker exec ollama ollama list
Configurer les APIs externes
AbuseIPDB
Créer un compte sur https://www.abuseipdb.com
Générer une clé API
Ajouter à .env : ABUSEIPDB_API_KEY=your-key
VirusTotal
Créer un compte sur https://www.virustotal.com
Générer une clé API
Ajouter à .env : VIRUSTOTAL_API_KEY=your-key
Règles personnalisées YARA
Ajouter des règles YARA dans config/yara/ :

rule SuspiciousBinary {
  meta:
    description = "Détecte binaires suspects"
    severity = "high"
  strings:
    $s1 = "CreateRemoteThread"
    $s2 = "WriteProcessMemory"
  condition:
    all of them
}
Recharger :

docker exec forenhive-api python -m app.enrichment.yara reload_rules
🔌 API
Documentation complète disponible via Swagger :

http://localhost:8000/docs

Points de terminaison principaux
Méthode	Endpoint	Description
POST	/auth/login	Authentification utilisateur
GET	/api/events	Lister événements honeypot
GET	/api/events/{id}	Détails événement
GET	/api/events/{id}/forensic	Analyse forensique
POST	/api/reports/generate	Générer rapport PDF
GET	/api/stats/summary	Statistiques globales
GET	/api/alerts	Lister alertes actives
POST	/api/alerts/{id}/resolve	Marquer alerte comme résolue
Schémas de réponse
Événement honeypot
{
  "id": "evt_12345",
  "timestamp": "2025-03-13T14:32:10.123Z",
  "source_ip": "203.0.113.45",
  "source_port": 54321,
  "target_port": 22,
  "honeypot_type": "cowrie",
  "protocol": "ssh",
  "payload": "ssh -l root -p 22 192.0.2.1",
  "geolocation": {
    "country": "Egypt",
    "city": "Cairo",
    "latitude": 30.0444,
    "longitude": 31.2357
  }
}
Analyse forensique
{
  "event_id": "evt_12345",
  "mitre": {
    "tactics": ["Reconnaissance"],
    "techniques": ["T1589.001"],
    "subtechniques": ["T1589.001.001"],
    "confidence": 0.94
  },
  "iocs": {
    "ips": ["203.0.113.45"],
    "hashes": ["a1b2c3d4e5f6..."],
    "domains": ["attacker.malicious.com"]
  },
  "timeline": [
    {
      "timestamp": "2025-03-13T14:32:10Z",
      "event": "Connection attempt SSH",
      "details": "Failed authentication attempt (root)"
    }
  ]
}
🧪 Tests
Lancer les tests unitaires
docker exec forenhive-api pytest tests/unit -v
Tests d'intégration
docker exec forenhive-api pytest tests/integration -v
Tests de performance
docker exec forenhive-api locust -f tests/load/locustfile.py
🐛 Dépannage
Elasticsearch n'est pas accessible
# Vérifier le statut
docker exec elasticsearch curl -s http://localhost:9200/_cluster/health | jq

# Vérifier les logs
docker logs elasticsearch
Ollama timeout
# Vérifier qu'Ollama est démarré
docker exec ollama ollama list

# Si non, recharger
docker restart ollama
docker exec ollama ollama pull mistral:7b
Erreur de connexion PostgreSQL
# Vérifier les credentials
docker exec postgres psql -U forenhive -d forenhive -c "SELECT 1"

# Migrations non appliquées
docker exec forenhive-api python -m alembic upgrade head
Logs complets
# API
docker logs -f forenhive-api

# Frontend
docker logs -f forenhive-frontend

# Pipeline
docker logs -f logstash
📚 Documentation supplémentaire
Architecture détaillée : voir docs/architecture.md
Spécification API : voir docs/api-spec.openapi.yaml
Guide d'enrichissement : voir docs/enrichment-guide.md
Mapping MITRE : voir docs/mitre-mapping.md
🤝 Contribuer
Les contributions sont bienvenues. Merci de :

Fork le dépôt
Créer une branche : git checkout -b feature/votre-feature
Commiter avec messages clairs : git commit -am 'Add feature X'
Push vers la branche : git push origin feature/votre-feature
Ouvrir une Pull Request avec description détaillée
Standards de code
Python : PEP 8 (linter : flake8)
JavaScript : ESLint + Prettier
Docstrings : Google style
Commits : Conventional Commits
Lancer la vérification locale :

make lint      # flake8 + black
make format    # auto-format code
make test      # exécuter tests
📜 Licence
Distribué sous licence MIT. Voir LICENSE pour plus de détails.

📞 Support & Contact
Équipe ForenHive

Zeineb Benrhouma : zeineb@isetrades.tn
Ismail Cherif : ismail@isetrades.tn
Superviseur PFE

Ghazi Oueslati (Tunisie Telecom)
Partenaire Industriel

Standard Sharing Software (3S), Charguia, Tunis
🙏 Remerciements
T-Pot Team pour l'orchestration honeypots
Elastic Stack pour ELK
Ollama pour l'inférence LLM locale
MITRE ATT&CK pour le référentiel tactiques/techniques
ISET Radès pour le support académique
Dernière mise à jour : Mars 2025
Version : 1.0.0
Statut : Production Candidate