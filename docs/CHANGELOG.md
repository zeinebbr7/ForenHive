# CHANGELOG

Toutes les modifications notables sont consignées ici, dans l'ordre
chronologique inverse (le plus récent en haut).

---

## Finalisation pré-soutenance — `chore/finalization-cleanup` (mai 2026)

- **Phase 1** — Nettoyage : `chatbot/` archivé (prototype standalone non
  utilisé en prod), caches Python dé-trackés (27 fichiers), `package-lock.json`
  racine vide supprimé, `.gitignore` consolidé.
- **Phase 2** — Outillage : `pyproject.toml` + `requirements-dev.txt` pour
  ruff (dev-only). `ruff format` + `ruff check --fix --unsafe-fixes`
  appliqués (45 fichiers reformatés, 588 issues auto-corrigées).
- **Phase 3** — Documentation : docstrings français exhaustifs sur les 11
  modules du forensic-engine, les 12 routers FastAPI, le SPA `app.js` et
  `docker-compose.yml`.
- **Phase 4** — Docs : `README.md` réécrit (4 couches / 4 sprints), création
  de `docs/architecture.md`, `docs/deployment.md`, `docs/forensic-engine.md`,
  `docs/api.md`, `docs/CHANGELOG.md`. `.env.example` enrichi.
- **Phase 5** — Vérifications : imports Python sains, `docker compose config`
  valide, aucune référence orpheline, token SPA cohérent.

---

## Sprint 4 — Backend + Frontend + Reporting (avril 2026)

- Backend FastAPI complet : 13 routers (auth, chat, sessions, attacks, geo,
  alerts, profiling, reports, risk_score, forensics, honeypots, audit, …).
- SPA Vite/React avec partiels HTML chargés dynamiquement, JWT Bearer auto
  (clé `forenhive.token`), 18 pages (dashboard, alerts, timeline,
  reconstruction, evidence, profiling, geomap, reporting, …).
- Rapports PDF WeasyPrint bilingues (EN + FR) à partir de
  `forenhive_rapport_v2.html` / `_fr.html`, `StrictUndefined` Jinja2 pour
  détecter immédiatement tout champ manquant.
- Export STIX 2.1 (Indicator + Observed-Data + Relationship SDOs).
- Alertes email + Twilio (SMS + WhatsApp).
- Nginx servant la SPA sur HTTP:3000.

## Sprint 3 — Forensic Engine (mars 2026)

- 11 modules Python orchestrés par `engine.py` (cron 5 min).
- Enrichissement IP multi-source : MaxMind GeoLite2 + AbuseIPDB + Shodan
  InternetDB + IPLocate + RDAP/Whois + PTR reverse DNS.
- Scan YARA tiered (CRITICAL/HIGH/MEDIUM) sur payloads Dionaea.
- VirusTotal lookup avec `quota_tracker` (réinit UTC midnight).
- Analyseur SMB : corrélation Dionaea SQLite + Zeek NTLM (EternalBlue,
  EPMapper, énumération).
- Timeline ms-précision multi-honeypot.
- Extracteur IoCs (9 types) compatible STIX 2.1.
- Mapping MITRE ATT&CK hybride : déterministe (15 IDs, confidence=1.0) +
  narration Mistral (≤ 80 tokens, jamais de nouveaux IDs).
- Risk Score v2.0.0 — 9 signaux (WHO 33 / WHAT 43 / HOW 24) — remplace le
  modèle v1 à 18 signaux (corrélations trop élevées).
- Suspect Profiler BAU : prompt 4 sections (~2600 tokens), mémoire ES
  (analogie ViCAP), 9+1 concepts criminologiques mappés au cyber.
- Chaîne de Custody : SHA-256 + RFC 3161 (freetsa.org + fallbacks),
  conforme ISO/IEC 27037.

## Sprint 2 — Pipeline ETL (février 2026)

- Filebeat → Logstash:5044 → Elasticsearch:9200.
- Normalisation ECS, parsing grok, enrichissement GeoIP MaxMind.
- 11,4 M+ événements indexés en pré-production.
- Indices journaliers `honeypot-logs-YYYY.MM.dd`.

## Sprint 1 — Honeypots (janvier 2026)

- Cowrie (SSH:2222, Telnet:2223) avec honeytokens et FS factice.
- Dionaea sur 11 protocoles (SMB, MSSQL, HTTP, MQTT, MySQL, FTP, …).
- Galah (HTTP:8080/8888) avec Mistral 7B pour réponses dynamiques.
- Zeek (host network) capture passive sur `eno12399`.
- Isolation réseau via `honeypot-net` (sans accès au backend).
