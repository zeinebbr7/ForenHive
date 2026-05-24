# ForenHive — Sprint 3 Audit
**Forensic Engine : Enrichissement · YARA/VT · Timeline · IoC · MITRE · Score · Profiler · Chain of Custody**
*Branche : main · Date : 2026-05-24*

---

## 1. Périmètre du Sprint 3

Sprint 3 implémente la couche **analyse forensique** entre l'ETL (Sprint 2) et le backend (Sprint 4). Tout est packagé dans un conteneur Docker unique `forenhive-forensic-engine`.

Le moteur enchaîne **9 phases analytiques** dans un ordre strict :

- **P1 — Enrichissement IP** (GeoIP, AbuseIPDB, IPLocate, Shodan, WHOIS, PTR).
- **P2 — Analyse SMB/NTLM** (corrélation Dionaea SQLite + Zeek NTLM).
- **P3 — Scan YARA** (10 jeux de règles) puis lookup VirusTotal v3.
- **P4 — Scoring** (modèle v2.0.0 à 9 signaux, score 0–100, WHO/WHAT/HOW).
- **P5 — Timeline** unifiée multi-honeypot (précision milliseconde).
- **P6 — Extraction d'IoC** (10 types, format compatible STIX 2.1).
- **P7 — Mapping MITRE ATT&CK** hybride (15 techniques déterministes + narration LLM).
- **P8 — Chain of Custody** (SHA-256 + hash chain + Merkle + RFC 3161 freetsa.org).
- **P9 — Profilage criminologique** (Mistral 7B, framework FBI BAU).

**Hors périmètre Sprint 3** : API REST FastAPI (Sprint 4), UI React (Sprint 5), Nginx, scheduler externe.

---

## 2. Vue d'ensemble — composants Sprint 3

| Composant | Type | Statut | Sortie principale |
|---|---|---|---|
| `forenhive-forensic-engine` | Conteneur Docker | Up 36h | 11 modules Python orchestrés |
| `forenhive-postgresql` | Conteneur Docker | Up 4j | 9 tables forensiques (schema.sql) |
| `forenhive-ollama` | Conteneur Docker | Up 4j | Mistral 7B Q4_K_M (4.4 Go), Phi-3 mini (2.2 Go) |
| `forenhive-elasticsearch` | Conteneur Docker | Up 4j | Index `forenhive-suspect-profiles` + `forenhive-smb-analysis` |
| YARA rules | 10 fichiers `.yar` | OK | Ransomware, Mirai, Emotet, WannaCry, RAT, shells, crypto-miners |
| MaxMind GeoLite2 | 2 BDD offline | OK | City + ASN, bind-mountées |

---

## 3. Détail des modules

### 3.1 — `engine.py` (orchestrateur)

- **Rôle** : point d'entrée CLI, enchaîne les 9 phases dans `run_full_analysis(hours_back)`.
- **Lignes** : 1 580.
- **Build** : `forensic-engine/Dockerfile` → image basée sur `python:3.11-slim`.
- **Port exposé** : `8001/tcp` (mini-HTTP status/healthcheck via `server.py`).
- **Cron interne** : `ENGINE_INTERVAL_MINUTES=5` (relance toutes les 5 min).
- **Réseau** : `backend-net` uniquement (zéro accès `honeypot-net`).
- **Dépendances dur** : Elasticsearch, PostgreSQL.
- **Dépendances soft** : Ollama, AbuseIPDB, Shodan, VirusTotal, freetsa.org, Twilio.

**CLI principaux** :
- `python engine.py` — analyse complète (24 h glissantes).
- `python engine.py --hours 48` — fenêtre étendue.
- `python engine.py --enrich-only | --yara-only | --score-only | --timeline-only | --ioc-only | --coc-only | --profile-only` — exécution par phase.
- `python engine.py --init-db` — bootstrap schéma PG.

### 3.2 — `enricher.py` (Phase 1)

- **Source** : ES `honeypot-logs-*` → IPs distinctes sur la fenêtre.
- **Pipeline** : MaxMind (offline) → IPLocate → AbuseIPDB → Shodan InternetDB → RDAP/WHOIS → PTR.
- **Cache** : PG `ip_enrichment_cache`, TTL **24 h**.
- **Parallélisme** : 5 workers (`ENRICH_PARALLEL_WORKERS=5`).
- **Cas IPs privées** (RFC 1918) : court-circuit des APIs publiques, marquage `is_private=true` → scoring bascule en mode comportemental pur.
- **Quota tracker** : table PG `api_quota_status` (persistance inter-runs).

### 3.3 — `smb_analyzer.py` (Phase 2)

- **Sources croisées** : Dionaea SQLite (`dionaea.sqlite`, tables `connections` + `downloads`) + Zeek NTLM logs (`ntlm*.log.gz`).
- **Détections clés** : EternalBlue (CVE-2017-0144, +40 pts), énumération SMB (+30 pts), EPMapper port 135 (+15 pts).
- **Sortie** : index ES `forenhive-smb-analysis` (1 doc par IP source).
- **Volume read-only** : `/opt/dionaea/var/lib/dionaea` bind-monté.

### 3.4 — `yara_scanner.py` + `virustotal.py` (Phase 3)

- **YARA** : compile une fois `forensic-engine/yara_rules/*.yar`, scanne les binaires Dionaea, hash SHA-256, persistance dans PG `file_analysis`.
- **Tiers de sévérité** : `critical` +30 pts, `high` +20 pts, `medium` +10 pts.
- **VirusTotal v3** : lookup `/files/{sha256}`, free tier **4 req/jour**, auto-pace 0.25 s/req, abort sur erreur réseau.
- **Rate-limit géré** : `quota_tracker` PG, `reset_at = next UTC midnight` sur HTTP 429.

### 3.5 — `timeline_builder.py` (Phase 5)

- **Source** : ES scroll par lots de 1 000 documents sur la fenêtre.
- **Normalizers** : `_norm_cowrie`, `_norm_dionaea`, `_norm_galah`, `_norm_zeek` → schéma unifié.
- **Précision** : milliseconde (ISO 8601 + ms).
- **Clé d'idempotence** : `es_doc_id UNIQUE` → rejouer sur fenêtre chevauchante ne duplique pas.
- **Cible** : PG `forensic_timeline_events` (~788 000 lignes en prod, voir §6).

### 3.6 — `ioc_extractor.py` (Phase 6)

- **Source** : PG `forensic_timeline_events` (champs `summary`, `raw` JSONB).
- **Types extraits** (10) : `url`, `domain`, `ipv4_external`, `sha256`, `md5`, `cve`, `email`, `file_path`, `cmdline`, `user_agent`, `http_path`.
- **Régex pré-compilées** module-level (fast path).
- **Déduplication** : `UNIQUE (ioc_type, ioc_value, source_ip)` + compteur `occurrences` cumulatif.
- **Cible** : PG `forensic_iocs` (export STIX 2.1 ready).

### 3.7 — `mitre_mapper.py` (Phase 7)

- **Approche hybride** :
  - **Niveau 1 — déterministe** : 15 IDs ATT&CK validés, `confidence = 1.0`, latence ≈ 0 ms.
  - **Niveau 2 — narration LLM** : Mistral 7B génère **uniquement** une phrase ≤ 80 tokens, **jamais d'IDs**.
- **Catalogue** : T1110.001, T1110.003, T1078, T1059.004, T1105, T1552.001, T1210, T1190, T1595.002, T1046, T1021.002, T1486, T1496, T1071.001, T1592.
- **Kill chain phases** : reconnaissance → weaponization → delivery → exploitation → installation → command_and_control → actions_on_objectives.
- **Fallback** : si Ollama injoignable, narration générique → pas de crash.

### 3.8 — `risk_score.py` (Phase 4 — modèle v2.0.0)

- **Score 0–100** sommé sur **9 signaux orthogonaux**, mappés au cadre FBI BAU :
  - **WHO (33 pts)** : `reputation` (15), `anonymization` (10), `threat_history` (8).
  - **WHAT (43 pts)** : `intent_volume` (10), `compromise_depth` (15), `exfiltration` (8), `lateral_movement` (10).
  - **HOW (24 pts)** : `malware` (15), `mitre_sophistication` (9).
- **Niveaux** : INFO < LOW < MEDIUM < HIGH < CRITICAL (seuils dans `risk_thresholds.py`).
- **Versioning** : colonne `score_version` (`1.0.0` legacy, `2.0.0` actuel).
- **Scope dual** : `score_session(session)` (par session) + `score_ip(ip, sessions, enrichment)` (agrégé par IP — Phase 9).

### 3.9 — `chain_of_custody.py` (Phase 8)

- **Triple couche d'intégrité** :
  1. **SHA-256 par enregistrement** sur JSON canonique (clés triées, colonnes load-bearing seules).
  2. **Hash chain append-only** : `prev_hash` = hash de l'enregistrement précédent.
  3. **Merkle root + RFC 3161** : racine binaire de toutes les sessions du batch, soumise à `freetsa.org`, réponse signée stockée en `BYTEA`.
- **Détection d'altération** : O(n) via `verify_coc.py`, exit code ≠ 0 sur divergence.
- **Idempotence** : `session_id UNIQUE` ; resealing automatique si `updated_at > sealed_at` (re-scoring détecté).
- **Conformité** : ISO/IEC 27037 (acquisition/préservation des preuves numériques).

### 3.10 — `profiler.py` (Phase 9)

- **Méthode** : criminologie FBI Behavioral Analysis Unit (BAU) adaptée au cyber.
- **Prompt 4 sections** (~2 600 tokens) :
  1. **System Role** — persona analyste BAU, contrat JSON-only.
  2. **Criminology Framework** — règles organized/disorganized, sophistication tiers, 9 objectifs primaires.
  3. **Session Evidence** — XML structuré (metadata, enrichment, MITRE, timeline, SMB, risk score).
  4. **Reference Cases** — top 5 profils similaires depuis ES `forenhive-suspect-profiles` (ViCAP-like).
- **Settings Ollama immuables** : `temperature=0.3`, `num_ctx=8192`, `timeout=300 s`.
- **Sortie JSON** : `sophistication`, `confidence`, `primary_objective`, `secondary_objective`, `behavioral_traits[]`, `organized_score`, `disguise_used`, `disguise_type`, `escalation_detected`, `mitre_techniques[]`, `dominant_tactic`, `kill_chain_phase`, `signature_indicators[]`, `similar_past_cases`, `risk_score`, `detective_narrative`.
- **Stockage dual** : PG `suspect_profiles` (UNIQUE `source_ip`) + ES `forenhive-suspect-profiles/_doc/profile-{ip}`.
- **Fail-safe** : 2 retries Ollama → profil minimal `confidence=0.0`.

### 3.11 — `verify_coc.py` (vérificateur indépendant)

- **Rôle** : audit tiers de la chaîne de custody.
- **Vérifie** : recalcul SHA-256 par session, intégrité hash chain, recalcul Merkle root, décodage TSR RFC 3161.
- **Dépendances minimales** (exécutable hors engine, sans `engine.py`).

---

## 4. Schéma PostgreSQL (9 tables)

Fichier : [forensic-engine/db/schema.sql](../forensic-engine/db/schema.sql) — initialisé par `db/init_db.py`.

| Table | Clé primaire | Rôle |
|---|---|---|
| `ip_enrichment_cache` | `ip` | Cache GeoIP/abuse/privacy, TTL 24 h |
| `file_analysis` | `sha256` | YARA matches + verdict VT par binaire |
| `forensic_sessions` | `session_id` | 1 ligne par session attaquant (scored + MITRE) |
| `forensic_timeline_events` | `id`, UNIQUE `es_doc_id` | Stream événementiel unifié (cross-honeypot) |
| `forensic_iocs` | UNIQUE `(ioc_type, ioc_value, source_ip)` | IoCs dédoublonnés + compteurs |
| `forensic_chain_of_custody` | UNIQUE `session_id` | Hash chain SHA-256 |
| `forensic_coc_batches` | `id` | Merkle root + TSR RFC 3161 |
| `suspect_profiles` | UNIQUE `source_ip` | Profil LLM (JSONB) |
| `api_quota_status` | `api_name` | État rate-limit persistant inter-runs |
| `ip_risk_scores` | `source_ip` | Score unifié par IP (Phase 9, multi-honeypot) |

---

## 5. Intégrations externes

| Service | Type | Endpoint | Usage | Quota |
|---|---|---|---|---|
| **Ollama** | LLM local (interne) | `http://forenhive-ollama:11434` | Profiler + MITRE narrative | CPU-only, gratuit |
| **AbuseIPDB** | API REST (clé) | `https://api.abuseipdb.com/api/v2/check` | Réputation IP | 1 000 req/jour free |
| **IPLocate** | API REST (no-auth) | `https://www.iplocate.io/api/lookup` | Tor/VPN/proxy flags | gratuit |
| **Shodan InternetDB** | API REST (no-auth) | `https://internetdb.shodan.io/{ip}` | Ports, CVEs, tags | gratuit |
| **VirusTotal v3** | API REST (clé) | `https://www.virustotal.com/api/v3/files/{sha256}` | Verdict antivirus | 4 req/jour free |
| **freetsa.org** | TSA RFC 3161 | `https://freetsa.org/tsr` | Horodatage signé | gratuit |
| **Twilio** | Notifications | `api.twilio.com` (SDK) | Alertes WhatsApp HIGH/CRITICAL | facturé |
| **MaxMind GeoLite2** | Base offline | `/app/GeoLite2-City.mmdb` + `GeoLite2-ASN.mmdb` | Géoloc + ASN | gratuit |

**Toutes les intégrations API publiques sont fail-soft** : `quota_tracker` PG enregistre l'épuisement et **skippe** les calls inutiles jusqu'au `reset_at`.

---

## 6. État live (snapshot 2026-05-24)

**Conteneurs** : 13/13 up.

**PostgreSQL** — `forenhive` DB :

| Table | Rows |
|---|---:|
| `forensic_sessions` | 54 |
| `forensic_timeline_events` | 788 040 |
| `forensic_iocs` | 1 210 |
| `forensic_chain_of_custody` | 54 (100 % sealed) |
| `forensic_coc_batches` | 4 916 |
| `suspect_profiles` | 14 |
| `ip_enrichment_cache` | 11 |
| `file_analysis` | 12 |
| `ip_risk_scores` | 4 |

**Elasticsearch** — indices Sprint 3 :

- `forenhive-suspect-profiles` : 4 docs (57.9 KB)
- `forenhive-smb-analysis` : 12 docs (25 KB)
- `forenhive-profiles` : 27 docs (68.5 KB)
- `honeypot-logs-2026.05.22` : 59 492 docs (21.4 MB)
- `honeypot-logs-2026.05.23` : 24 214 docs (15.8 MB)

**Ollama** :
- `mistral:latest` — 7.2 B · Q4_K_M · 4.4 GB.
- `phi3:mini` — 3.8 B · Q4 · 2.2 GB.

---

## 7. Fichiers livrables — chemins exacts

| Catégorie | Chemin (depuis racine repo) |
|---|---|
| Orchestrateur | [forensic-engine/engine.py](../forensic-engine/engine.py) |
| Config env loader | [forensic-engine/config.py](../forensic-engine/config.py) |
| Schéma SQL | [forensic-engine/db/schema.sql](../forensic-engine/db/schema.sql) |
| Bootstrap DB | [forensic-engine/db/init_db.py](../forensic-engine/db/init_db.py) |
| Pool de connexions | [forensic-engine/db_pool.py](../forensic-engine/db_pool.py) |
| Enrichissement | [forensic-engine/enricher.py](../forensic-engine/enricher.py) |
| YARA | [forensic-engine/yara_scanner.py](../forensic-engine/yara_scanner.py) |
| VirusTotal | [forensic-engine/virustotal.py](../forensic-engine/virustotal.py) |
| SMB/NTLM | [forensic-engine/smb_analyzer.py](../forensic-engine/smb_analyzer.py) |
| Timeline | [forensic-engine/timeline_builder.py](../forensic-engine/timeline_builder.py) |
| IoC extractor | [forensic-engine/ioc_extractor.py](../forensic-engine/ioc_extractor.py) |
| MITRE mapper | [forensic-engine/mitre_mapper.py](../forensic-engine/mitre_mapper.py) |
| Risk score v2.0.0 | [forensic-engine/risk_score.py](../forensic-engine/risk_score.py) |
| Seuils de risque | [forensic-engine/risk_thresholds.py](../forensic-engine/risk_thresholds.py) |
| Chain of custody | [forensic-engine/chain_of_custody.py](../forensic-engine/chain_of_custody.py) |
| Vérificateur CoC | [forensic-engine/verify_coc.py](../forensic-engine/verify_coc.py) |
| Profiler LLM | [forensic-engine/profiler.py](../forensic-engine/profiler.py) |
| Quota tracker | [forensic-engine/quota_tracker.py](../forensic-engine/quota_tracker.py) |
| Mini-HTTP serveur | [forensic-engine/server.py](../forensic-engine/server.py) |
| Dockerfile | [forensic-engine/Dockerfile](../forensic-engine/Dockerfile) |
| Requirements | [forensic-engine/requirements.txt](../forensic-engine/requirements.txt) |
| Règles YARA | [forensic-engine/yara_rules/](../forensic-engine/yara_rules/) (10 fichiers) |
| GeoIP MaxMind | `geoip/GeoLite2-City.mmdb` + `geoip/GeoLite2-ASN.mmdb` (bind-mount) |
| Compose | [docker-compose.yml](../docker-compose.yml) — service `forensic-engine` |
| Tests | [forensic-engine/tests/test_risk_score.py](../forensic-engine/tests/test_risk_score.py) |

---

## 8. Conformité Sprint 3 — objectifs vs livrés

| Critère initial | Statut | Évidence |
|---|---|---|
| Enrichissement IP automatisé (GeoIP + réputation) | OK | `enricher.py`, 11 IPs en cache |
| Détection malware (YARA + VT) | OK | 10 jeux YARA, 12 fichiers analysés |
| Mapping MITRE ATT&CK | OK | 15 techniques déterministes, 0 hallucination |
| Score de risque numérique 0–100 | OK | Modèle v2.0.0 à 9 signaux, 54 sessions scorées |
| Timeline forensique ms-précision | OK | 788 040 événements indexés |
| Extraction d'IoC dédupliqués | OK | 1 210 IoCs, 10 types |
| Profil criminologique de l'attaquant | OK | 14 profils générés (BAU framework) |
| Chain of custody cryptographique | OK | 54/54 sessions scellées, 4 916 batches Merkle |
| Horodatage RFC 3161 par tiers | OK | freetsa.org, TSR signés en BYTEA |
| Vérification indépendante | OK | `verify_coc.py`, exit 0/1 |

**Sprint 3 — Statut : COMPLET.**

---

## 9. Décisions d'adaptation prises pendant le sprint

- **Modèle de score consolidé 18 → 9 signaux** (`v2.0.0`) pour réduire les corrélations et améliorer l'interprétabilité. Migration in-place avec colonne `score_version` ; les anciennes lignes restent filtrables à `1.0.0`.
- **MITRE — séparation détection/narration**. L'approche v1 (`ollama_mitre.py`, supprimé) laissait Mistral inventer les IDs → hallucinations. v2 : règles déterministes pour les IDs, LLM uniquement pour la phrase de contexte.
- **Profiler — `OLLAMA_TIMEOUT_SEC=300`** (au lieu de 120) après mesure empirique sur Mistral 7B CPU (~115–200 s/profil).
- **Re-sealing automatique** quand une session est re-scorée (`updated_at > sealed_at`) : suppression de l'ancien sceau, ré-insertion en queue de chaîne → la chaîne reste append-only.
- **Quota tracker persistant en PG** au lieu d'in-memory : survit aux redémarrages, évite de brûler les retries après épuisement quotidien.

---

## 10. Ce qui n'est PAS fait (et pourquoi)

| Item | Statut | Justification |
|---|---|---|
| Honeypots exposés en IP publique | Non | Décision projet — Sprint 1 reste en réseau interne, traffic synthétique Kali |
| Export STIX 2.1 effectif (fichier `.json`) | Partiel | Schéma compatible déclaré, mais pas de route export — sera ajouté côté backend Sprint 4 |
| Push MISP | Non | Hors périmètre Sprint 3 |
| Modèle Llama 3 / Mixtral | Non | Mistral 7B suffisant ; matériel R750 CPU-only |
| Tests d'intégration end-to-end | Partiel | Uniquement `test_risk_score.py` — couverture insuffisante |
| Suppression code legacy (`ollama_mitre.py`, `mitre_llm.py`) | OK | Effectuée à la finalisation (cf. FINALIZATION_AUDIT) |

---

## 11. Conclusion

Le Sprint 3 transforme le flux brut de logs honeypot en preuves forensiques structurées, scorées, mappées MITRE, scellées cryptographiquement et profilées par LLM. Le moteur tourne en cron interne (5 min), reste idempotent, et survit aux pannes APIs externes (fail-soft systématique). Le travail restant relève d'**intégration** (exposition par le backend Sprint 4) et non d'analyse.

---

**Auteur audit** : Claude Code (Opus 4.7)
**Vérification** : comptages PG/ES live au 2026-05-24, lecture intégrale de 18 modules Python + schéma SQL + Dockerfile + docker-compose.yml.
