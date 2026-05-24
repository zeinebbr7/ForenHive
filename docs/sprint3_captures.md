# Sprint 3 — Écrans clés à capturer

Équivalent des "CAPTURE À VENIR" du chapitre 5, mais pour la **réalisation Sprint 3**.
Pour chaque étape (un composant = une étape numérotée), 3–4 captures à produire.

> **Convention chapitre 5** : `[CAPTURE À VENIR : <titre court> — <commande/écran>]`
> Réutiliser exactement cette syntaxe dans le LaTeX pour cohérence inter-chapitres.

---

## Étape 1 — Build et démarrage du conteneur `forensic-engine`

1. **Build de l'image Docker**
   - Commande : `docker compose build forensic-engine`
   - À capturer : sortie terminal complète montrant les étapes (apt-get → pip install yara-python → COPY → succès).
   - Placeholder : `[CAPTURE À VENIR : build de l'image forenhive-forensic-engine — docker compose build]`

2. **Démarrage du conteneur**
   - Commande : `docker compose up -d forensic-engine && docker compose logs -f forensic-engine | head -30`
   - À capturer : init du schéma PG, "Waiting for postgres ... ready", premier "Engine started, interval=5min".
   - Placeholder : `[CAPTURE À VENIR : démarrage et bootstrap PG — docker compose logs forensic-engine]`

3. **Conteneurs up — vue d'ensemble**
   - Commande : `docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"`
   - À capturer : les 13 conteneurs UP, dont `forenhive-forensic-engine 0.0.0.0:8001`.
   - Placeholder : `[CAPTURE À VENIR : état des conteneurs Sprint 3 — docker ps]`

4. **Healthcheck HTTP**
   - Commande : `curl -s http://localhost:8001/health | jq`
   - À capturer : JSON `{"status":"ok", "version":..., "phases":[...]}` (selon `server.py`).
   - Placeholder : `[CAPTURE À VENIR : healthcheck moteur — curl :8001/health]`

---

## Étape 2 — Phase 1 : Enrichissement IP

1. **Run isolé de la phase enrichissement**
   - Commande : `docker exec -it forenhive-forensic-engine python engine.py --enrich-only --hours 24`
   - À capturer : log "5 IPs to enrich → MaxMind / IPLocate / AbuseIPDB / Shodan / RDAP" + résultat par IP.
   - Placeholder : `[CAPTURE À VENIR : exécution enricher.py — --enrich-only --hours 24]`

2. **Cache PG `ip_enrichment_cache`**
   - Commande : `docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "SELECT ip, data->'geo'->>'country' country, data->'reputation'->>'abuse_score' abuse FROM ip_enrichment_cache ORDER BY cached_at DESC LIMIT 10;"`
   - À capturer : tableau IPs + pays + score AbuseIPDB.
   - Placeholder : `[CAPTURE À VENIR : cache d'enrichissement PG — ip_enrichment_cache]`

3. **Vérification quota tracker**
   - Commande : `docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "SELECT * FROM api_quota_status;"`
   - À capturer : tableau (vide ou avec entrées si VT/AbuseIPDB épuisés).
   - Placeholder : `[CAPTURE À VENIR : état des quotas APIs — api_quota_status]`

---

## Étape 3 — Phase 3 : Scan YARA + VirusTotal

1. **Compilation et listing des règles**
   - Commande : `ls -la forensic-engine/yara_rules/ && wc -l forensic-engine/yara_rules/*.yar`
   - À capturer : les 10 fichiers `.yar` avec leurs tailles.
   - Placeholder : `[CAPTURE À VENIR : règles YARA livrées — yara_rules/]`

2. **Run YARA**
   - Commande : `docker exec -it forenhive-forensic-engine python engine.py --yara-only`
   - À capturer : log "X fichiers Dionaea scannés, Y matches".
   - Placeholder : `[CAPTURE À VENIR : exécution scan YARA — --yara-only]`

3. **Résultats `file_analysis`**
   - Commande : `docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "SELECT sha256, yara_matches, analyzed_at FROM file_analysis ORDER BY analyzed_at DESC LIMIT 10;"`
   - À capturer : tableau hash + matches.
   - Placeholder : `[CAPTURE À VENIR : verdicts YARA en base — file_analysis]`

4. **Verdict VirusTotal**
   - Commande : `docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "SELECT sha256, virustotal_result->'data'->'attributes'->'last_analysis_stats' FROM file_analysis WHERE virustotal_result IS NOT NULL LIMIT 5;"`
   - À capturer : verdict VT (malicious/suspicious/harmless count).
   - Placeholder : `[CAPTURE À VENIR : verdict VirusTotal v3 — file_analysis]`

---

## Étape 4 — Phase 4 : Scoring + MITRE

1. **Run scoring complet**
   - Commande : `docker exec -it forenhive-forensic-engine python engine.py --score-only --hours 48`
   - À capturer : log par session avec `[LEVEL] honeypot Session XXX... IP=Y score=N [LATERAL] [delivery]`.
   - Placeholder : `[CAPTURE À VENIR : scoring 9 signaux v2.0.0 — --score-only --hours 48]`

2. **Top des sessions scorées**
   - Commande : `docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "SELECT source_ip, honeypot_type, risk_score, risk_level, primary_technique, kill_chain_phase FROM forensic_sessions ORDER BY risk_score DESC LIMIT 10;"`
   - À capturer : tableau IPs triées par risk_score.
   - Placeholder : `[CAPTURE À VENIR : sessions scorées — forensic_sessions]`

3. **Détail d'une session (signal breakdown)**
   - Commande : `docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "SELECT signal_breakdown FROM forensic_sessions WHERE risk_score >= 60 ORDER BY risk_score DESC LIMIT 1;"`
   - À capturer : JSON `signal_breakdown` avec ventilation des 9 signaux.
   - Placeholder : `[CAPTURE À VENIR : ventilation des 9 signaux pour une session HIGH — signal_breakdown JSONB]`

4. **MITRE techniques observées**
   - Commande : `docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "SELECT mitre_techniques, count(*) FROM forensic_sessions GROUP BY mitre_techniques ORDER BY count DESC LIMIT 10;"`
   - À capturer : techniques ATT&CK détectées sur le corpus.
   - Placeholder : `[CAPTURE À VENIR : distribution MITRE ATT&CK — mitre_techniques]`

---

## Étape 5 — Phase 5 + 6 : Timeline + IoC

1. **Run timeline**
   - Commande : `docker exec -it forenhive-forensic-engine python engine.py --timeline-only --hours 24`
   - À capturer : log "scrolled X docs from ES, inserted Y new rows in forensic_timeline_events".
   - Placeholder : `[CAPTURE À VENIR : construction timeline — --timeline-only]`

2. **Volume timeline (live)**
   - Commande : `docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "SELECT honeypot_type, event_category, count(*) FROM forensic_timeline_events GROUP BY 1,2 ORDER BY 3 DESC LIMIT 20;"`
   - À capturer : tableau croisé honeypot × catégorie d'événement.
   - Placeholder : `[CAPTURE À VENIR : volumétrie timeline — forensic_timeline_events]`

3. **Run IoC extraction**
   - Commande : `docker exec -it forenhive-forensic-engine python engine.py --ioc-only --hours 24`
   - À capturer : log "scanning N timeline events → M IoCs extracted".
   - Placeholder : `[CAPTURE À VENIR : extraction d'IoC — --ioc-only]`

4. **Top IoCs par type**
   - Commande : `docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "SELECT ioc_type, count(*) FROM forensic_iocs GROUP BY 1 ORDER BY 2 DESC;"`
   - À capturer : distribution par type (url, sha256, cmdline, cve…).
   - Placeholder : `[CAPTURE À VENIR : distribution des IoCs par type — forensic_iocs]`

---

## Étape 6 — Phase 8 : Chain of Custody

1. **Run sealing**
   - Commande : `docker exec -it forenhive-forensic-engine python engine.py --coc-only`
   - À capturer : log "N new + M re-scored sessions to seal → Merkle root=XXX → TSA freetsa.org → tsa_status=ok".
   - Placeholder : `[CAPTURE À VENIR : scellement chaîne de custody — --coc-only]`

2. **Hash chain (preuve d'intégrité)**
   - Commande : `docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "SELECT id, session_id, substring(record_hash,1,16) hash, substring(prev_hash,1,16) prev, batch_id FROM forensic_chain_of_custody ORDER BY id DESC LIMIT 10;"`
   - À capturer : tableau record_hash / prev_hash montrant le chaînage.
   - Placeholder : `[CAPTURE À VENIR : hash chain SHA-256 — forensic_chain_of_custody]`

3. **Merkle root + TSA**
   - Commande : `docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "SELECT id, substring(merkle_root,1,32) root, record_count, tsa_provider, tsa_status, tsa_time FROM forensic_coc_batches ORDER BY id DESC LIMIT 5;"`
   - À capturer : Merkle root + statut TSA (`ok` / `unavailable`).
   - Placeholder : `[CAPTURE À VENIR : Merkle + RFC 3161 — forensic_coc_batches]`

4. **Vérification indépendante**
   - Commande : `docker exec -it forenhive-forensic-engine python verify_coc.py`
   - À capturer : sortie verte "OK X sessions checked" + exit code 0.
   - Placeholder : `[CAPTURE À VENIR : vérification chaîne de custody — verify_coc.py]`

---

## Étape 7 — Phase 9 : Profiler LLM

1. **Modèles Ollama disponibles**
   - Commande : `docker exec forenhive-ollama ollama list`
   - À capturer : `mistral:latest 4.4 GB` + `phi3:mini 2.2 GB`.
   - Placeholder : `[CAPTURE À VENIR : modèles LLM chargés — ollama list]`

2. **Profilage d'une IP**
   - Commande : `docker exec -it forenhive-forensic-engine python profiler.py --ip 185.191.171.12`
   - À capturer : log "Calling Ollama for ... (prompt length: ~10kB)" puis JSON profile complet à la fin (sophistication, primary_objective, detective_narrative).
   - Placeholder : `[CAPTURE À VENIR : génération profil Mistral 7B — profiler.py --ip ...]`

3. **Profil persisté en PG**
   - Commande : `docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "SELECT source_ip, risk_score, profile->>'sophistication' sophist, profile->>'primary_objective' obj, profile->>'kill_chain_phase' phase FROM suspect_profiles ORDER BY risk_score DESC LIMIT 10;"`
   - À capturer : tableau IPs + sophistication + objectif primaire.
   - Placeholder : `[CAPTURE À VENIR : profils stockés en base — suspect_profiles]`

4. **Document ES `forenhive-suspect-profiles`**
   - Commande : `curl -s "http://localhost:9200/forenhive-suspect-profiles/_search?pretty&size=1"`
   - À capturer : document JSON complet (toutes les clés du schéma).
   - Placeholder : `[CAPTURE À VENIR : indexation profil dans Elasticsearch — forenhive-suspect-profiles]`

---

## Étape 8 — Run end-to-end complet

1. **Lancement analyse complète 24 h**
   - Commande : `docker exec -it forenhive-forensic-engine python engine.py --hours 24`
   - À capturer : bandeau d'ouverture `=== ForenHive Full Forensic Analysis (last 24h) ===` puis chaque "=== Phase N: ... ===" puis bandeau de fin avec `IPs enriched / Sessions scored / Timeline events / IoCs extracted / Custody sealed / TSA=ok`.
   - Placeholder : `[CAPTURE À VENIR : run forensique complet 9 phases — python engine.py --hours 24]`

2. **Tableau de bord Kibana (optionnel mais fort)**
   - Préparation : créer une dashboard "ForenHive — Sprint 3" avec 4 visualisations : risk_score histogram, MITRE techniques top 10, IPs par pays (carte), timeline events par honeypot.
   - À capturer : screenshot Kibana plein écran.
   - Placeholder : `[CAPTURE À VENIR : dashboard Kibana Sprint 3 — Kibana :5601]`

3. **Volumétrie globale en base**
   - Commande : `docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "SELECT 'sessions' tbl, count(*) FROM forensic_sessions UNION ALL SELECT 'timeline', count(*) FROM forensic_timeline_events UNION ALL SELECT 'iocs', count(*) FROM forensic_iocs UNION ALL SELECT 'coc', count(*) FROM forensic_chain_of_custody UNION ALL SELECT 'batches', count(*) FROM forensic_coc_batches UNION ALL SELECT 'profiles', count(*) FROM suspect_profiles;"`
   - À capturer : tableau récapitulatif (les 54 / 788 040 / 1 210 / 54 / 4 916 / 14 chiffres de l'audit §6).
   - Placeholder : `[CAPTURE À VENIR : volumétrie finale Sprint 3 — comptages PG]`

---

## Étape 9 — Section Test / Supervision (séparée)

Conformément au plan du rapport, la section "Test / Supervision" est **séparée** de la Réalisation. Captures dédiées :

1. **Tests unitaires `pytest`**
   - Commande : `docker exec -it forenhive-forensic-engine pytest tests/ -v`
   - À capturer : sortie verte avec liste des tests `test_risk_score.py`.
   - Placeholder : `[CAPTURE À VENIR : tests unitaires risk_score — pytest tests/]`

2. **Logs live (supervision)**
   - Commande : `docker compose logs --tail=50 forensic-engine`
   - À capturer : extrait représentatif d'une boucle cron 5 min (chaque ligne `[INFO] engine — ...`).
   - Placeholder : `[CAPTURE À VENIR : supervision logs moteur — docker compose logs]`

3. **Alerte WhatsApp (Twilio)**
   - Préparation : générer une session synthétique avec `risk_score >= 80` (CRITICAL).
   - À capturer : capture écran téléphone montrant le message WhatsApp `⚠️ ForenHive ALERTE IP : ... Risk Score : N/100 Niveau : CRITICAL`.
   - Placeholder : `[CAPTURE À VENIR : alerte WhatsApp Twilio sur session CRITICAL]`

---

## Récapitulatif — combien de captures par étape

| Étape | Captures à produire | Total |
|---|---|---:|
| 1. Conteneur engine | build, démarrage, docker ps, /health | 4 |
| 2. Enrichissement | run, cache PG, quotas | 3 |
| 3. YARA + VT | règles, run YARA, file_analysis, VT | 4 |
| 4. Scoring + MITRE | run, top sessions, breakdown, MITRE | 4 |
| 5. Timeline + IoC | run timeline, volumétrie, run IoC, types | 4 |
| 6. Chain of custody | run, hash chain, Merkle/TSA, verify | 4 |
| 7. Profiler LLM | ollama list, run profile, PG, ES | 4 |
| 8. End-to-end | run complet, Kibana, volumétrie globale | 3 |
| 9. Test / supervision | pytest, logs cron, alerte WhatsApp | 3 |
| **Total** | | **33** |

Le chapitre 5 (Sprint 1) cite ~12 captures ; le Sprint 3 est plus dense (3 fois plus de composants livrés) — viser entre 20 et 33 captures selon la place dans le PDF.
