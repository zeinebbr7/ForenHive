# Démo ForenHive — Runbook Encadrant (manuel, étape par étape)

**Testé en réel le 2026-04-19** — durée totale ≈ **12–13 min** (dont ~9 min pour l'engine).
Toutes les commandes sont à **copier/coller une par une** dans le terminal depuis `/home/pfe/ForenHive`.

> ⚠️ Le conteneur forensic-engine actif est **`forenhive-forensic-engine-dev`** (pas `forenhive-forensic-engine` qui est Exited).
> ⚠️ Quota **VirusTotal** = 4 req/jour. Si déjà consommé, l'engine skip VT, le reste tourne.

---

## Phase 0 — Pré-vol (30 sec)

```bash
docker compose ps --format 'table {{.Name}}\t{{.Status}}'
docker exec forenhive-ollama ollama list
```
**Attendu :** 9 conteneurs `Up` + `forenhive-forensic-engine-dev Up`. Ollama liste `mistral:latest` (4.4 GB).

> **À dire :** « Tous les conteneurs tournent, le LLM Mistral 7B est chargé en local, prêt pour l'analyse offline. »

---

## Phase 1 — Effacement complet (1 min)

### 1a. Elasticsearch
```bash
curl -s -X PUT "http://localhost:9200/_cluster/settings" -H 'Content-Type: application/json' \
  -d '{"transient":{"action.destructive_requires_name":false}}'
curl -s -X DELETE "http://localhost:9200/honeypot-logs-*"
curl -s -X DELETE "http://localhost:9200/forenhive-*"
curl -s "http://localhost:9200/_cat/indices?v"
```
**Attendu :** `{"acknowledged":true}` trois fois, puis aucune ligne `honeypot-logs-*` ni `forenhive-*`.

### 1b. PostgreSQL
```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c \
  "TRUNCATE forensic_timeline_events, forensic_chain_of_custody, forensic_coc_batches,
            forensic_iocs, forensic_sessions, file_analysis, ip_enrichment_cache,
            suspect_profiles, api_quota_status RESTART IDENTITY CASCADE;"
```
**Attendu :** `TRUNCATE TABLE`

### 1c. Fichiers logs des honeypots
```bash
COWRIE_VOL=$(docker inspect forenhive-cowrie --format '{{range .Mounts}}{{if eq .Destination "/cowrie/cowrie-git/var"}}{{.Name}}{{end}}{{end}}')
docker run --rm \
  -v $COWRIE_VOL:/cowrie-var \
  -v dionaea_dionaea-logs:/dionaea-logs \
  -v forenhive_galah-logs:/galah-logs \
  -v zeek_zeek-logs:/zeek-logs \
  alpine sh -c "
    find /cowrie-var/log/cowrie/ -name 'cowrie.json.*' -delete 2>/dev/null
    : > /cowrie-var/log/cowrie/cowrie.json
    : > /dionaea-logs/dionaea.log
    : > /dionaea-logs/dionaea-errors.log
    : > /galah-logs/event_log.json
    find /zeek-logs/current/ -name '*.log' -exec sh -c ': > {}' \; 2>/dev/null
    echo cowrie=\$(wc -l < /cowrie-var/log/cowrie/cowrie.json)
    echo dionaea=\$(wc -l < /dionaea-logs/dionaea.log)
    echo galah=\$(wc -l < /galah-logs/event_log.json)
  "
```
**Attendu :** `cowrie=0`, `dionaea=0`, `galah=0`.

### 1d. Reset du pipeline
```bash
docker compose restart filebeat logstash
```

> **À dire :** « J'efface tout : indices ES, tables PostgreSQL, fichiers logs honeypots. On repart d'un environnement propre. »

---

## Phase 2 — Vérification environnement vide (20 sec)

```bash
curl -s "http://localhost:9200/_cat/indices?v"

docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT 'sessions' AS t, COUNT(*) FROM forensic_sessions UNION ALL
SELECT 'timeline', COUNT(*) FROM forensic_timeline_events UNION ALL
SELECT 'iocs', COUNT(*) FROM forensic_iocs UNION ALL
SELECT 'coc_chain', COUNT(*) FROM forensic_chain_of_custody UNION ALL
SELECT 'coc_batches', COUNT(*) FROM forensic_coc_batches UNION ALL
SELECT 'ip_cache', COUNT(*) FROM ip_enrichment_cache;"
```
**Attendu :** aucun index `honeypot-logs-*` · toutes les tables = 0.

> **À dire :** « Zéro événement dans ES, zéro ligne dans PostgreSQL. Base propre. »

---

## Phase 3 — Injection attaques publiques + privée (1 min)

### 3a. 3 IPs publiques (active AbuseIPDB / GeoIP / TOR)
```bash
python3 scripts/inject_public_ip_scenario.py
```
Injecte :
- **185.220.101.45** — Tor exit (Allemagne, AbuseScore 97)
- **45.227.254.8** — Brute-forcer SSH (Panama)
- **193.32.162.157** — Scanner SMB/Mirai (Roumanie)

### 3b. 1 IP privée (interne Kali)
```bash
python3 scripts/inject_kali_scenario.py
```
Injecte **10.212.134.201** (10.0.0.0/8 → classée `corporate_internal`, pas d'appel API externe).

### 3c. Attendre l'ingestion Filebeat → Logstash → ES
```bash
until [ "$(curl -s 'http://localhost:9200/honeypot-logs-*/_search?size=0' \
  -H 'Content-Type: application/json' -d '{"track_total_hits":true}' \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["hits"]["total"]["value"])' 2>/dev/null)" -ge 50 ]; do
  sleep 3
done
echo "Ingestion OK"
```

### 3d. Vérifier répartition par IP
```bash
curl -s "http://localhost:9200/honeypot-logs-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d '{"aggs":{"by_ip":{"terms":{"field":"source.ip.keyword","size":20}}}}' \
  | python3 -c "
import json,sys
r=json.load(sys.stdin)
print('Total docs:', r['hits']['total']['value'])
for b in r['aggregations']['by_ip']['buckets']:
    print(f'  {b[\"key\"]:18s} -> {b[\"doc_count\"]}')"
```
**Attendu (réel) :** `Total docs: 54` · `185.220.101.45 → 17`, `10.212.134.201 → 17`, `45.227.254.8 → 14`, `193.32.162.157 → 6`.

> **À dire :** « 3 IPs publiques réelles (Tor, brute-forcer, scanner Mirai) + 1 IP interne Kali. 54 événements ingérés dans les 4 honeypots. »

---

## Phase 4 — Moteur forensique complet (≈ 9 min)

```bash
docker exec forenhive-forensic-engine-dev python engine.py --hours 2
```
Phases affichées par l'engine :
1. **Enrichissement IP** — AbuseIPDB + IPLocate + MaxMind GeoLite2-ASN
2. **YARA Scan** — binaires capturés Dionaea (synthétiques → 0 match, normal)
3. **Scoring + MITRE** — Mistral 7B via Ollama (≈ 18 sec par session)
4. **Timeline** — corrélation ms-precision entre honeypots
5. **Extraction IoCs** — URLs, domaines, users, commandes, hashes
6. **Chain of Custody** — hash SHA-256 + Merkle root + RFC 3161 freetsa.org
7. **Profiling LLM** — profil sophistication par IP (≈ 80 sec par IP)

**Attendu final :**
```
IPs enriched   : 4   (3 publiques cachées + 1 privée skippée)
Sessions scored: 8
Risk breakdown : CRITICAL=1 HIGH=2 MEDIUM=1 LOW=2 INFO=2
Timeline events: +54
IoCs extracted : 21
Custody sealed : 8 session(s), batch=#1, TSA=ok
Duration       : ~520s
```

> **À dire :** « L'engine enrichit les IPs publiques via 3 sources externes, scanne YARA, fait mapper chaque session à une technique MITRE ATT&CK par Mistral, construit la timeline, extrait les IoCs, puis scelle tout dans une chaîne de hashs horodatée par un TSA RFC 3161. »

---

## Phase 5 — Résultats forensiques (2 min de requêtes)

### 5a. Enrichissement IP (pays, ASN, score abuse, Tor, VPN)
```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT
  ip,
  data->'geo'->>'country'            AS country,
  data->'geo'->>'asn'                AS asn,
  data->'geo'->>'org'                AS org,
  data->'reputation'->>'abuse_score' AS abuse,
  data->'reputation'->>'is_tor'      AS is_tor,
  data->'privacy'->>'is_vpn'         AS is_vpn
FROM ip_enrichment_cache ORDER BY ip;"
```
**Attendu (observé) :**
```
       ip       | country |  asn   |          org           | abuse | is_tor | is_vpn
----------------+---------+--------+------------------------+-------+--------+--------
 185.220.101.45 | Germany | 200052 | Joshua Peter McQuistan |   97  |  true  |  false
 193.32.162.157 | Romania |  35478 | Bunea TELECOM SRL      |   35  |  false |  false
 45.227.254.8   | Panama  |  51852 | Private Layer INC      |    0  |  false |  false
```
> **Point clé :** l'IP privée **10.212.134.201 n'apparaît PAS** dans cette table → preuve que l'engine ne brûle pas de quota AbuseIPDB sur les IPs RFC 1918 (attaque interne).

### 5b. Sessions + score de risque + MITRE ATT&CK
```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT source_ip, honeypot_type, risk_score, kill_chain_phase, primary_technique
FROM forensic_sessions ORDER BY source_ip, honeypot_type;"
```
**Attendu (observé) :**
```
   source_ip    | honeypot_type | risk_score | kill_chain_phase | primary_technique
----------------+---------------+------------+------------------+-------------------
 10.212.134.201 | cowrie        |     40     | installation     | T1110.001
 10.212.134.201 | dionaea       |     20     | lateral_movement | T1021.002
 10.212.134.201 | galah         |     15     | delivery         | T1190
 185.220.101.45 | cowrie        |     94     | installation     | T1110.001   ← CRITICAL Tor
 185.220.101.45 | dionaea       |     74     | lateral_movement | T1021.002
 185.220.101.45 | galah         |     69     | delivery         | T1190
 193.32.162.157 | dionaea       |     34     | lateral_movement | T1021.002
 45.227.254.8   | cowrie        |     13     | exploitation     | T1110.001
```

### 5c. Timeline (ms-precision, multi-honeypots entrelacés)
```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT ts, honeypot_type, source_ip, event_action
FROM forensic_timeline_events ORDER BY ts LIMIT 12;"
```
Montre les connexions Tor + Kali entrelacées à la milliseconde près sur Cowrie/Dionaea/Galah.

### 5d. IoCs extraits
```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT ioc_type, ioc_value, occurrences FROM forensic_iocs
ORDER BY occurrences DESC LIMIT 15;"
```
**Observé :** 21 IoCs — URL `http://45.9.148.108/bins/mirai.x86`, commande `wget ... mirai.x86`, paths `/etc/passwd`, user agents de scanners, etc.

### 5e. Chain of custody (hash + RFC 3161 TSA)
```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT id, record_count, LEFT(merkle_root,24) AS merkle_head,
       tsa_provider, tsa_status, tsa_time
FROM forensic_coc_batches;"

docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT id, LEFT(session_id,22) AS session,
       LEFT(record_hash,16) AS hash, LEFT(prev_hash,16) AS prev
FROM forensic_chain_of_custody ORDER BY id;"
```
**Observé :** 1 batch, 8 sessions scellées, Merkle root `258ad8dcec1be2af…`, `tsa_provider=freetsa.org`, `tsa_status=ok`. Chaque record pointe vers le hash du précédent (Merkle chain).

### 5f. Vérification intégrité
```bash
docker exec forenhive-forensic-engine-dev python verify_coc.py
```
**Attendu :** `✓ chain intact — 8 records, 1 batch(es)` (en vert).

> **À dire :** « La chaîne de custody est cryptographiquement intacte : toute modification a posteriori casserait la chaîne et serait détectée. L'horodatage TSA freetsa.org prouve l'instant exact du scellement. »

---

## Phase 6 — Toutes les tables PostgreSQL

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "\dt"

docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT 'ip_enrichment_cache'       AS t, COUNT(*) FROM ip_enrichment_cache UNION ALL
SELECT 'file_analysis',                COUNT(*) FROM file_analysis UNION ALL
SELECT 'forensic_sessions',            COUNT(*) FROM forensic_sessions UNION ALL
SELECT 'forensic_timeline_events',     COUNT(*) FROM forensic_timeline_events UNION ALL
SELECT 'forensic_iocs',                COUNT(*) FROM forensic_iocs UNION ALL
SELECT 'forensic_chain_of_custody',    COUNT(*) FROM forensic_chain_of_custody UNION ALL
SELECT 'forensic_coc_batches',         COUNT(*) FROM forensic_coc_batches UNION ALL
SELECT 'api_quota_status',             COUNT(*) FROM api_quota_status UNION ALL
SELECT 'suspect_profiles',             COUNT(*) FROM suspect_profiles
ORDER BY t;"
```
**Observé :**
```
 api_quota_status          |  0
 file_analysis             |  1
 forensic_chain_of_custody |  8
 forensic_coc_batches      |  1
 forensic_iocs             | 21
 forensic_sessions         |  8
 forensic_timeline_events  | 54
 ip_enrichment_cache       |  3   ← 3 publiques, pas la privée
 suspect_profiles          |  4   ← 4 IPs profilées par Mistral
```

---

## Points clés à souligner à l'encadrant

1. **IP privée traitée différemment** — pas d'enrichissement externe (économie de quota, confidentialité).
2. **3 sources d'enrichissement** pour chaque IP publique : AbuseIPDB (réputation/score), IPLocate (TOR/VPN/proxy), MaxMind (ASN/pays/géo).
3. **Mapping MITRE ATT&CK** fait par **Mistral 7B local** (pas d'API cloud, offline).
4. **Timeline ms-precision** corrèle 3 honeypots (Cowrie/Dionaea/Galah) pour la même IP.
5. **Chain of custody RFC 3161** — Merkle root scellé par TSA public (freetsa.org) = preuve légale d'intégrité temporelle.
6. **Score 94/100 pour Tor** vs **13/100 pour un brute-forcer isolé** — le moteur discrimine correctement.

---

## Annexe — Troubleshooting rapide

| Symptôme | Cause | Fix |
|---|---|---|
| `forenhive-forensic-engine` exited | dev container à la place | utiliser `forenhive-forensic-engine-dev` |
| ES agg échoue sur `source.ip` | text field | utiliser `source.ip.keyword` |
| Timeline vide | Filebeat pas redémarré | `docker compose restart filebeat logstash` |
| AbuseIPDB quota dépassé | limite journalière | `engine.py --quota-reset abuseipdb` |
| VirusTotal skip | 4 req/jour seulement | normal — pas bloquant |

**Durée démo totale observée : ~12 min 30** (dont Phase 4 = 9 min, le reste est rapide).
