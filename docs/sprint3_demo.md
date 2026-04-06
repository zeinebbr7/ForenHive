# ForenHive — Guide de test manuel Sprint 2 + Sprint 3

**Branch:** `ismail2` | **Date:** 2026-04-06  
**Serveur:** `172.16.1.100` | **Répertoire:** `/home/pfe/ForenHive`

---

## Avant de commencer — état des services

```bash
cd /home/pfe/ForenHive
docker compose ps --format "table {{.Name}}\t{{.Status}}"
```

Tout doit être `Up`. Si `forenhive-forensic-engine` est en `Restarting` c'est **normal** — il tourne en boucle.

---

## PARTIE 1 — Sprint 2 : Pipeline ETL

### 1.1 Elasticsearch est vivant ?

```bash
curl -s http://localhost:9200/_cluster/health | python3 -m json.tool
```

**Attendu :** `"status": "yellow"` ou `"green"`

---

### 1.2 Combien d'événements dans le pipeline ?

```bash
curl -s "http://localhost:9200/honeypot-logs-*/_count" | python3 -m json.tool
```

**Attendu :** `"count": > 1000`

---

### 1.3 Répartition par honeypot

```bash
curl -s "http://localhost:9200/honeypot-logs-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 0,
    "aggs": {
      "par_honeypot": {
        "terms": { "field": "honeypot.type.keyword", "size": 10 }
      }
    }
  }' | python3 -c "
import sys, json
r = json.load(sys.stdin)
for b in r['aggregations']['par_honeypot']['buckets']:
    print(f\"  {b['key']:15s} → {b['doc_count']:,} events\")
"
```

---

### 1.4 Les champs ECS sont bien là ?

```bash
for field in "source.ip" "event.id" "honeypot.type" "source.geo.location"; do
  count=$(curl -s "http://localhost:9200/honeypot-logs-*/_count" \
    -H 'Content-Type: application/json' \
    -d "{\"query\":{\"exists\":{\"field\":\"$field\"}}}" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])")
  echo "  $field → $count docs"
done
```

---

### 1.5 Dernier événement reçu (pipeline toujours actif ?)

```bash
curl -s "http://localhost:9200/honeypot-logs-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":1,"sort":[{"@timestamp":"desc"}],"_source":["@timestamp","honeypot.type","event.id","source.ip"]}' \
  | python3 -c "import sys,json; h=json.load(sys.stdin)['hits']['hits'][0]['_source']; print(json.dumps(h, indent=2))"
```

---

### 1.6 Voir un événement Cowrie complet

```bash
curl -s "http://localhost:9200/honeypot-logs-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":1,"query":{"term":{"honeypot.type.keyword":"cowrie"}}}' \
  | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin)['hits']['hits'][0]['_source'], indent=2))"
```

---

### 1.7 Logstash traite encore des événements ?

```bash
docker logs forenhive-logstash --tail 5
```

**Attendu :** des lignes avec `events.in` / `events.out` ou des filtres actifs.

---

## PARTIE 2 — Sprint 3 : Forensic Engine

### 2.1 Scanner YARA uniquement (rapide, offline)

```bash
docker compose run --rm forensic-engine python engine.py --yara-only
```

**Attendu :**
```
[INFO] yara_scanner — Compiled 6 YARA rule files
[INFO] yara_scanner — Scanning 2 Dionaea binary files ...
[INFO] yara_scanner — MATCH [1bb736b97b...] → ['CryptoMiner_XMRig', 'WannaCry_Ransomware']
[INFO] yara_scanner — YARA scan complete: 1/2 files flagged
```

---

### 2.2 Vérifier le résultat YARA dans PostgreSQL

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT
  sha256,
  jsonb_array_length(yara_matches) AS yara_hits,
  yara_matches->0->>'rule' AS first_rule,
  yara_matches->1->>'rule' AS second_rule,
  analyzed_at
FROM file_analysis
ORDER BY yara_hits DESC NULLS LAST;
"
```

---

### 2.3 Enrichissement IP uniquement (AbuseIPDB + Shodan + IPLocate)

```bash
docker compose run --rm forensic-engine python engine.py --enrich-only --hours 48
```

Voir les IPs enrichies :

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT
  ip,
  data->'reputation'->>'abuse_score'   AS abuse,
  data->'infrastructure'->>'machine_type' AS machine,
  data->'infrastructure'->>'org'       AS org,
  data->'privacy'->>'is_tor'           AS tor,
  data->'geo'->>'country'              AS country
FROM ip_enrichment_cache
ORDER BY (data->'reputation'->>'abuse_score')::int DESC NULLS LAST;
"
```

---

### 2.4 Tester Shodan manuellement sur une IP

```bash
docker compose run --rm forensic-engine python3 -c "
import sys; sys.path.insert(0,'.')
import config, json
from enricher import _shodan_lookup

ip = '185.220.101.45'   # remplace par une IP de tes logs
result = _shodan_lookup(ip)
print(json.dumps(result, indent=2, default=str))
"
```

**Ce que tu dois voir :**
```json
{
  "machine_type": "vps",        ← type de machine
  "open_ports": [22, 80, 443],  ← ports exposés
  "services": [
    {"port": 22, "product": "OpenSSH", "version": "8.9"},
    {"port": 80, "product": "nginx"}
  ],
  "org": "DigitalOcean",
  "tags": ["self-signed"],
  "vulns": ["CVE-2023-XXXX"]
}
```

---

### 2.5 Tester AbuseIPDB manuellement

```bash
docker compose run --rm forensic-engine python3 -c "
import sys; sys.path.insert(0,'.')
import config, json
from enricher import _abuseipdb_lookup

result = _abuseipdb_lookup('185.220.101.45')
print(json.dumps(result, indent=2))
"
```

**Attendu :** `abuse_score: 100`, `total_reports: > 50`

---

### 2.6 VirusTotal sur un SHA-256

```bash
docker compose run --rm forensic-engine python3 -c "
import sys; sys.path.insert(0,'.')
from virustotal import VirusTotalScanner
import json

vt = VirusTotalScanner()
# EICAR — toujours détecté par tous les AV
result = vt.lookup_hash('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f')
print(json.dumps(result, indent=2, default=str))
"
```

**Attendu :** `"detection_ratio": "67/69"`, `"family": "virus"`

---

### 2.7 Analyse complète (tout en même temps)

```bash
docker compose run --rm forensic-engine python engine.py --hours 24
```

Attendre la fin (~5-30s selon le nombre d'IPs), puis lire le résumé :

```
====== Analysis Complete ======
  IPs enriched  : X
  Sessions scored: X
  Risk breakdown : CRITICAL=X HIGH=X MEDIUM=X
  Duration       : X.Xs
```

---

### 2.8 Voir les sessions forensiques scorées

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT
  session_id,
  source_ip,
  risk_score,
  honeypot_type,
  started_at
FROM forensic_sessions
ORDER BY risk_score DESC
LIMIT 10;
"
```

Sessions par niveau de risque :

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT
  CASE
    WHEN risk_score >= 80 THEN 'CRITICAL'
    WHEN risk_score >= 60 THEN 'HIGH'
    WHEN risk_score >= 40 THEN 'MEDIUM'
    WHEN risk_score >= 20 THEN 'LOW'
    ELSE 'INFO'
  END AS level,
  COUNT(*) AS sessions
FROM forensic_sessions
GROUP BY level
ORDER BY MIN(risk_score) DESC;
"
```

---

### 2.9 Voir l'enrichissement complet d'une IP

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT ip, jsonb_pretty(data) FROM ip_enrichment_cache LIMIT 1;
"
```

---

### 2.10 Vider le cache et forcer un ré-enrichissement

```bash
# Supprimer le cache (il sera refait au prochain run)
docker exec forenhive-postgresql psql -U forenhive -d forenhive \
  -c "DELETE FROM ip_enrichment_cache;"

# Relancer l'analyse
docker compose run --rm forensic-engine python engine.py --enrich-only --hours 24
```

---

## PARTIE 3 — Suite de tests automatique (51/53)

```bash
docker run --rm \
  --network=backend-net \
  --env-file .env \
  -e PG_HOST=forenhive-postgresql \
  -e PG_PASSWORD=forenhive_dev \
  -e ES_HOST=forenhive-elasticsearch \
  -e ABUSEIPDB_KEY=$(grep ABUSEIPDB_API_KEY .env | cut -d= -f2) \
  -e SHODAN_KEY=$(grep ^SHODAN_KEY .env | cut -d= -f2) \
  -e VIRUSTOTAL_KEY=$(grep VIRUSTOTAL_API_KEY .env | cut -d= -f2) \
  -v /home/pfe/ForenHive/forensic-engine:/app \
  -v /home/pfe/ForenHive/malware-samples/binaries:/test-binaries:ro \
  forenhive-forensic-engine:latest \
  python /app/tests/test_all.py
```

**Résultat attendu :** `51/53 PASS — Score 96%`  
Les 2 FAIL restants sont le GeoIP MaxMind (`.mmdb` non monté dans ce one-shot).

---

## Résumé des commandes clés

| Quoi tester | Commande |
|---|---|
| Services actifs | `docker compose ps` |
| Events dans ES | `curl localhost:9200/honeypot-logs-*/_count` |
| YARA scan | `docker compose run --rm forensic-engine python engine.py --yara-only` |
| Enrichissement IP | `docker compose run --rm forensic-engine python engine.py --enrich-only` |
| Analyse complète | `docker compose run --rm forensic-engine python engine.py --hours 24` |
| Tables PostgreSQL | `docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "\dt"` |
| Sessions scorées | `SELECT * FROM forensic_sessions ORDER BY risk_score DESC LIMIT 10` |
| Suite de tests auto | `docker run ... forenhive-forensic-engine python /app/tests/test_all.py` |
