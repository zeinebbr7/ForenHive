# Guide de démonstration ForenHive — Test end-to-end devant l'encadreur

> Ce guide enchaîne tous les tests : nettoyage → injection → enrichissement → MITRE → timeline → chaîne de garde → **profiling**.
> Durée totale : ~12 minutes. Tous les blocs sont copier-coller.

---

## 0. Pré-vol — vérifier que tout tourne

```bash
docker compose ps
```
Attendu : 10 conteneurs `Up` (cowrie, dionaea, galah, zeek, ollama, filebeat, logstash, elasticsearch, postgresql, forensic-engine-dev).

```bash
docker exec forenhive-ollama ollama list
curl -s http://localhost:8080/ -I | head -3
```
Attendu : `mistral:latest 4.4 GB` + Galah répond `HTTP/1.1 200 OK`.

---

## 0.5. IP publiques vs IP privées — ce qu'on attend à chaque étape

Ce guide injecte **3 IP publiques** (attaquants externes simulés) et **3 IP privées RFC 1918** (attaques internes, menaces latérales depuis le LAN). Chaque phase les traite différemment :

| Phase | IP publique (ex. `185.191.171.12`) | IP privée (ex. `10.0.50.25`) |
|---|---|---|
| **Logstash GeoIP** | pays + ville résolus | tag `_geoip_lookup_failure` |
| **Enricher (`ip_enrichment_cache`)** | ligne écrite : geo + AbuseIPDB + IPLocate | **aucune ligne** — classée `corporate_internal`, quotas non consommés |
| **Risk score** | signaux externes actifs (abuse, distance géo, ASN hébergeur) | signaux latéraux actifs (`private=true`, `network_class=corporate_internal`) |
| **MITRE mapping** | techniques Delivery / Initial Access | mêmes techniques, contexte mouvement latéral |
| **Profiling (Mistral)** | profil FBI-BAU complet avec attribution géo/ASN | profil généré, `detective_narrative` souligne l'origine RFC 1918 interne |

La valeur pédagogique : montrer que le moteur **détecte à la fois** les attaques externes (honeypot exposé) **et** les compromissions internes (menace latérale), avec la même pipeline.

---

## 1. Nettoyer les anciens logs et vider les bases

**Elasticsearch** (indices honeypot + forensique) :
```bash
curl -s -X PUT "http://localhost:9200/_cluster/settings" -H 'Content-Type: application/json' \
  -d '{"transient":{"action.destructive_requires_name":false}}'
curl -s -X DELETE "http://localhost:9200/honeypot-logs-*"
curl -s -X DELETE "http://localhost:9200/forenhive-*"
```

**PostgreSQL** (toutes les tables forensiques) :
```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
TRUNCATE forensic_timeline_events, forensic_chain_of_custody, forensic_coc_batches,
         forensic_iocs, forensic_sessions, file_analysis,
         ip_enrichment_cache, suspect_profiles, api_quota_status
RESTART IDENTITY CASCADE;"
```

**Fichiers de logs des honeypots** (via un conteneur Alpine jetable) :
```bash
docker run --rm \
  -v bb474ddc3d2a3f3026c85d4c2fe7f1c5723f2e68f8ba60a05e4c9bb4471292ce:/cowrie-var \
  -v dionaea_dionaea-logs:/dionaea-logs \
  -v forenhive_galah-logs:/galah-logs \
  -v forenhive_zeek-spool:/zeek-spool \
  alpine sh -c "
    find /cowrie-var/log/cowrie/ -name 'cowrie.json.*' -delete
    : > /cowrie-var/log/cowrie/cowrie.json
    : > /dionaea-logs/dionaea/dionaea.log
    : > /galah-logs/event_log.json
    find /zeek-spool/zeek/ -name '*.log' -exec truncate -s 0 {} \;
    echo 'Logs purgés'
  "
```

> **Note** : le volume Cowrie est anonyme (hash `bb474ddc...`). Si l'ID change après un `docker compose down -v`, retrouver le bon via `docker inspect forenhive-cowrie --format '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}'`.

```bash
docker compose restart filebeat logstash
```

**Vérification** :
```bash
curl -s "http://localhost:9200/_cat/indices?v"
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT COUNT(*) FROM forensic_sessions;
SELECT COUNT(*) FROM ip_enrichment_cache;
SELECT COUNT(*) FROM forensic_chain_of_custody;
SELECT COUNT(*) FROM suspect_profiles;"
```
Attendu : aucun index `honeypot-logs-*`, tous les counts à `0`.

---

## 2. Injecter 3 IPs publiques + 3 IPs privées dans chaque honeypot

```bash
docker run --rm \
  -v bb474ddc3d2a3f3026c85d4c2fe7f1c5723f2e68f8ba60a05e4c9bb4471292ce:/cowrie-var \
  -v dionaea_dionaea-logs:/dionaea-logs \
  -v forenhive_galah-logs:/galah-logs \
  -v forenhive_zeek-spool:/zeek-spool \
  alpine sh -c '
PUB="185.191.171.12 118.25.6.39 45.155.205.233"
PRIV="10.0.50.25 172.16.50.25 192.168.100.50"
ALL="$PUB $PRIV"
ISO=$(date -u +"%Y-%m-%dT%H:%M:%S.000Z")
DION=$(date -u +"%Y-%m-%d %H:%M:%S")
GAL=$(date -u +"%Y-%m-%d %H:%M:%S.000")
TS=$(date +%s)

i=1
for ip in $ALL; do
  sess=$(printf "sess%06d" $i)
  echo "{\"timestamp\":\"$ISO\",\"eventid\":\"cowrie.login.failed\",\"src_ip\":\"$ip\",\"dst_ip\":\"172.16.1.100\",\"dst_port\":2222,\"username\":\"root\",\"password\":\"admin123\",\"session\":\"$sess\",\"protocol\":\"ssh\",\"message\":\"login attempt [root/admin123] failed\",\"sensor\":\"forenhive\"}" >> /cowrie-var/log/cowrie/cowrie.json
  echo "[$DION] connection 0x7f123abcd accept/tcp/smbd [172.16.1.100:445->$ip:45678]" >> /dionaea-logs/dionaea/dionaea.log
  echo "{\"eventTime\":\"$GAL\",\"srcIP\":\"$ip\",\"srcPort\":54321,\"sensorName\":\"forenhive-galah\",\"port\":\"8080\",\"httpRequest\":{\"method\":\"GET\",\"request\":\"/admin/config.php\",\"userAgent\":\"Mozilla/5.0 Nmap\",\"sessionID\":\"gs-$ip\",\"protocolVersion\":\"HTTP/1.1\"},\"httpResponse\":{\"headers\":{\"Server\":\"Apache/2.4.29 (Ubuntu)\"}},\"responseMetadata\":{\"generationSource\":\"llm\",\"info\":{\"model\":\"mistral:latest\"}}}" >> /galah-logs/event_log.json
  echo "{\"ts\":$TS.123,\"uid\":\"C$((5000+i))\",\"id.orig_h\":\"$ip\",\"id.orig_p\":$((5000+i)),\"id.resp_h\":\"172.16.1.100\",\"id.resp_p\":445,\"proto\":\"tcp\",\"service\":\"smb\",\"duration\":1.234,\"orig_bytes\":150,\"resp_bytes\":320,\"conn_state\":\"SF\",\"history\":\"ShADdafF\"}" >> /zeek-spool/zeek/conn.log
  i=$((i+1))
done
echo "Injecté : 6 événements × 4 honeypots = 24"
'
```

**Attendre l'ingestion** (~15 s) puis :
```bash
sleep 20
curl -s "http://localhost:9200/honeypot-logs-*/_search?size=0" \
  -H 'Content-Type: application/json' \
  -d '{"aggs":{"hp":{"terms":{"field":"honeypot.type.keyword"}}}}' \
  | python3 -m json.tool
```
Attendu : `total.value = 24`, 6 docs pour chaque : cowrie, dionaea, galah, zeek.

---

## 3. Vérifier l'enrichissement GeoIP dans Elasticsearch (étape Logstash)

```bash
curl -s "http://localhost:9200/honeypot-logs-*/_search?size=30" | python3 -c "
import json, sys, ipaddress
r = json.load(sys.stdin)
print(f'{\"honeypot\":8s} | {\"ip\":17s} | {\"privé?\":6s} | {\"pays\":15s} | geo_fail')
print('-'*70)
rows = []
for h in r['hits']['hits']:
    s = h['_source']; hp = s.get('honeypot.type','?'); ip = s.get('source.ip','?')
    geo = s.get('source.geo',{}) or {}
    country = geo.get('geo',{}).get('country_name','') or geo.get('country_name','')
    fail = '_geoip_lookup_failure' in s.get('tags',[])
    try: priv = ipaddress.ip_address(ip).is_private
    except: priv = None
    rows.append((hp, ip, str(priv), country, fail))
for r in sorted(rows): print(f'{r[0]:8s} | {r[1]:17s} | {r[2]:6s} | {r[3]:15s} | {r[4]}')
"
```
Attendu :
- IPs publiques → pays renseigné (`China`, `United Kingdom`/`Netherlands`, `Germany`/`Russia`), `geo_fail=False`
- IPs privées (RFC 1918) → `geo_fail=True` (normal : pas de géo pour le privé)

---

## 4. Lancer le moteur forensique complet

```bash
docker exec forenhive-forensic-engine-dev python engine.py --hours 2 2>&1 | tail -40
```
Étapes attendues dans les logs :
1. **Phase 1 : IP Enrichment** — `Enriched 3 IPs` (les 3 publiques ; privées zappées)
2. **Phase 2a : YARA** — pas de binaires (injection synthétique)
3. **Phase 3 : Session Scoring + MITRE** — `MITRE [...] phase=Delivery|Lateral Movement llm=yes` × 18
4. **Phase 4 : Timeline** — `inserted 24 new events`
5. **Phase 5 : IoC** — `extracted 36 distinct IoCs`
6. **Phase 6 : Chain of custody** — `merkle_root=... TSA status=ok ... sealed 18 records in batch #1`
7. **Phase 7 : Profiling** — `Profiling complete — profiled=6, skipped=0`

Durée : ~7–8 min (Mistral ~18 s par session + ~18 s par profil).

---

## 5. Vérifier les enrichissements (AbuseIPDB, pays, Tor/VPN, privé)

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -t -c \
  "SELECT ip, data FROM ip_enrichment_cache ORDER BY ip;" | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    ip, _, rest = line.partition('|')
    try: d = json.loads(rest.strip())
    except: continue
    geo = d.get('geo',{}); rep = d.get('reputation',{}); priv = d.get('privacy',{})
    print(f'=== {ip.strip()} ===')
    print(f'  pays   : {geo.get(\"country\")} ({geo.get(\"country_code\")})')
    print(f'  ISP    : {rep.get(\"isp\")}')
    print(f'  AbuseIPDB score : {rep.get(\"abuse_score\")}/100 ({rep.get(\"total_reports\")} reports)')
    print(f'  Tor={priv.get(\"is_tor\")} VPN={priv.get(\"is_vpn\")} Proxy={priv.get(\"is_proxy\")}')
    print()
"
```
Attendu :
- `185.191.171.12` → Pays-Bas, SEMrush, **score 100/100, ~1900 reports**
- `118.25.6.39` → Chine, Tencent Cloud, score 7
- `45.155.205.233` → Allemagne, Cloud.ru, score 7
- Les 3 IPs privées **n'apparaissent pas** dans le cache (normal — l'enricher les classe comme `corporate_internal` sans consommer le quota AbuseIPDB).

**Détection attaque interne vs externe** :
```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT source_ip,
       enrichment_data->>'private' AS privée,
       enrichment_data->>'network_class' AS classe_réseau,
       enrichment_data->'geo'->>'country' AS pays,
       enrichment_data->'reputation'->>'abuse_score' AS abuse
FROM forensic_sessions WHERE honeypot_type='cowrie' ORDER BY source_ip;"
```
Attendu :
- IPs `10.*`, `172.16.*`, `192.168.*` → `privée=true, classe_réseau=corporate_internal` (**attaque vient de l'interne**)
- IPs publiques → `pays` et `abuse` renseignés

---

## 6. Vérifier Ollama Mistral + mapping MITRE ATT&CK

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT honeypot_type, source_ip, risk_score, kill_chain_phase, kill_chain_stage,
       primary_technique, left(forensic_narrative, 80) AS narratif
FROM forensic_sessions ORDER BY honeypot_type, risk_score DESC;"
```
Attendu :
- Cowrie/Galah → technique **T1190** (Exploit Public-Facing App), phase `delivery` (stage 3)
- Dionaea → technique **T1021.002** (SMB/Windows Admin Shares), phase `lateral_movement` (stage 7)
- Colonne `narratif` remplie = Mistral a bien généré le texte

---

## 7. Vérifier la timeline (précision ms, multi-sources)

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT ts, honeypot_type, source_ip, event_action, destination_port, summary
FROM forensic_timeline_events ORDER BY ts LIMIT 15;"
```
Attendu : 24 lignes au total, horodatage à la milliseconde, événements entrelacés Cowrie → Dionaea → Galah → Zeek.

---

## 8. Vérifier la chaîne de garde (hash SHA-256 + Merkle + TSA RFC 3161)

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT id AS batch, record_count, tsa_provider, tsa_status, tsa_time,
       left(merkle_root,16) AS merkle, octet_length(tsa_response) AS tsa_bytes
FROM forensic_coc_batches;"

docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT session_id, left(record_hash,16) AS hash, left(prev_hash,16) AS prev_hash
FROM forensic_chain_of_custody ORDER BY id LIMIT 5;"
```
Attendu :
- 1 batch avec `record_count=18`, `tsa_status=ok`, `tsa_provider=freetsa.org`, `tsa_bytes ≈ 4677`
- Chaque session a un `record_hash` SHA-256 unique et `prev_hash = record_hash précédent` (chaîne type blockchain)

**Vérification d'intégrité automatique** :
```bash
docker exec forenhive-forensic-engine-dev python verify_coc.py
```
Attendu : **`✓ chain intact — 18 records, 1 batch(es)`** (en vert).

---

## 8.5. Profiling (Phase 7 — Ollama/Mistral, méthodologie FBI-BAU)

Le profiler agrège toutes les sessions par IP source et demande à Mistral de produire un **profil comportemental** structuré (sophistication, objectifs, traits, MITRE, narratif type « détective »).

**Relancer uniquement le profiling** (si besoin de régénérer) :
```bash
docker exec forenhive-forensic-engine-dev python engine.py --profile-only --hours 24 2>&1 | tail -25
```
Attendu : `Profiling complete — profiled=6, skipped=0` (1 profil par IP distincte). **Durée : ~8 min** (Mistral sur CPU = 80–90 s par IP × 6 IPs).

> ⚠ Le flag `--hours` doit couvrir l'horodatage des sessions. Si les données datent de plus de 24 h, augmentez la fenêtre (ex. `--hours 168` pour une semaine).

**Liste des profils dans PostgreSQL** :
```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "
SELECT source_ip,
       risk_score,
       profile->>'sophistication' AS sophist,
       profile->>'confidence' AS conf,
       profile->>'dominant_tactic' AS tactique,
       profile->>'kill_chain_phase' AS phase,
       profile->>'disguise_type' AS disguise
FROM suspect_profiles ORDER BY risk_score DESC;"
```
Attendu : **6 lignes** (3 publiques + 3 privées).
- `185.191.171.12` doit sortir avec le `risk_score` le plus haut (AbuseIPDB 100/100).
- `sophist` ∈ {`amateur`,`intermediate`,`expert`,`unknown`}.
- IPs privées → `disguise=none`, `phase` typiquement `lateral_movement`.

**Profil complet pour une IP publique + une IP privée** :
```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -t -c \
  "SELECT source_ip, profile FROM suspect_profiles
   WHERE source_ip IN ('185.191.171.12','10.0.50.25');" | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    ip, _, rest = line.partition('|')
    try: d = json.loads(rest.strip())
    except: continue
    print(f'=== {ip.strip()} ===')
    print(f'  sophistication    : {d.get(\"sophistication\")} (confiance {d.get(\"confidence\")})')
    print(f'  objectif primaire : {d.get(\"primary_objective\")}')
    print(f'  objectif secondaire: {d.get(\"secondary_objective\")}')
    print(f'  traits            : {d.get(\"behavioral_traits\")}')
    print(f'  organisé          : {d.get(\"organized_score\")} | escalade={d.get(\"escalation_detected\")}')
    print(f'  disguise          : {d.get(\"disguise_type\")} (used={d.get(\"disguise_used\")})')
    print(f'  MITRE             : {d.get(\"mitre_techniques\")}')
    print(f'  tactique dominante: {d.get(\"dominant_tactic\")} | phase: {d.get(\"kill_chain_phase\")}')
    print(f'  cas similaires    : {d.get(\"similar_past_cases\")}')
    print(f'  récit détective   : {d.get(\"detective_narrative\")}')
    print()
"
```
Attendu :
- IP publique : `disguise` peut être `none`/`vpn`/`proxy` selon IPLocate ; narratif mentionne le pays et l'ISP.
- IP privée `10.0.50.25` : narratif souligne l'**origine interne RFC 1918** / hypothèse de poste compromis ou insider.

**Mémoire des profils indexée dans Elasticsearch** :
```bash
curl -s "http://localhost:9200/forenhive-suspect-profiles/_count" | python3 -m json.tool
curl -s "http://localhost:9200/forenhive-suspect-profiles/_search?size=1&pretty" | head -50
```
Attendu : `count.value = 6`. Cet index sert de **mémoire à long terme** (le profiler compare chaque nouvelle IP aux cas passés → section « SIMILAR PAST CASES » du prompt).

**Test d'idempotence** (relancer → pas de doublons, mise à jour) :
```bash
docker exec forenhive-forensic-engine-dev python engine.py --profile-only 2>&1 | tail -5
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c \
  "SELECT COUNT(*) AS profils, COUNT(DISTINCT source_ip) AS ips_uniques FROM suspect_profiles;"
```
Attendu : `profils = 6`, `ips_uniques = 6` (aucune duplication grâce à l'index unique sur `source_ip`), et `updated_at` rafraîchi.

---

## 9. Tableau récapitulatif à montrer à l'encadreur

| Composant | Test | Résultat attendu |
|---|---|---|
| **Honeypots** | Cowrie, Dionaea, Galah, Zeek running | `docker compose ps` = 10 Up |
| **ETL** | 24 événements ingérés | ES `honeypot-logs-*` = 24 docs |
| **GeoIP Logstash** | Publiques enrichies / Privées fail | `_geoip_lookup_failure` uniquement sur RFC 1918 |
| **AbuseIPDB** | SEMrush = 100/100 | `reputation.abuse_score=100, total_reports=1858` |
| **Détection interne** | 10.0.x, 172.16.x, 192.168.x | `private=true, network_class=corporate_internal` |
| **MITRE (Mistral)** | Techniques ATT&CK + narratif | T1190 (cowrie/galah), T1021.002 (dionaea), `llm=yes` |
| **Timeline** | Précision ms multi-sources | 24 events, triés sur `ts` |
| **Chain of custody** | Hash + Merkle + TSA | `verify_coc.py` : chain intact |
| **Profiler (Mistral)** | 6 profils FBI-BAU générés | `suspect_profiles` = 6 lignes, index ES `forenhive-suspect-profiles` = 6 docs, idempotent |

---

## Annexe — commandes de dépannage

```bash
# Logs d'un conteneur spécifique
docker logs -f forenhive-logstash --tail 50

# Relancer Galah si LLM bloque
docker compose restart galah ollama

# Vérifier quota AbuseIPDB/VirusTotal
docker exec forenhive-forensic-engine-dev python engine.py --quota-status

# Scanner seulement YARA (sans brûler quota VT)
docker exec forenhive-forensic-engine-dev python engine.py --yara-only

# Relancer uniquement le profiler (sans refaire MITRE/CoC)
docker exec forenhive-forensic-engine-dev python engine.py --profile-only

# Regarder un profil particulier en JSON brut
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c \
  "SELECT jsonb_pretty(profile) FROM suspect_profiles WHERE source_ip='185.191.171.12';"
```
