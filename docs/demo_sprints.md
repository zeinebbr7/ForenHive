# ForenHive — Démonstration Sprint 1 & Sprint 2

**PFE 2025/2026 — ISET Radès, spécialité RSI**
**Étudiantes :** Zeineb Benrhouma & Ismail Cherif
**Entreprise d'accueil :** Standard Sharing Software (3S), Charguia, Tunis
**Serveur :** Dell PowerEdge R750 · Ubuntu 24.10 · 172.16.1.100

---

## Vue d'ensemble du projet

ForenHive est une plateforme automatisée d'analyse forensique basée sur des honeypots.
L'architecture est organisée en 5 couches :

```
C1 Honeypots  →  C2 Pipeline ETL  →  C3 Moteur Forensique  →  C4 Backend  →  C5 Interface
   (Sprint 1)      (Sprint 2)           (Sprint 3)             (Sprint 3)     (Sprint 3)
```

**Stockage dual :** Elasticsearch (logs d'attaques) + PostgreSQL (utilisateurs / rapports)

---

## Sprint 1 — Honeypots

### Objectif

Déployer 4 honeypots qui simulent des services vulnérables pour attirer et capturer du trafic malveillant.

### Conteneurs déployés

| Conteneur | Rôle | Ports exposés |
|---|---|---|
| `forenhive-cowrie` | Honeypot SSH/Telnet — simule un serveur Linux | 2222 (SSH), 2223 (Telnet) |
| `forenhive-dionaea` | Honeypot multi-protocoles — capture malwares | 80, 445 (SMB), 3306 (MySQL), 1433 (MSSQL), 1883 (MQTT)… |
| `forenhive-galah` | Honeypot web LLM — génère des réponses HTTP réalistes via IA | 8080, 8888 |
| `forenhive-zeek` | Analyseur réseau passif — capture tout le trafic réseau | interface hôte |
| `forenhive-ollama` | Serveur LLM local — Mistral 7B pour Galah | interne |

### Ce que chaque honeypot fait

**Cowrie** — imite un vrai serveur SSH nommé `db-prod` (serveur de base de données fictif).
Toute tentative de connexion SSH est acceptée avec les credentials définis dans `userdb.txt`.
Les commandes tapées par l'attaquant sont enregistrées dans un journal JSON.

**Dionaea** — imite 11 protocoles réseau simultanément (SMB, MySQL, MSSQL, HTTP, MQTT…).
Il capture les tentatives d'exploitation et télécharge les binaires malveillants envoyés.
Il se présente comme `WIN-SERVER2019` sur le réseau SMB.

**Galah** — honeypot web intelligent. Chaque requête HTTP est envoyée à Mistral 7B (via Ollama)
qui génère une réponse HTML réaliste (page de login, 404, formulaire admin…).
Les attaquants croient interagir avec un vrai serveur web.

**Zeek** — analyseur passif. Il n'interagit pas avec les attaquants mais observe tout le trafic
réseau de l'interface `eno12399` et génère des logs structurés (`conn.log`, `ssh.log`, `http.log`).

---

### Commandes de test — Sprint 1

#### Étape 0 — Vérifier que tous les conteneurs tournent

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```
**Résultat attendu :** 9 conteneurs avec statut `Up`

---

#### Étape 1 — Tester Cowrie SSH

```bash
# Connexion avec un credential valide (doit accepter et donner un faux shell)
ssh -p 2222 -o StrictHostKeyChecking=no root@172.16.1.100
# mot de passe : root
```
**Résultat attendu :** prompt `root@db-prod:~#` (faux shell Cowrie)

```bash
# Connexion avec un mauvais mot de passe (doit refuser)
ssh -p 2222 -o StrictHostKeyChecking=no root@172.16.1.100
# mot de passe : mauvais_mdp
```
**Résultat attendu :** `Permission denied`

```bash
# Vérifier que l'événement est écrit dans le log Cowrie
docker exec forenhive-cowrie python3 -c "
with open('/cowrie/cowrie-git/var/log/cowrie/cowrie.json') as f:
    lines = f.readlines()
    for l in lines[-3:]: print(l.strip())
"
```
**Résultat attendu :** lignes JSON avec `cowrie.login.success` ou `cowrie.login.failed`

---

#### Étape 2 — Tester Cowrie Telnet

```bash
telnet 172.16.1.100 2223
# login : root
# mot de passe : root
```
**Résultat attendu :** prompt `root@db-prod:~#`

---

#### Étape 3 — Tester Dionaea

```bash
# Test SMB — Dionaea se présente comme WIN-SERVER2019
smbclient -L //172.16.1.100 -N
```
**Résultat attendu :** liste de partages ADMIN$, C$, IPC$ avec identité WIN-SERVER2019

```bash
# Test HTTP port 80
curl -s http://172.16.1.100:80/
```
**Résultat attendu :** réponse HTTP (quelconque)

```bash
# Vérifier que Dionaea écrit dans son log
docker exec forenhive-dionaea python3 -c "
with open('/opt/dionaea/var/log/dionaea/dionaea.log', encoding='utf-8', errors='replace') as f:
    lines = f.readlines()
    for l in lines[-3:]: print(l.strip())
"
```
**Résultat attendu :** lignes de log récentes (horodatage du jour)

---

#### Étape 4 — Tester Galah (honeypot web IA)

```bash
# Requête normale
curl -s http://172.16.1.100:8080/
```
**Résultat attendu :** page HTML générée par Mistral 7B (homepage, login, etc.)

```bash
# Chemin suspect — Galah génère une réponse convaincante
curl -s http://172.16.1.100:8080/wp-admin/
curl -s http://172.16.1.100:8080/.env
```
**Résultat attendu :** réponses HTML réalistes adaptées au chemin demandé

```bash
# Vérifier le log Galah
docker exec forenhive-galah sh -c 'wc -l /app/logs/event_log.json'
```
**Résultat attendu :** nombre de lignes > 0 (chaque requête = 1 ligne JSON)

---

#### Étape 5 — Tester Zeek

```bash
# Vérifier que Zeek tourne
docker exec forenhive-zeek zeekctl status
```
**Résultat attendu :** `zeek   standalone   localhost   running`

```bash
# Vérifier les fichiers de logs en cours d'écriture
docker exec forenhive-zeek ls -lh /usr/local/zeek/logs/current/
```
**Résultat attendu :** `conn.log`, `ssh.log`, `http.log` avec horodatage récent

---

## Sprint 2 — Pipeline ETL

### Objectif

Collecter automatiquement tous les logs des honeypots, les normaliser au standard ECS
(Elastic Common Schema), les enrichir géographiquement, et les stocker dans Elasticsearch.

### Architecture du pipeline

```
[Cowrie JSON log]  ──┐
[Dionaea text log] ──┤
[Galah JSON log]   ──┤──► Filebeat ──► Logstash ──► Elasticsearch
[Zeek conn/ssh/http]─┘     (port 5044)   (filtre ECS)  (index journalier)
```

### Conteneurs déployés

| Conteneur | Rôle |
|---|---|
| `forenhive-filebeat` | Lit les fichiers de logs et les envoie à Logstash |
| `forenhive-logstash` | Normalise les champs, enrichit GeoIP, route par honeypot |
| `forenhive-elasticsearch` | Stocke les événements, indices journaliers `honeypot-logs-YYYY.MM.dd` |
| `forenhive-postgresql` | Base de données relationnelle (prête pour Sprint 3) |

### Ce que le pipeline fait

**Filebeat** surveille en temps réel 4 fichiers de logs (un par honeypot) et transmet chaque
nouvel événement à Logstash sur le port 5044.

**Logstash** applique un filtre différent selon le honeypot (identifié par les tags) :
- Parse le JSON (Cowrie, Galah, Zeek) ou extrait les champs par pattern Grok (Dionaea)
- Renomme les champs vers ECS : `src_ip` → `source.ip`, `eventid` → `event.id`, etc.
- Enrichit géographiquement les IPs sources (MaxMind GeoLite2)
- Corrige l'horodatage : utilise l'heure réelle de l'événement (timezone Africa/Tunis)
- Supprime le bruit : messages debug Dionaea, champs internes inutiles

**Elasticsearch** reçoit les événements normalisés et les stocke dans un index par jour :
`honeypot-logs-2026.03.29`, `honeypot-logs-2026.03.30`…

---

### Commandes de test — Sprint 2

#### Étape 6 — Vérifier Filebeat

```bash
# Voir les logs Filebeat (harvesters actifs, erreurs éventuelles)
docker logs forenhive-filebeat --tail=20 2>&1 | grep -v "^{"
```
**Résultat attendu :** aucune ligne `ERR`, harvesters démarrés pour cowrie/dionaea/galah/zeek

---

#### Étape 7 — Vérifier Logstash

```bash
# Statistiques du pipeline : événements reçus / envoyés
docker exec forenhive-logstash curl -s http://127.0.0.1:9600/_node/stats/pipelines | python3 -c "
import sys, json
d = json.load(sys.stdin)
p = d['pipelines']['main']['events']
print('Événements reçus  :', p['in'])
print('Événements envoyés:', p['out'])
print('Événements filtrés:', p['filtered'])
"
```
**Résultat attendu :** `in` = `out` (aucun événement perdu), valeurs > 0

---

#### Étape 8 — Vérifier Elasticsearch

```bash
# Lister tous les indices journaliers
docker exec forenhive-elasticsearch curl -s "http://localhost:9200/_cat/indices/honeypot-logs-*?v&s=index"
```
**Résultat attendu :** un index par jour avec plusieurs milliers/millions de documents

```bash
# Compter les événements d'aujourd'hui par honeypot
TODAY=$(date +%Y.%m.%d)
docker exec forenhive-elasticsearch curl -s "http://localhost:9200/honeypot-logs-$TODAY/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 0,
    "aggs": {
      "par_honeypot": {
        "terms": { "field": "honeypot.type.keyword" }
      }
    }
  }' | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('Événements aujourd hui :')
for b in d['aggregations']['par_honeypot']['buckets']:
    print(f'  {b[\"key\"]:12} : {b[\"doc_count\"]:,} événements')
"
```
**Résultat attendu :** 4 honeypots présents (cowrie, dionaea, galah, zeek) avec doc_count > 0

---

#### Étape 9 — Vérifier les champs ECS normalisés

```bash
# Exemple d'événement Cowrie avec champs ECS
TODAY=$(date +%Y.%m.%d)
docker exec forenhive-elasticsearch curl -s "http://localhost:9200/honeypot-logs-$TODAY/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 1,
    "query": {"term": {"honeypot.type.keyword": "cowrie"}},
    "_source": ["honeypot.type","source.ip","user.name","event.id","event.category","event.outcome","@timestamp"]
  }' | python3 -c "
import sys, json
d = json.load(sys.stdin)
src = d['hits']['hits'][0]['_source']
print('Événement Cowrie normalisé :')
for k,v in sorted(src.items()): print(f'  {k}: {v}')
"
```
**Résultat attendu :** champs ECS présents (`source.ip`, `event.id`, `@timestamp` = heure réelle)

```bash
# Exemple d'événement Zeek
docker exec forenhive-elasticsearch curl -s "http://localhost:9200/honeypot-logs-$TODAY/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 1,
    "query": {"term": {"honeypot.type.keyword": "zeek"}},
    "_source": ["honeypot.type","source.ip","destination.ip","destination.port","network.transport","@timestamp"]
  }' | python3 -c "
import sys, json
d = json.load(sys.stdin)
src = d['hits']['hits'][0]['_source']
print('Événement Zeek normalisé :')
for k,v in sorted(src.items()): print(f'  {k}: {v}')
"
```

```bash
# Exemple d'événement Galah avec réponse IA
docker exec forenhive-elasticsearch curl -s "http://localhost:9200/honeypot-logs-$TODAY/_search?pretty" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 1,
    "query": {"term": {"honeypot.type.keyword": "galah"}},
    "_source": ["honeypot.type","source.ip","http.request.method","http.request.uri","event.action","@timestamp"]
  }' | python3 -c "
import sys, json
d = json.load(sys.stdin)
src = d['hits']['hits'][0]['_source']
print('Événement Galah normalisé :')
for k,v in sorted(src.items()): print(f'  {k}: {v}')
"
```

---

#### Étape 10 — Test end-to-end (trafic → Elasticsearch en ~30 secondes)

Générer du trafic depuis Kali et vérifier qu'il arrive dans Elasticsearch :

```bash
# Sur Kali : générer trafic SSH + HTTP simultanément
ssh -p 2222 -o StrictHostKeyChecking=no root@172.16.1.100  # mot de passe : root
curl http://172.16.1.100:8080/admin-panel
curl http://172.16.1.100:8888/config.php
```

```bash
# Sur le serveur : attendre 30s puis vérifier le nouveau compte
sleep 30
TODAY=$(date +%Y.%m.%d)
docker exec forenhive-elasticsearch curl -s "http://localhost:9200/honeypot-logs-$TODAY/_count" | python3 -c "
import sys, json; d=json.load(sys.stdin); print('Total événements aujourd hui:', d['count'])
"
```
**Résultat attendu :** le compteur augmente par rapport à avant la génération de trafic

---

## Résumé des résultats attendus

| Test | Résultat attendu |
|---|---|
| `docker ps` | 9 conteneurs `Up` |
| SSH valide sur port 2222 | Prompt `root@db-prod:~#` |
| SSH invalide sur port 2222 | `Permission denied` |
| Telnet sur port 2223 | Prompt `root@db-prod:~#` |
| `smbclient -L //...` | Partages WIN-SERVER2019 |
| `curl :8080/` | HTML généré par IA |
| `zeekctl status` | `running` |
| Zeek current/ dans Filebeat | `conn.log`, `ssh.log`, `http.log` visibles |
| Logstash stats | `in` = `out`, valeurs > 0 |
| Indices Elasticsearch | Un index par jour, millions de docs |
| Agrégation par honeypot | cowrie + dionaea + galah + zeek présents |
| Champs ECS | `source.ip`, `event.id`, `@timestamp` corrects |
| Test end-to-end | Compteur augmente en < 30 secondes |

---

## Métriques actuelles (au 2026-03-29)

| Source | Événements total (5 jours) |
|---|---|
| Dionaea | 11 431 353 |
| Zeek | 2 619 |
| Cowrie | 1 458 |
| Galah | 172 |
| **Total** | **~11,4 millions** |

> **Note :** Le serveur n'est pas encore exposé à Internet. Tout le trafic actuel est du trafic
> de test local généré depuis la machine Kali du réseau interne. Les métriques réelles
> augmenteront significativement une fois le déploiement Internet effectué.
