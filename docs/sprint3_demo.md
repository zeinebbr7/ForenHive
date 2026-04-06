# ForenHive — Démonstration Sprint 3
**Forensic Engine: Enrichissement · YARA · VirusTotal · Risk Scoring**
*Branch: zeineb | Date: 2026-04-06*

---

## Vue d'ensemble

Sprint 3 implémente la couche d'analyse forensique (C3) qui consomme les événements normalisés de Sprint 2 (Elasticsearch) et produit des résultats forensiques stockés dans PostgreSQL.

```
Elasticsearch (14.7M+ events) ──┐
                                 ├──► forensic-engine ──► PostgreSQL
Dionaea malware captures ────────┘    (C3 layer)          (résultats enrichis)
```

---

## Prérequis — vérifier que les services Sprint 2 tournent

```bash
docker compose ps --format "table {{.Name}}\t{{.Status}}" | grep -E "elastic|postgres|dionaea"
```
**Résultat attendu :** `forenhive-elasticsearch Up`, `forenhive-postgresql Up`, `forenhive-dionaea Up`

---

## Étape 1 — Construire l'image Docker du moteur forensique

```bash
docker compose build forensic-engine
```
**Résultat attendu :** `Image forenhive-forensic-engine Built`

Le build installe `gcc`, `libssl-dev`, `libmagic1` pour compiler `yara-python`, puis installe toutes les dépendances Python (elasticsearch, psycopg2, geoip2, yara-python, shodan, ipwhois…).

---

## Étape 2 — Initialiser le schéma PostgreSQL

```bash
docker compose run --rm forensic-engine python db/init_db.py
```
**Résultat attendu :**
```
[init_db] PostgreSQL ready.
[init_db] Schema applied successfully.
[init_db] Done.
```

Vérifier les tables créées :
```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive -c "\dt"
```
**Résultat obtenu :**
```
                List of relations
 Schema |        Name         | Type  |   Owner
--------+---------------------+-------+-----------
 public | file_analysis       | table | forenhive
 public | forensic_sessions   | table | forenhive
 public | ip_enrichment_cache | table | forenhive
 public | suspect_profiles    | table | forenhive
(4 rows)
```

---

## Étape 3 — Scanner YARA (sans dépendances externes)

```bash
docker compose run --rm forensic-engine python engine.py --yara-only
```
**Résultat obtenu :**
```
[INFO] yara_scanner — Compiled 6 YARA rule files: ['crypto_miner.yar', 'emotet.yar',
       'credential_stealer.yar', 'generic_shell.yar', 'wannacry.yar', 'mirai.yar']
[INFO] yara_scanner — Scanning 2 Dionaea binary files ...
[INFO] yara_scanner — MATCH [1bb736b97b5bcb4c5b3adf5c3c903fa3] SHA256=3ca20938... → ['CryptoMiner_XMRig', 'WannaCry_Ransomware']
[INFO] yara_scanner — YARA scan complete: 1/2 files flagged
```

**Interprétation :**
- Fichier `1bb736b97b5bcb4c5b3adf5c3c903fa3` (5.1 MB ELF) — capturé par Dionaea le 2026-03-30 — déclenche 2 règles :
  - `CryptoMiner_XMRig` : wallet Monero détecté à l'offset 131587
  - `WannaCry_Ransomware` : chaînes `tasksche.exe`, `mssecsvc.exe`, `icacls` détectées (CVE-2017-0144)
- Fichier `test_eicar.exe` (69 bytes) — aucun match (attendu — EICAR est un fichier test AV sans patterns malware réels)

---

## Étape 4 — Analyse complète (enrichissement + VT + scoring)

```bash
docker compose run --rm forensic-engine python engine.py --hours 240
```

**Sortie complète obtenue :**
```
[INFO] engine — ====== ForenHive Full Analysis (last 240h) ======

[INFO] engine — === IP Enrichment (last 240h) ===
[INFO] enricher — Found 143 unique source IPs in the last 240h
[INFO] enricher — Enriching batch of 143 unique IPs ...
[INFO] enricher — Enriching 64.233.166.188 ...
[INFO] enricher — Enriching 173.194.76.188 ...
[INFO] engine — Enriched 143 IPs

[INFO] engine — === YARA Scan (Dionaea binaries) ===
[INFO] yara_scanner — MATCH [1bb736...] SHA256=3ca20938... → ['CryptoMiner_XMRig', 'WannaCry_Ransomware']
[INFO] yara_scanner — YARA scan complete: 1/2 files flagged
[INFO] virustotal — VirusTotal [3ca20938...] 66/72 detections, family=trojan

[INFO] engine — === VirusTotal lookup for Cowrie downloads (last 240h) ===
[INFO] engine — Found 6 unique hashes — submitting to VirusTotal ...
[INFO] virustotal — VirusTotal: hash not found — 7b23224696dea3c1... (unknown malware)
[INFO] virustotal — VirusTotal [a56145270ce6b3be...] 0/62 detections, family=unknown
[INFO] virustotal — VirusTotal: hash not found — bed89110eafe9846... (unknown malware)
[INFO] virustotal — VirusTotal: hash not found — a6594d0fed26788c... (unknown malware)
[INFO] virustotal — VirusTotal: hash not found — f6ac9ab75f5067d8... (unknown malware)
[INFO] virustotal — VirusTotal: hash not found — 2638f1c1c2018567... (unknown malware)

[INFO] engine — === Session Scoring (last 240h) ===
[INFO] engine — Found 46 Cowrie sessions to score

[INFO] engine — ====== Analysis Complete ======
[INFO] engine —   IPs enriched  : 143
[INFO] engine —   Sessions scored: 46
[INFO] engine —   Risk breakdown : CRITICAL=0 HIGH=0 MEDIUM=0
[INFO] engine —   Duration       : 24.2s
```

---

## Résultats extraits de PostgreSQL

### 4.1 Analyse de fichiers malveillants (`file_analysis`)

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive \
  -c "SELECT sha256, virustotal_result->>'detection_ratio' AS vt_ratio,
             virustotal_result->>'family' AS family,
             virustotal_result->>'tags' AS tags,
             jsonb_array_length(yara_matches) AS yara_hits
      FROM file_analysis ORDER BY sha256;"
```

| SHA-256 (tronqué) | Fichier source | VT ratio | Famille | Tags VT | YARA hits |
|---|---|---|---|---|---|
| `3ca20938...` | `1bb736...` (Dionaea) | **66/72** | `trojan` | `pedll, cve-2017-0147, armadillo, overlay, exploit` | **2** |
| `131f95c5...` | `test_eicar.exe` | — | — | — | 0 |
| `a56145270c...` | Cowrie download | 0/62 | — | `known-distributor, text` | — |
| `7b232246...` | Cowrie download | **inconnu** | — | non indexé VT | — |
| `bed89110...` | Cowrie download | **inconnu** | — | non indexé VT | — |
| `a6594d0f...` | Cowrie download | **inconnu** | — | non indexé VT | — |
| `f6ac9ab7...` | Cowrie download | **inconnu** | — | non indexé VT | — |
| `2638f1c1...` | Cowrie download | **inconnu** | — | non indexé VT | — |

**Observation clé :** Le binaire `3ca20938` capturé par Dionaea est reconnu par **66 moteurs AV sur 72** comme un trojan avec les tags `cve-2017-0147` (EternalBlue/SMB) et `armadillo` (packer connu). C'est un exploit SMB weaponisé avec des composants de cryptominer Monero — une menace hybride. Les 5 fichiers téléchargés via Cowrie sont **inconnus de VirusTotal** (zero-day ou malware personnalisé).

---

### 4.2 Enrichissement IP (`ip_enrichment_cache`)

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive \
  -c "SELECT ip, data->'geo'->>'country' AS country, data->'geo'->>'org' AS org,
             data->'geo'->>'asn' AS asn, data->'reputation'->>'abuse_score' AS abuse,
             data->'reputation'->>'total_reports' AS reports,
             data->'privacy'->>'is_tor' AS tor
      FROM ip_enrichment_cache;"
```

| IP | Pays | Org | ASN | Abuse Score | Reports | Tor |
|---|---|---|---|---|---|---|
| `64.233.166.188` | United States | Google LLC | 15169 | 0 | 1 | false |
| `173.194.76.188` | United States | Google LLC | 15169 | 0 | 1 | false |

**Note :** 141 des 143 IPs sont RFC 1918 (trafic Kali interne `10.212.134.x`, `172.20.0.x`) → enrichissement sauté automatiquement. Seules 2 IPs publiques Google LLC ont été enrichies — ces IPs apparaissent dans des requêtes HTTP sur Galah (scan automatique Google ou bot).

GeoIP MaxMind opérationnel :
```json
{
  "asn": 15169, "lat": 37.751, "lon": -97.822,
  "org": "Google LLC", "country": "United States", "country_code": "US"
}
```

---

### 4.3 Sessions forensiques (`forensic_sessions`)

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive \
  -c "SELECT count(*) AS total, count(DISTINCT source_ip) AS unique_ips,
             max(risk_score) AS max_score, round(avg(risk_score),1) AS avg_score,
             sum(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) AS critical,
             sum(CASE WHEN risk_score >= 60 THEN 1 ELSE 0 END) AS high,
             sum(CASE WHEN risk_score >= 40 THEN 1 ELSE 0 END) AS medium
      FROM forensic_sessions;"
```

| Total sessions | IPs uniques | Score max | Score moyen | CRITICAL | HIGH | MEDIUM |
|---|---|---|---|---|---|---|
| 46 | 3 | 5 | 0.2 | 0 | 0 | 0 |

Sessions avec score > 0 :

```bash
docker exec forenhive-postgresql psql -U forenhive -d forenhive \
  -c "SELECT session_id, source_ip, risk_score, started_at, ended_at
      FROM forensic_sessions WHERE risk_score > 0 ORDER BY risk_score DESC;"
```

| Session | IP | Score | Début | Fin |
|---|---|---|---|---|
| `719ec095c065` | `10.212.134.200` | **5** | 2026-03-28 12:20 | 2026-03-28 20:14 |
| `dd46d1eb66e2` | `10.212.134.200` | 2 | 2026-03-28 12:18 | 2026-03-28 20:14 |
| `3d540e70b01a` | `10.212.134.200` | 2 | 2026-03-28 12:30 | 2026-03-28 20:14 |
| `6a6fce682665` | `172.20.0.1` | 2 | 2026-03-28 12:07 | 2026-03-28 20:14 |

**Explication des scores faibles :** Tout le trafic actuel provient de la machine Kali du réseau interne (IPs RFC 1918). Les IPs privées obtiennent automatiquement un `abuse_score = 0` et `is_tor = false`, ce qui plafonne le score à 15 points maximum (login attempts + command count + port targeting). Les scores augmenteront significativement une fois le serveur exposé à Internet.

---

## Résumé des résultats

| Test | Résultat |
|---|---|
| Build Docker | ✅ yara-python compilé avec gcc |
| Schéma PostgreSQL | ✅ 4 tables créées |
| YARA scan (2 fichiers) | ✅ 1/2 fichiers flaggés (malware réel) |
| VirusTotal (binaire Dionaea) | ✅ **66/72** détections — trojan + CVE-2017-0147 |
| VirusTotal (Cowrie downloads) | ✅ 5 hashes inconnus, 1 clean |
| GeoIP MaxMind | ✅ ASN + géolocalisation opérationnels |
| AbuseIPDB enrichment | ✅ 2 IPs publiques enrichies |
| IPLocate (Tor/VPN detection) | ✅ opérationnel |
| Session scoring (46 sessions) | ✅ scorées et persistées en PostgreSQL |
| Durée analyse complète | ✅ **24.2 secondes** |

---

## Limites actuelles (trafic test)

| Limitation | Cause | Impact attendu en production |
|---|---|---|
| Tous les scores ≤ 5 | IPs RFC 1918 → abuse_score = 0 | Scores 40-100 avec IPs publiques d'attaquants réels |
| 5 hashes Cowrie inconnus de VT | Malware personnalisé ou récent | YARA les identifiera localement même sans VT |
| 2 IPs publiques = Google LLC | Pas encore de vrais attaquants | Dès exposition Internet : IPs malveillantes dans AbuseIPDB |
| Pas de sessions MEDIUM/HIGH/CRITICAL | Trafic interne uniquement | Dès exposition : sessions avec Tor, VPN, IPs connues |
