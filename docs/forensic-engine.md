# Forensic Engine — Référence technique

> Cœur analytique de ForenHive. 11 modules Python orchestrés par `engine.py`.
> Tourne en cron interne (intervalle `ENGINE_INTERVAL_MINUTES=5`) et expose
> un mini-serveur HTTP sur :8001 pour healthcheck.

---

## Les 11 modules

| Ordre | Module | Rôle | I/O |
|-------|--------|------|-----|
| 1 | [`enricher.py`](../forensic-engine/enricher.py) | Enrichissement IP (geoip, réputation, ASN) | IP → `ip_enrichment_cache` (PG) |
| 2 | [`yara_scanner.py`](../forensic-engine/yara_scanner.py) | Détection malware (YARA) | fichiers Dionaea → `file_analysis` |
| 3 | [`virustotal.py`](../forensic-engine/virustotal.py) | Lookup SHA-256 contre VirusTotal v3 | hash → merge dans `file_analysis` |
| 4 | [`smb_analyzer.py`](../forensic-engine/smb_analyzer.py) | Corrélation SMB/NTLM (Dionaea + Zeek) | logs → `forenhive-smb-analysis` (ES) |
| 5 | [`timeline_builder.py`](../forensic-engine/timeline_builder.py) | Timeline ms-précision multi-honeypot | ES events → `forensic_timeline_events` |
| 6 | [`ioc_extractor.py`](../forensic-engine/ioc_extractor.py) | Extraction IoCs (URLs, hashes, CVEs…) | timeline → `forensic_iocs` |
| 7 | [`mitre_mapper.py`](../forensic-engine/mitre_mapper.py) | MITRE ATT&CK hybride (déterministe + LLM) | events → liste de techniques |
| 8 | [`risk_score.py`](../forensic-engine/risk_score.py) | Risk score v2.0.0 (9 signaux) | tout → `ScoreResult` 0-100 |
| 9 | [`profiler.py`](../forensic-engine/profiler.py) | Profil criminologique (Mistral) | session → `suspect_profiles` |
| 10 | [`chain_of_custody.py`](../forensic-engine/chain_of_custody.py) | Sceau SHA-256 + RFC 3161 | sessions → `forensic_chain_of_custody` |
| 11 | `engine.py` | Orchestrateur principal + CLI | flags `--hours`, `--enrich-only`, etc. |

Modules support :

- `config.py` — toutes les variables d'environnement et chemins.
- `db_pool.py` — pool de connexions PostgreSQL.
- `risk_thresholds.py` — seuils LOW/MEDIUM/HIGH/CRITICAL.
- `quota_tracker.py` — gestion quotas APIs externes (VT, AbuseIPDB).
- `verify_coc.py` — outil CLI de vérification de la chaîne de custody.
- `server.py` — mini-serveur HTTP :8001 (healthcheck).

---

## Risk Score v2.0.0 — modèle à 9 signaux

Score total max : **100** (somme cappée).
Niveaux : `INFO` < `LOW` < `MEDIUM` < `HIGH` < `CRITICAL`
(bornes définies dans `risk_thresholds.py`).

### Taxonomie WHO / WHAT / HOW

| Catégorie | Signal | Max | Source |
|-----------|--------|-----|--------|
| **WHO** (33) | reputation | 15 | AbuseIPDB |
| | anonymization | 10 | Tor/VPN/proxy détectés |
| | threat_history | 8 | récidive honeypot + ASN connu malveillant |
| **WHAT** (43) | intent_volume | 10 | vélocité, pages scannées, ciblage admin |
| | compromise_depth | 15 | login réussi + commandes shell |
| | exfiltration | 8 | données téléchargées hors honeypot |
| | lateral_movement | 10 | multi-honeypot, scan interne, SMB enum |
| **HOW** (24) | malware | 15 | matchs YARA + détections VT |
| | mitre_sophistication | 9 | diversité tactiques ATT&CK observées |
| **TOTAL** | | **100** | |

### Règle spéciale — IPs privées (RFC1918)

Les services de réputation publics (AbuseIPDB, Tor, VPN) ne couvrent pas
l'espace d'adressage privé. Une IP interne malveillante = menace interne
critique. Les signaux comportementaux sont donc traités sans atténuation
pour refléter la criticité.

### Historique

Le modèle précédent à 18 signaux (`risk_score_optimized.py`, supprimé) a
été consolidé en 9 signaux v2.0.0 pour réduire les corrélations et
améliorer l'interprétabilité : un signal = une dimension orthogonale.

---

## Suspect Profiler — Criminologie assistée par LLM

Méthode inspirée du **FBI Behavioral Analysis Unit (BAU)** adaptée au cyber.
Références académiques : Ressler & Douglas (1988), Turvey BEA, Canter (2004),
Zatyko & Bay (2014).

### Prompt en 4 sections (~2600 tokens)

1. **System Role** (~200 tok) — positionnement en analyste BAU.
2. **Criminology Framework** (~400 tok) — 9+1 concepts mappés au cyber :
   organized/disorganized, MO→MITRE, signature behavior, Locard, staging,
   escalation→Kill Chain, victimologie, profilage géo, déduction/induction,
   plus détection de déguisement (contribution originale).
3. **Session Evidence XML** (~1200 tok) — données forensiques brutes de la session.
4. **ES Reference Cases** (~800 tok) — top 5 profils similaires de la mémoire.

### Mémoire Elasticsearch — index `forenhive-suspect-profiles`

Analogie FBI ViCAP — base de cas pour comparaison inter-profils. Matching primaire :

- ≥ 2 techniques MITRE en commun, OU
- même famille malware (YARA), OU
- même ASN.

Les top 5 cas similaires sont injectés en Section 4 comme « Reference Case Files ».

**Bootstrap :** les 20-50 premiers profils générés sans mémoire (cold start
attendu, pas une régression).

### Paramètres Ollama (immuables)

- `temp=0.3` — reproductibilité maximale (profil forensique ≠ créativité).
- `ctx=8192` — fenêtre suffisante pour 4 sections + JSON output.
- `model=mistral:7b-instruct-q4_K_M` — 4,4 Go, CPU-only.

### Output JSON structuré

```json
{
  "sophistication": "low|medium|high|advanced",
  "confidence": 0-100,
  "objective": "...",
  "behavioral_traits": [...],
  "organized_score": 0.0-1.0,
  "detective_narrative": "..."
}
```

---

## Mapping MITRE ATT&CK — approche hybride

### Niveau 1 — Déterministe (confidence = 1.0)

15 techniques mappées par règles `if/else` sur les indicateurs comportementaux :

| Comportement | Technique |
|--------------|-----------|
| bruteforce SSH (≥ 10 logins échoués) | T1110.001 |
| commande `wget <url>` | T1105 |
| exploit SMB port 445 (EternalBlue) | T1210 |
| scan multi-port (≥ 5 ports) | T1046 |
| énumération SMB | T1135 |
| persistance crontab | T1053.003 |
| … | … |

Précision : 100% (zéro hallucination), latence ≈ 0 ms.

### Niveau 2 — Narration LLM (Mistral, ≤ 80 tokens)

Mistral génère **uniquement une phrase de contexte tactique** en langage
naturel. **Jamais de nouveaux IDs ATT&CK** (source d'hallucinations dans la
v1 `ollama_mitre.py`, supprimé). Séparation stricte : DÉTECTION (déterministe,
fiable) vs NARRATION (LLM, créativité contextuelle uniquement).

Si Ollama est injoignable → fallback narratif générique, pas de crash.

---

## Chaîne de Custody — SHA-256 + RFC 3161

Principe de Locard appliqué au numérique : toute interaction laisse une trace,
et l'intégrité doit être démontrable mathématiquement.

### Procédure de scellement (4 étapes)

1. **Sérialisation canonique** — JSON déterministe (clés triées, pas de
   champs volatiles) des colonnes load-bearing du record.
2. **SHA-256** — empreinte cryptographique → colonne `record_hash`.
   Choix SHA-256 vs MD5/SHA-1 : résistance aux collisions.
3. **Chaîne append-only** — chaque ligne lie à la précédente via `prev_hash`.
   Toute altération propage en aval et invalide toute la chaîne (vérifiable
   par `verify_coc.py`).
4. **Horodatage RFC 3161 batch** — racine Merkle de toutes les sessions
   scellées d'un run, soumise à une TSA (`freetsa.org` par défaut + fallbacks).
   La réponse signée prouve que la racine existait avant une date certifiée.

### Usage légal

SHA-256 + RFC 3161 = preuves recevables en investigation numérique selon
**ISO/IEC 27037** (identification, collecte, acquisition, préservation).

### Tables PostgreSQL

- `forensic_chain_of_custody` — une ligne par session scellée
- `forensic_coc_batches` — une ligne par requête TSA (ancrage Merkle root)

---

## Vérification de la chaîne

```bash
docker compose exec forensic-engine python verify_coc.py
```

Sortie attendue :

```
  → 142 sealed sessions checked, 142 valid
✓ chain intact — 142 records, 7 batch(es)
```

Toute rupture (`prev_hash` mismatch, record_hash recalculé différent,
horodatage TSA invalide) entraîne un exit code non-zéro et un message
d'erreur explicite par session impactée.
