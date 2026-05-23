# Architecture — ForenHive

ForenHive est structuré en **4 couches** strictement isolées par réseaux Docker
(`honeypot-net` et `backend-net`).

```
┌──────────────────────────────────────────────────────────────┐
│  C1 — HONEYPOTS               (honeypot-net, isolé)          │
│                                                              │
│   Cowrie ──┐                                                 │
│   Dionaea ─┤── logs ──► Filebeat                             │
│   Galah ───┘                                                 │
│   Zeek (host network, capture passive)                       │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  C2 — ETL & STOCKAGE         (backend-net)                   │
│                                                              │
│   Filebeat ──► Logstash ──► Elasticsearch                    │
│                  │              │                            │
│                  │              ├─► honeypot-logs-YYYY.MM.dd │
│                  │              └─► forenhive-suspect-...    │
│                  │                                           │
│                  └─► GeoIP MaxMind enrich                    │
│                                                              │
│   PostgreSQL ◄─── stockage forensique structuré              │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  C3 — FORENSIC ENGINE        (cron interne 5 min)            │
│                                                              │
│   engine.py orchestre 10 modules en chaîne :                 │
│   enricher → yara → VT → smb → timeline → ioc → mitre →      │
│   risk_score → profiler → chain_of_custody                   │
│                                                              │
│   Ollama (Mistral 7B Q4_K_M) consommé par : profiler,        │
│   mitre_mapper (narration uniquement), galah                 │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  C4 — BACKEND + SPA + REPORTING                              │
│                                                              │
│   FastAPI :8000 (13 routers) ◄─── JWT Bearer                 │
│        │                                                     │
│        ├─ services : ES, PG, Ollama, Twilio, report_*        │
│        └─ /api/reports/forensic/{sid}/generate ──► PDF       │
│                                                              │
│   nginx :3000/3443 ──► SPA (Vite build, partiels HTML)       │
└──────────────────────────────────────────────────────────────┘
```

---

## Flux de données

### Capture → indexation (C1 → C2)

1. Un attaquant interagit avec un honeypot.
2. Le honeypot écrit dans son log local (volume Docker).
3. **Filebeat** tail le log et l'envoie à Logstash sur `:5044`.
4. **Logstash** :
   - parse (grok / json filter),
   - normalise au format **ECS** (Elastic Common Schema),
   - enrichit avec **GeoIP MaxMind** (pays, ville, lat/lon, ASN),
   - indexe dans `honeypot-logs-YYYY.MM.dd` (Elasticsearch).

### Indexation → analyse (C2 → C3)

5. Toutes les 5 min, `engine.py` interroge ES sur la fenêtre récente
   (`--hours 24` par défaut).
6. Pour chaque IP source nouvelle ou session non analysée :
   - enrichissement multi-source (GeoIP local + AbuseIPDB + Shodan…),
   - scan YARA sur les payloads Dionaea,
   - lookup VirusTotal (si quota),
   - corrélation SMB (Dionaea + Zeek NTLM),
   - construction d'une timeline ms-précision,
   - extraction d'IoCs,
   - mapping MITRE ATT&CK (déterministe + narration Mistral),
   - calcul du risk score 9 signaux,
   - génération du profil criminologique BAU (Mistral),
   - scellement SHA-256 + RFC 3161 (chaîne de custody).
7. Persistance atomique en PostgreSQL (4+ tables) + ES (profils).

### Analyse → consultation (C3 → C4)

8. Le backend FastAPI (`:8000`) expose les données via 13 routers REST.
9. La SPA (`:3000` ou `:3443` HTTPS) consomme l'API avec JWT Bearer
   (clé localStorage `forenhive.token`).
10. Sur demande utilisateur, `POST /api/reports/forensic/{sid}/generate`
    rend un PDF WeasyPrint à partir des templates Jinja2
    `forenhive_rapport_v2.html` (EN) ou `_v2_fr.html` (FR).

---

## Réseaux Docker

| Réseau | Contenu | Isolation |
|--------|---------|-----------|
| `honeypot-net` | Cowrie, Dionaea, Galah, Filebeat | les attaquants ne peuvent pas atteindre le backend depuis ce réseau |
| `backend-net` | Logstash, ES, PG, Ollama, forensic-engine, backend, frontend, Galah | trafic interne uniquement |
| `host network` | Zeek | nécessaire pour capture passive sur `eno12399` |

Galah est sur les **deux** réseaux car il a besoin :
- d'exposer HTTP côté honeypot pour piéger les attaquants,
- de joindre Ollama côté backend pour générer ses réponses LLM.

---

## Stockage

### Elasticsearch — données chronologiques

- `honeypot-logs-YYYY.MM.dd` — un index par jour (ETL).
- `forenhive-suspect-profiles` — profils BAU (mémoire de cas).
- `forenhive-smb-analysis` — corrélation SMB (Dionaea + Zeek NTLM).

### PostgreSQL — données forensiques structurées

| Table | Rôle |
|-------|------|
| `forensic_sessions` | sessions d'attaque agrégées par IP/session_id |
| `forensic_timeline_events` | timeline ms-précision multi-honeypot |
| `forensic_iocs` | IoCs extraits (URL, hash, CVE, …) |
| `forensic_chain_of_custody` | scellements SHA-256 + ancrages TSA |
| `forensic_coc_batches` | requêtes TSA (Merkle root anchors) |
| `suspect_profiles` | profils BAU générés par Mistral |
| `file_analysis` | matchs YARA + détections VT |
| `ip_enrichment_cache` | cache enrichissement IP (TTL 24h) |
| `ip_risk_scores` | scores de risque + ventilation par signal |
| `users`, `audit_log` | auth + journal d'audit backend |

---

## Choix techniques structurants

- **CPU-only LLM** : Mistral 7B Q4_K_M tourne sur CPU du R750 (~3-5 s par
  appel court, ~30 s pour profil complet). Pas de dépendance GPU.
- **Pas de LLM externe** : pas d'OpenAI, pas de Claude — exigence
  "souveraineté des données forensiques" (le contenu d'une session ne
  quitte pas l'infrastructure).
- **PostgreSQL + Elasticsearch** : duo standard du forensique numérique
  (PG pour la véracité structurée, ES pour la recherche full-text et les
  agrégations time-series).
- **WeasyPrint** : rendu PDF déterministe à partir de HTML/CSS (vs LaTeX
  ou alternatives). Templates Jinja2 avec `StrictUndefined` pour détecter
  immédiatement tout champ manquant.
- **SPA vanilla** (HTML/JS + Vite) : pas de framework lourd, partiels
  HTML chargés dynamiquement. Choix justifié par la simplicité de
  maintenance et le faible besoin d'état côté client.

---

*Pour les détails du Forensic Engine (modules, signaux, Suspect Profiler) :
voir [`forensic-engine.md`](forensic-engine.md).
Pour les endpoints REST : voir [`api.md`](api.md).
Pour le déploiement : voir [`deployment.md`](deployment.md).*
