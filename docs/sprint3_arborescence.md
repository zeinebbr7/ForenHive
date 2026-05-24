# Sprint 3 — Arborescence du projet (livrables forensic engine)

Ce document accompagne la section "Arborescence" du chapitre 7 du rapport.
Il fournit (a) le **listing textuel** prêt-à-coller dans un `\begin{verbatim}` LaTeX et (b) la **consigne précise** pour la capture VSCode.

---

## 1. Listing textuel — répertoires Sprint 3

À placer en regard du screenshot VSCode dans le rapport.

```
forenhive/
├── forensic-engine/                # Conteneur unique : 11 modules + tests + YARA
│   ├── engine.py                   # 1580 L  — orchestrateur 9 phases (CLI)
│   ├── server.py                   #  390 L  — mini-HTTP /status :8001
│   ├── config.py                   #   81 L  — loader .env (ES, PG, Ollama, keys)
│   ├── db_pool.py                  #  114 L  — pool PG (psycopg2 + retry)
│   ├── enricher.py                 #  713 L  — Phase 1 : GeoIP + reputation
│   ├── smb_analyzer.py             #  702 L  — Phase 2 : Dionaea + Zeek NTLM
│   ├── yara_scanner.py             #  161 L  — Phase 3a : YARA → file_analysis
│   ├── virustotal.py               #  207 L  — Phase 3b : VT v3 + quota
│   ├── risk_score.py               #  755 L  — Phase 4 : modèle v2.0.0, 9 signaux
│   ├── risk_thresholds.py          #   34 L  — seuils INFO/LOW/.../CRITICAL
│   ├── timeline_builder.py         #  351 L  — Phase 5 : timeline ms-précision
│   ├── ioc_extractor.py            #  267 L  — Phase 6 : 10 types IoC + STIX 2.1
│   ├── mitre_mapper.py             #  531 L  — Phase 7 : hybride déterministe+LLM
│   ├── chain_of_custody.py         #  343 L  — Phase 8 : SHA-256 + Merkle + RFC3161
│   ├── verify_coc.py               #  141 L  — vérificateur indépendant
│   ├── profiler.py                 #  707 L  — Phase 9 : Mistral 7B + BAU
│   ├── quota_tracker.py            #  222 L  — rate-limit persistant (PG)
│   ├── Dockerfile                  # python:3.11-slim + yara-python + libmagic
│   ├── requirements.txt            # 14 dépendances pinned
│   ├── GeoLite2-City.mmdb          # base offline MaxMind (bind-mount host)
│   ├── GeoLite2-ASN.mmdb           # base offline MaxMind (bind-mount host)
│   ├── db/
│   │   ├── schema.sql              # 9 tables forensiques + migrations ALTER
│   │   ├── init_db.py              # bootstrap idempotent (CREATE IF NOT EXISTS)
│   │   └── __init__.py
│   ├── yara_rules/                 # 10 jeux de règles, compilés une fois au boot
│   │   ├── ransomware.yar          # LockBit, BlackCat, Clop
│   │   ├── wannacry.yar            # WannaCry/EternalBlue payload
│   │   ├── mirai.yar               # botnet Mirai (IoT)
│   │   ├── emotet.yar              # malware bancaire Emotet
│   │   ├── rat.yar                 # AsyncRAT, QuasarRAT
│   │   ├── crypto_miner.yar        # XMRig, CoinMiner
│   │   ├── linux_backdoor.yar      # backdoors *nix
│   │   ├── credential_stealer.yar  # vol de credentials
│   │   ├── generic_shell.yar       # web shells génériques
│   │   └── malware.yar             # patterns génériques (EICAR + heuristiques)
│   └── tests/
│       ├── conftest.py             # fixtures pytest
│       └── test_risk_score.py      # tests unitaires modèle v2.0.0
│
├── docker-compose.yml              # ligne ~206 : service forensic-engine
├── .env / .env.example             # clés AbuseIPDB / VT / Twilio / TSA_URL
└── docs/
    ├── sprint3_audit.md            # audit complet 11 sections (ce sprint)
    ├── sprint3_arborescence.md     # ce fichier
    ├── sprint3_listings.md         # extraits de code à citer
    └── sprint3_captures.md         # screenshots à produire
```

---

## 2. Capture VSCode — consigne précise

**Objectif** : produire une image équivalente à celle utilisée au chapitre 5 (Sprint 1), mais focalisée sur le Sprint 3.

**Préparation dans VSCode** :

1. Ouvrir le workspace `/home/pfe/forenhive` dans VSCode.
2. Dans l'Explorer (panneau gauche), **plier tous les dossiers** racines (`Cmd/Ctrl+K` puis `Cmd/Ctrl+0`).
3. **Déplier uniquement** :
   - `forensic-engine/`
   - `forensic-engine/db/`
   - `forensic-engine/yara_rules/`
   - `forensic-engine/tests/`
4. **Laisser pliés** : `backend/`, `frontend/`, `honeypots/`, `pipeline/`, `geoip/`, `archive/`, `.github/`, `.git/`.
5. Régler la police de l'Explorer en taille lisible (15–16 px).
6. Masquer la barre d'activité gauche si possible (plus de largeur pour l'arborescence).

**Capture** :

- Cadre : du haut de l'Explorer (titre `EXPLORER: FORENHIVE`) jusqu'au dernier fichier visible (`test_risk_score.py`).
- Format : PNG, largeur ≥ 800 px.
- Nom de fichier conseillé : `figures/sprint3_arborescence_vscode.png`.

**Optionnel** — `forensic-engine/engine.py` ouvert dans l'éditeur (onglet visible), curseur sur la ligne `class ForensicEngine:` ou sur l'entête `═══ MOTEUR D'ORCHESTRATION ═══`. Cela donne un côté "code source vivant" à la figure.

---

## 3. Légende LaTeX suggérée

```latex
\begin{figure}[H]
  \centering
  \includegraphics[width=0.85\textwidth]{figures/sprint3_arborescence_vscode.png}
  \caption{Arborescence VSCode du livrable Sprint 3 — répertoire
           \texttt{forensic-engine/} avec ses 11 modules Python,
           10 jeux de règles YARA, schéma SQL et tests unitaires.}
  \label{fig:sprint3-arborescence}
\end{figure}
```
