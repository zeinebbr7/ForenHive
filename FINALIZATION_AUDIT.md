# FINALIZATION AUDIT — ForenHive

> Rapport PHASE 0 (cartographie en lecture seule). Aucune modification n'a été appliquée.
> Auteur : passe de finalisation pré-soutenance PFE — 2026-05-23.

---

## 0. Points bloquants à trancher AVANT toute action

Deux blocages préalables à la création de la branche `chore/finalization-cleanup` :

### B-1 : la branche `develop` n'existe pas
Branches locales : `main`, `audit/report-pipeline-2026-05-22`, `ismail`, `ismail2`, `pzyy`, `zeineb`, `zinoba`.
Branches distantes : `main`, `ismail`, `ismail2`, `zeineb`, `zinoba`. Aucune `develop` côté `origin`.
La mission indique de partir de `develop`. **À trancher :**
  - (a) créer `develop` à partir de `main` puis brancher `chore/finalization-cleanup` dessus, **ou**
  - (b) partir directement de `main` (renommer la branche de travail si souhaité).

### B-2 : ~50 changements non commités sur `main`
- 40 fichiers modifiés (M), 4 supprimés (D), 9 non suivis (??).
- Notamment :
  - Suppressions : `forensic-engine/risk_score_optimized.py`, `frontend/src/pages/Yara.jsx`, `frontend/src/pages/yara.html`, un `.pyc` orphelin.
  - Nouveaux : `forensic-engine/risk_score.py` (remplaçant), `forensic-engine/tests/`, `backend/templates/forenhive_rapport_v2_fr.html`, `backend/templates/report.html`, `docs/forensic_engine_reference.md`, `docs/sprint3_audit_v2.md`, `frontend/src/contexts/LanguageContext.jsx`, `frontend/src/i18n/`, `frontend/forenhive-locations.inc`.
  - Modifs lourdes : `frontend/src/pages/Stats.jsx` (~854 lignes touchées), `pages/Access.jsx`, `pages/Reporting.jsx`, `frontend/src/components/Layout.jsx`, etc.
- Ces changements ressemblent à la migration FR/EN (i18n) + remplacement du moteur de scoring + ménage Yara.

**À trancher :** ces changements doivent-ils être :
  - (a) commités sur `main` AVANT la création de la branche (état de départ propre), **ou**
  - (b) emportés sur `chore/finalization-cleanup` puis commités au début de la branche (cleanup inclut alors l'intégration de ces évolutions), **ou**
  - (c) partiellement triés (certains sur main, d'autres jetés) ?

> Tant que B-1 et B-2 ne sont pas tranchés, je ne crée pas de branche et n'applique aucune modification.

---

## 1. Cartographie du dépôt

### Arborescence racine

```
forenhive/
├── backend/                FastAPI (Python 3.11 dans Docker, 3.12 sur le poste)
│   ├── alerts/             alert_manager (e-mail / Twilio)
│   ├── models/             modèles Pydantic / domaine
│   ├── models_sql/         modèles SQLAlchemy async
│   ├── routers/            endpoints REST (chat, forensics, sessions, …)
│   ├── services/           ES, report adapter/service, alert_engine
│   ├── templates/          gabarits WeasyPrint + e-mail
│   ├── tests/              test_risk_score.py (1 fichier)
│   ├── main.py · config.py · db.py · requirements.txt · Dockerfile
│   └── __pycache__/        ⚠ caches commités
├── chatbot/                hive_chat.py (intégration Mistral via Ollama)
│   ├── hive/               sources Ollama/CLI ?
│   └── __pycache__/        ⚠
├── docs/                   architecture.md + 5 audits sprint (voir §5)
├── forensic-engine/        Moteur C3 (10+ modules)
│   ├── db/                 schema.sql, init_db.py
│   ├── tests/              conftest.py + test_risk_score.py
│   ├── yara_rules/         règles YARA
│   ├── GeoLite2-*.mmdb     bases GeoIP (binaires lourds — vérifier .gitignore)
│   ├── engine.py · enricher.py · risk_score.py · profiler.py · …
│   └── __pycache__/        ⚠
├── frontend/               SPA Vite + React
│   ├── dist/               ⚠ artefact de build commité (devrait être ignoré)
│   ├── public/, assets/
│   ├── src/
│   │   ├── pages/          JSX + HTML partiels (couplés 1↔1, sauf yara* supprimés)
│   │   ├── components/     Layout, ProtectedRoute, hive-chat.js
│   │   ├── contexts/       AuthContext, ModalContext, LanguageContext (nouveau)
│   │   ├── i18n/           nouveau dossier (non encore inventorié)
│   │   ├── api.js · app.js · App.jsx · constants.js · utils.js · main.jsx
│   │   └── mockProfiles.js ⚠ données de démo en bundle prod ?
│   ├── Dockerfile · nginx.conf · forenhive-locations.inc (nouveau, inclus par nginx)
│   └── index.html
├── geoip/                  bases GeoIP (dupliquées avec forensic-engine ?)
├── honeypots/              cowrie/, dionaea/, galah/, zeek/
├── pipeline/               filebeat/, logstash/
├── docker-compose.yml      ⚠ ne pas toucher sauf commentaires morts
├── .env (modifié) · .env.example
├── Makefile · README.md · .gitignore · package-lock.json (88 octets — quasi vide)
├── .github/workflows/      CI (à inspecter)
└── .pytest_cache/, .vscode/, .claude/   ⚠ caches outils
```

### Volumétrie pages frontend (lignes)

| Page              | JSX  | HTML partiel |
| ----------------- | ---- | ------------ |
| Profiling         | 1071 | 1422         |
| Reconstruction    |  732 |  569         |
| Stats             |  626 |  410         |
| Landing           |  605 |  —           |
| Access            |  524 |  319         |
| Reporting         |  497 | 1107         |
| Honeypots         |  451 |  184         |
| Evidence          |  419 |  422         |
| Timeline          |  390 |  389         |
| Alerts            |  366 |  389         |
| Dashboard         |  354 |  200         |
| Sessions          |  333 |  309         |
| GeoMap            |  333 |  264         |
| Health            |  287 |  283         |
| Config            |  235 |  170         |
| Login             |  195 |   89         |
| Audit             |  174 |  186         |
| Settings          |  123 |   96         |

→ **Aucun fichier placeholder vide détecté** dans `frontend/src/pages/` (contrairement à ce que la mémoire ancienne laissait penser). Tous les JSX/HTML ont du contenu réel. La paire `Yara.jsx` / `yara.html` a déjà été supprimée (en attente de commit).

---

## 2. Outillage détecté

| Sujet                           | État                                                                 |
| ------------------------------- | -------------------------------------------------------------------- |
| Python (Dockerfile backend)     | **3.11-slim** — poste local : 3.12.3                                 |
| Python deps backend             | `backend/requirements.txt` (pinned, 25 paquets)                      |
| Python deps engine              | `forensic-engine/requirements.txt` (pinned, 14 paquets)              |
| **Incohérence**                 | FastAPI 0.115 (backend) vs 0.111 (engine) ; Pydantic 2.10 vs 2.7 ; Uvicorn 0.32 vs 0.29 ; python-dotenv 1.0.1 vs 1.0.0 ; rfc3161-client 1.0.6 dans les deux ✅ |
| Lint/format Python              | **Aucun config** (`pyproject.toml`, `ruff.toml`, `.ruff.toml`, `setup.cfg` absents) |
| Lint/format JS                  | **Aucun** `.prettierrc`, `eslint.config.*`, ni `package.json` à la racine — `package-lock.json` racine est quasi vide (88 octets) |
| package.json frontend           | présent dans `frontend/` (non encore lu)                             |
| Tests Python                    | pytest 8.3.4 dans les deux deps. 2 fichiers `test_risk_score.py` (backend + engine) — **contenus différents** : à clarifier (doublon historique ou suites distinctes ?) |
| CI                              | `.github/workflows/` présent (non encore inspecté en Phase 0)        |

---

## 3. Caches & artefacts (candidats nettoyage immédiat — bas risque)

Aucune action prise. Ces éléments sont déjà couverts par `.gitignore` mais présents sur disque (et certains semblent versionnés) :

- 11 dossiers `__pycache__/` dans : `backend/`, `backend/alerts/`, `backend/models/`, `backend/models_sql/`, `backend/routers/`, `backend/services/`, `backend/tests/`, `chatbot/`, `forensic-engine/`, `forensic-engine/db/`, `forensic-engine/tests/`.
- 20+ fichiers `.pyc`.
- 3 dossiers `.pytest_cache/` : racine, `backend/`, `forensic-engine/`.
- `frontend/dist/` (artefact de build) — `dist/` est gitignoré, à vérifier qu'il n'est pas tracké.
- `package-lock.json` à la racine (88 octets — résiduel d'un essai npm probablement).
- `.vscode/` (préférences IDE).

**Recommandation :** Phase 1 — `git rm --cached` ce qui est tracké, suppression disque, puis durcir `.gitignore`.

---

## 4. Suspects de code mort / doublons (à valider — RIEN supprimé)

| # | Élément                                                                                | Statut                                                                                       | Action proposée                |
| - | -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ------------------------------ |
| 1 | `forensic-engine/risk_score_optimized.py`                                              | déjà supprimé (en attente de commit), remplacé par `risk_score.py`                           | confirmer / commiter           |
| 2 | `frontend/src/pages/Yara.jsx` + `yara.html`                                            | déjà supprimés (en attente de commit)                                                        | confirmer / commiter           |
| 3 | `backend/templates/report.html` (118 lignes) **vs** `forenhive_rapport_v2.html` (1565) | `report.html` semble être un brouillon/fallback. **Quel template est utilisé en prod ?**     | inspecter `services/report_service.py` puis archiver le mort |
| 4 | `forenhive_rapport_v2.html` (EN) vs `forenhive_rapport_v2_fr.html` (FR)                | versions linguistiques (diff : `<html lang>` + traductions). **Garder les deux ?**           | OK probable (bilingue), valider |
| 5 | `frontend/src/mockProfiles.js`                                                          | données de démo. **Encore référencé en Profiling.jsx pour la soutenance ?**                 | conserver si utile, sinon retirer |
| 6 | `backend/tests/test_risk_score.py` vs `forensic-engine/tests/test_risk_score.py`       | contenus différents — peut-être un test d'intégration vs unitaire                            | clarifier / fusionner / renommer |
| 7 | `geoip/` racine vs `forensic-engine/GeoLite2-*.mmdb`                                   | possible duplication des bases GeoIP                                                         | vérifier qui lit quoi          |
| 8 | `chatbot/` racine (`hive_chat.py`) vs `frontend/src/components/hive-chat.js`           | un est Python (backend chat), l'autre JS (UI terminal) — **pas un doublon**, mais à documenter |
| 9 | Branches mortes : `pzyy`, `ismail`, `ismail2`, `zinoba`, `audit/report-pipeline-2026-05-22` | à nettoyer après merge (hors scope cleanup code)                                            | à confirmer                    |

---

## 5. Documentation existante — incohérences

- **README.md** déclare **5 sprints** (S1-S4 ✅/🔄, S5 ⏳ Pending). La mission indique **4 sprints**. À aligner.
- README mentionne aussi une architecture en **5 couches** dans la description : « honeypots → ETL → forensic engine → REST API → dashboard ». La mission prescrit **4 couches** (C1-C4 où C4 = Backend+Frontend+Reporting). À aligner.
- `docs/` contient **plusieurs audits sprint3 redondants** : `sprint3_audit.md`, `sprint3_audit_final.md`, `sprint3_audit_v2.md`, plus `sprint4_audit.md`, `AUDIT_REPORT.md`, `forensic_engine_reference.md` (nouveau). → consolider en un seul audit par sprint + un rapport global.
- Pas de `CHANGELOG.md`.
- `docs/architecture.md` existe (à relire en Phase 4 pour réécriture cohérente).

---

## 6. Métriques de départ (référence avant cleanup)

```
Branches locales  : 7        Branches distantes : 5
Commits totaux    : 193
Modifs non commit : 53 (40 M + 4 D + 9 ??)
Dossiers __pycache__ tracés sur disque : 11
Modules Python (engine) : 14
Pages SPA (paires JSX+HTML) : 18
Templates de report      : 3 (dont 1 suspect)
Fichiers d'audit sprint  : 6
```

---

## 7. Plan proposé (rappel des Phases — pour validation)

- **Phase 0** ✅ (ce document)
- **Phase 1** — Nettoyage : valider §3+§4, puis appliquer suppressions et durcir `.gitignore`. Tests scratch déplacés dans `archive/old-tests/` avant suppression définitive.
- **Phase 2** — Format + refactor léger : installer `ruff` (sans le commiter aux deps runtime), formater Python, déduplication évidente, logging propre.
- **Phase 3** — Docstrings/commentaires **en français** sur le Forensic Engine, les routes FastAPI, et la logique non triviale du SPA (`app.js`, loader dynamique, Bearer auto).
- **Phase 4** — Refonte `README.md` + `docs/` (4 couches, 4 sprints), `CHANGELOG.md`.
- **Phase 5** — Smoke test (`docker compose config`, imports Python, grep des symboles retirés).
- **Phase 6** — Commits atomiques par phase, rapport final dans ce même fichier, PR laissée à votre review.

---

## 8. Questions à valider avant Phase 1

1. **B-1** : créer `develop` depuis `main` (a) ou partir directement de `main` (b) ?
2. **B-2** : que faire des 50 changements non commités ?
3. §4 ligne 3 : confirmer le template de report en production (`report.html` jetable ?).
4. §4 ligne 5 : garder ou retirer `mockProfiles.js` ?
5. §4 ligne 6 : doublon `test_risk_score.py` — fusionner ou conserver les deux ?
6. §4 ligne 9 : faut-il aussi nettoyer les branches mortes (hors scope strict du cleanup code) ?
7. Outillage : OK pour introduire `ruff` **en outil de dev uniquement** (pas dans `requirements.txt`) pour le formatage Phase 2 ?

**STOP — j'attends vos réponses avant d'enchaîner.**

---

# PHASE 1 — Inventaire pour validation (RIEN n'a été supprimé)

> État git au début de la Phase 1 :
> - Branche : `chore/finalization-cleanup` (créée depuis `main` après commit `56a68a2`).
> - Sur `main` : commit `56a68a2 feat: finalize platform — état projet complet` intègre
>   les 50 changements en attente + dé-track 27 caches Python + 1 `package-lock.json`
>   racine vide. Décision actée : pas de branche `develop`.
> - Sur la branche cleanup : seuls `M .env`, `?? FINALIZATION_AUDIT.md`, `?? package-lock.json` (résidu disque) restent.

Chaque suspect est listé avec : preuve grep, verdict, action proposée, risque.
**Aucune suppression ne sera appliquée sans votre validation explicite.**

---

## LISTE A — Code mort présumé

### A-1 : Chaîne `POST /api/reports/generate` (template "simple")

**Faits :**
- `frontend/src/api.js:127-129` définit `generateReport()`, `reportDownloadUrl()`, `reportStixUrl()`.
- **Aucun composant SPA ne les appelle** :
  ```
  $ grep -rn "generateReport\|reportDownloadUrl\|reportStixUrl" frontend/src
  → seules les 3 définitions ; zéro consommateur.
  ```
- Côté backend, la chaîne complète est encore câblée :
  - `routers/reports.py:1655` → `POST /generate`
  - `routers/reports.py:1670` → `GET ""` (liste)
  - `routers/reports.py:1676` → `GET /{id}/download`
  - `routers/reports.py:1696` → `POST /{id}/stix`
  - tous appellent `get_reports().*` → `services/report_service.py` (450 l) → `report.html` (118 l).
- L'autre chaîne `/api/reports/forensic/{sid}/generate` (route 2151) utilise `forenhive_rapport_v2.html` / `_fr.html` — **c'est elle que le SPA utilise** (Reporting.jsx, reporting.html).

**Risque :** ces endpoints peuvent être consommés par un client externe (intégration SIEM, export STIX 2.1 mentionné comme livrable). **Pas de signal qu'ils sont morts hors-SPA.** Le STIX export est même mentionné dans le README comme un livrable Sprint 5.

**Verdict :** **NE PAS supprimer.** Documenter en Phase 3 que ces endpoints existent pour usage externe et que le SPA n'expose volontairement aucun bouton. Vous confirmez ?

### A-2 : Doublon `test_risk_score.py` (backend ↔ engine)

**Faits :**
- `forensic-engine/tests/test_risk_score.py` (518 l) : test unitaire complet — un test par signal (`_signal_reputation`, `_signal_anonymization`, …). Importe directement depuis `risk_score`.
- `backend/tests/test_risk_score.py` (189 l) : test de **contrat cross-package** — ajoute `forensic-engine/` au `sys.path` et vérifie que le backend peut importer `score_session` + bindings `risk_thresholds`.

**Verdict :** **rôles distincts, conserver les deux.** Renommage clarifiant proposé :
- `backend/tests/test_risk_score.py` → `backend/tests/test_risk_score_integration.py`

OK pour le renommage ?

### A-3 : Doublon `geoip/` racine ↔ `forensic-engine/GeoLite2-*.mmdb`

**Faits :**
- `geoip/GeoLite2-ASN.mmdb` (6.6 MB) + `GeoLite2-City.mmdb` (62.9 MB) — **67 Mo** au total à la racine.
- `forensic-engine/GeoLite2-ASN.mmdb` + `GeoLite2-City.mmdb` — mêmes fichiers, chemin lu par le code :
  ```
  forensic-engine/config.py:46  GEOIP_CITY_DB = ".../GeoLite2-City.mmdb"  (dans /app/ du conteneur)
  forensic-engine/enricher.py:107  geoip2.database.Reader(config.GEOIP_CITY_DB)
  ```
- Le Dockerfile de l'engine copie depuis `forensic-engine/` vers `/app/`. **`geoip/` racine n'est référencé nulle part dans le code Python.**

**Risque :** est-ce un volume monté ailleurs (logstash GeoIP filter par ex.) ?

```
$ grep -rn "geoip\|GeoLite" pipeline docker-compose.yml
```
À lancer avant suppression. Si rien : on supprime `geoip/` racine et on économise 67 Mo + on évite la double maintenance lors des updates MaxMind.

**Verdict :** **à valider après grep complémentaire.** OK pour que je fasse le grep et propose la suppression si confirmé non utilisé ?

### A-4 : `chatbot/` — chevauchement avec `services/ollama_service.py`

**Faits :**
- `chatbot/hive_chat.py` existe (script Python lancé en standalone).
- `chatbot/hive` est un script shell exécutable (281 octets — sans doute un wrapper `python hive_chat.py`).
- **Aucun import** depuis `backend/` ou `frontend/` vers `chatbot/` :
  ```
  $ grep -rn "from chatbot\|import chatbot" backend forensic-engine frontend
  → vide.
  ```
- `frontend/src/components/hive-chat.js` est l'UI terminal (sans rapport).
- `backend/services/ollama_service.py` est le client Ollama du backend FastAPI (le vrai chemin de prod).

**Verdict :** **`chatbot/` est probablement un prototype standalone abandonné**, remplacé par `services/ollama_service.py`. À archiver vers `archive/chatbot/` (pas supprimer définitivement avant votre confirmation). OK ?

### A-5 : Imports inutilisés / dead code dans modules Python

Pas encore scanné — nécessite `ruff check --select F401,F841,E501` (Phase 2, après installation de ruff en outil dev). Je remonterai la liste avant de toucher quoi que ce soit.

### A-6 : `frontend/src/mockProfiles.js`

**Faits :** activement utilisé par `Profiling.jsx:847` (chargement dynamique pour le bouton "Load Demo Profiles") et `profiling.html:1267`. **Pas mort.** ✅ (cf. votre instruction : utile pour la soutenance.)

### A-7 : `print()` "debug oublié" ?

Aucun trouvé dans le code de production. Les `print()` détectés sont **tous légitimes** (CLI standalone) :
- `forensic-engine/profiler.py:657-660` → bloc `if __name__ == "__main__"` (CLI).
- `forensic-engine/verify_coc.py` → outil CLI complet.
- `forensic-engine/db/init_db.py` → script d'init au démarrage Docker.

Aucun `except:` nu trouvé ✅.

---

## LISTE B — Fichiers inutiles (caches, artefacts, résidus)

### B-1 : Caches Python sur disque

**Faits :** 11 dossiers `__pycache__/` (déjà dé-trackés en `56a68a2`, restent sur disque).
3 dossiers `.pytest_cache/` (racine, `backend/`, `forensic-engine/`).

**Action proposée :** `find . -type d -name __pycache__ -exec rm -rf {} +` et idem pour `.pytest_cache`. Risque nul.

### B-2 : `frontend/dist/` (1.3 MB)

**Faits :** non tracké en git, déjà couvert par `.gitignore`. Artefact de `npm run build` (le Dockerfile frontend rebuild dans une image multi-stage, donc inutile sur disque).

**Action proposée :** `rm -rf frontend/dist/`. Risque nul (sera regénéré au prochain `docker compose build`).

### B-3 : `package-lock.json` racine (88 octets, vide)

**Faits :** déjà dé-tracké en `56a68a2`. Contenu : `{ "name": "forenhive", "lockfileVersion": 3, "requires": true, "packages": {} }`. Résidu d'un `npm install` lancé à la racine sans `package.json`.

**Action proposée :** `rm package-lock.json`. Risque nul.

### B-4 : `.vscode/` (préférences IDE)

**Faits :** `.gitignore` couvre déjà. Vérifier si tracé.

```
$ git ls-files .vscode
```
Si tracé → `git rm --cached -r .vscode`. Sinon ne rien faire.

### B-5 : Doublon `.env.example` racine vs `backend/.env.example`

**Faits :** **contenus différents** (le racine fait 40+ lignes, l'autre 1 ligne d'après le diff partiel). À investiguer plus précisément avant action — peut-être que `backend/.env.example` est un brouillon obsolète. Question pour vous : préférez-vous **1 seul `.env.example` consolidé à la racine** (avec une section par service), ou **conserver les deux** (racine = global, backend = spécifique) ?

### B-6 : 🚨 `.env` tracé en git malgré `.gitignore` (sécurité)

**Faits critiques :**
- `git ls-files | grep -E '^\.env$'` → **`.env` est tracé.**
- `.gitignore` ligne 2 ET ligne 69 le liste (donc ignoré pour nouveaux fichiers mais le tracé historique persiste).
- Le `.env` contient probablement des credentials (DB, Twilio, VirusTotal API key, AbuseIPDB, Shodan, JWT secret, mot de passe admin initial…).

**Action proposée — hors scope strict du cleanup, MAIS bloquant pour la soutenance :**
1. **Rotation immédiate** de tous les secrets contenus (clés API, mots de passe, JWT secret).
2. `git rm --cached .env` + commit.
3. Optionnellement : purge historique via `git filter-repo` (lourd, casse les forks ; à discuter — si le dépôt n'a pas encore été poussé public, suffisant de juste dé-tracker maintenant).

**Question :** voulez-vous que je gère le dé-tracking dans cette branche, en supposant que vous faites la rotation des secrets en parallèle ? Ou bien on laisse `.env` intouché tant que la rotation n'est pas faite ?

### B-7 : Branches mortes

**Faits :** branches locales `pzyy`, `ismail`, `ismail2`, `zinoba`, `audit/report-pipeline-2026-05-22` sont mergées ou abandonnées.

**Action proposée :** hors scope strict du cleanup code (c'est de l'hygiène git). À traiter manuellement après merge de la PR finalisation. **Pas d'action de ma part.**

---

## LISTE C — Tests scratch / debug à archiver

### C-1 : (vide)

**Aucun test scratch détecté.** Les seuls `test_*.py` du dépôt sont les 2 `test_risk_score.py` traités en A-2 (suites structurées, à garder).

`backend/tests/` ne contient que `test_risk_score.py` (M en cours). Les `__pycache__` annonçaient `test_alert_dedup`, `test_auth`, `test_stix` — vérifions si les fichiers `.py` correspondants existent encore :

```
$ ls backend/tests/
```
À faire avant tout pour confirmer qu'aucun `.py` n'a été supprimé sans nettoyer son cache associé.

**Verdict provisoire :** rien à archiver dans `archive/old-tests/`. Si l'inventaire complet de `backend/tests/` révèle des `.py` actifs non listés dans le PHASE 0, je remonterai.

---

## Tableau de décision attendu

| ID  | Action proposée                                              | OK ? |
| --- | ------------------------------------------------------------ | ---- |
| A-1 | Conserver chaîne `/api/reports/generate` (usage externe)     |  ?   |
| A-2 | Renommer `backend/tests/test_risk_score.py` → `_integration.py` |  ?   |
| A-3 | Si grep `geoip` négatif : supprimer `geoip/` racine (-67 Mo) |  ?   |
| A-4 | Archiver `chatbot/` vers `archive/chatbot/`                  |  ?   |
| A-5 | Phase 2 : scan `ruff F401/F841`, je remonte avant action     |  ?   |
| B-1 | `rm -rf` les `__pycache__/` et `.pytest_cache/` (disque)     |  ?   |
| B-2 | `rm -rf frontend/dist/`                                      |  ?   |
| B-3 | `rm package-lock.json` (racine)                              |  ?   |
| B-4 | Si `.vscode` tracé : `git rm --cached -r .vscode`            |  ?   |
| B-5 | Consolider `.env.example` (1 fichier ou 2) ? Stratégie ?     |  ?   |
| B-6 | 🚨 `.env` : dé-tracker maintenant ou après rotation secrets ?|  ?   |
| C-1 | Aucune action (pas de scratch).                              |  ✓   |

**STOP — j'attends vos décisions ligne par ligne avant toute suppression / déplacement.**

