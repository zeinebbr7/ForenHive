# API REST — ForenHive

Backend FastAPI exposé sur `:8000`. Toutes les routes sont préfixées par
`/api/` sauf `/health`. Auth JWT via header `Authorization: Bearer <token>`
(clé localStorage SPA : `forenhive.token`).

## Authentification (`/api/auth`)

| Méthode | URL | Auth | Description |
|---------|-----|------|-------------|
| POST | `/api/auth/login` | non | login form-data (username, password) → `{access_token}` |
| POST | `/api/auth/refresh` | Bearer | rafraîchit le token (rotation) |
| GET  | `/api/auth/me` | Bearer | renvoie l'utilisateur courant + rôle |

Codes : 200 / 401 (mauvaises creds) / 422 (validation).

## Chat (`/api/chat`)

| POST | `/api/chat` | public (token vérifié côté client) | SSE stream vers Mistral via Ollama |

## Sessions d'attaque (`/api/sessions`)

| GET | `/api/sessions` | Bearer | liste paginée des sessions (limit≤500, active_only) |
| GET | `/api/sessions/{session_id}` | Bearer | détail complet d'une session |

## Événements bruts (`/api/attacks`)

| GET | `/api/attacks` | Bearer | événements honeypot indexés en ES, pagination |

## Cartographie (`/api/geo`)

| GET | `/api/geo/heat` | Bearer | heatmap agrégée par pays/lat-lon |
| GET | `/api/geo/asn` | Bearer | top ASN attaquants |

## Alertes (`/api/alerts`)

| GET  | `/api/alerts/config` | Bearer | config d'alertes courante |
| PUT  | `/api/alerts/config` | Bearer admin | mise à jour |
| GET  | `/api/alerts/history` | Bearer | historique paginé |
| POST | `/api/alerts/test` | Bearer admin | envoi de test (mail/SMS/WA) |

## Profiling (`/api/profiling`)

| GET | `/api/profiling` | Bearer | liste des profils BAU générés |
| GET | `/api/profiling/{ip}` | Bearer | détail d'un profil par IP source |

## Rapports (`/api/reports`)

Chaîne **"legacy" simple** (template `report.html`) — exposée pour usage externe :

| POST | `/api/reports/generate` | Bearer | génère un rapport simple |
| GET  | `/api/reports` | Bearer | liste paginée des rapports |
| GET  | `/api/reports/{id}/download` | Bearer | télécharge le PDF |
| POST | `/api/reports/{id}/stix` | Bearer | export STIX 2.1 |

Chaîne **forensique complète** (templates `forenhive_rapport_v2*.html`) —
utilisée par la SPA :

| GET  | `/api/reports/forensic/sessions` | Bearer | sessions analysables |
| GET  | `/api/reports/forensic/sessions/{sid}/enrichment` | Bearer | données d'enrichissement |
| GET  | `/api/reports/forensic/{sid}/preview?lang=fr` | Bearer | preview HTML in-browser |
| POST | `/api/reports/forensic/{sid}/generate?lang=fr` | Bearer | génère et télécharge le PDF |
| GET  | `/api/reports/forensic/{sid}/detail` | Bearer | JSON complet du dossier |

Codes : 200 / 401 / 404 / 422 / 500 (engine render failed, log correlation_id).

## Risk Scores (`/api/risk-scores`)

| GET | `/api/risk-scores` | Bearer | liste paginée (ip_risk_scores PG) |
| GET | `/api/risk-scores/{ip}` | Bearer | score détaillé par IP (ventilation 9 signaux) |

## Forensic Engine (`/api/forensics`)

| GET  | `/api/forensics/status` | Bearer admin | statut dernier run |
| POST | `/api/forensics/run` | Bearer admin | déclenche un run manuel (background) |

## Honeypots (admin, `/api/honeypots`)

| GET  | `/api/honeypots/status` | Bearer admin | statut des conteneurs |
| POST | `/api/honeypots/{name}/start` | Bearer admin | démarrer un honeypot |
| POST | `/api/honeypots/{name}/stop` | Bearer admin | arrêter un honeypot |
| POST | `/api/honeypots/{name}/restart` | Bearer admin | redémarrer |

## Audit (admin, `/api/audit`)

| GET | `/api/audit/log` | Bearer admin | journal d'audit paginé |

---

## Codes HTTP communs

| Code | Sens |
|------|------|
| 200 | OK |
| 401 | non authentifié (token absent/expiré) |
| 403 | interdit (rôle insuffisant) |
| 404 | ressource introuvable |
| 422 | validation Pydantic échouée |
| 500 | erreur interne (engine, template render, DB) — log avec correlation_id |
| 503 | dépendance manquante (WeasyPrint indisponible) |

## Conventions

- Pagination : query params `limit` (≤ 500) + `offset` ou `cursor`.
- Tri : `?sort=field` / `?sort=-field` (descendant).
- Réponses listing : `{ "items": [...], "total": N }`.
- Bearer obligatoire sur toutes les routes sauf `/health`, `/api/chat`,
  `/api/auth/login`.
