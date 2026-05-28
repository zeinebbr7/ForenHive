# Sprint 5 — React SPA + Reporting

## Sprint Overview

- **Sprint name:** Frontend SPA & Reporting
- **Sprint number:** 5
- **Goal:** Ship a single-page operator console for the SOC analyst — every artefact produced by Sprints 1–4 must be reachable, filterable, and exportable as a PDF report, in English or French.

## Objectives

- Build a Vite + React 18 SPA served by Nginx (`forenhive-frontend`, port 3000), proxying `/api` to the backend.
- Implement role-based routing (operator vs. admin).
- Provide a bilingual UI (EN/FR) with a single translations table.
- Embed the HIVE chat assistant.
- Drive PDF report generation from the SPA and stream the result to the operator.

## Tasks Completed

- **18 lazy-loaded pages** wired in [`App.jsx`](../../frontend/src/App.jsx).
- **Role-based routing** — `/health`, `/evidence`, `/honeypots`, `/access`, `/config` require `admin`; everything else needs only authentication.
- **Bilingual UI** via `LanguageContext` + single translations table.
- **HIVE chat widget** ([`hive-chat.js`](../../frontend/src/components/hive-chat.js)) talking to `/api/chat`.
- **Reporting flow** — SPA triggers PDF generation, receives WeasyPrint output, and offers it as a download (EN/FR share the same trigger endpoint).
- **Boot watchdog + global error handler** in `index.html` that takes over the page if the bundle crashes, surfacing the stack trace to the operator.

## Technical Details

- `vite` for dev (`npm run dev`) and prod build (`npm run build` → static files served by Nginx).
- Routing via `react-router-dom@6` with a single guarded `Layout` shell.
- State is intentionally **context-only** (Auth, Language, Modal) — no Redux/Zustand. Each page owns its own fetch state.
- Charts via `recharts`, map via raw `leaflet` (no `react-leaflet` wrapper — dropped during cleanup).
- Nginx splits static delivery from `/api` reverse proxy in [`forenhive-locations.inc`](../../frontend/forenhive-locations.inc), included from [`nginx.conf`](../../frontend/nginx.conf).

### Build + serve

- [`vite.config.js`](../../frontend/vite.config.js) — React plugin, `@` alias for `src/`, dev proxy `/api → http://localhost:8000`.
- [`package.json`](../../frontend/package.json) — runtime (`react`, `react-dom`, `react-router-dom`, `recharts`, `leaflet`), dev (`vite`, `@vitejs/plugin-react`).
- [`Dockerfile`](../../frontend/Dockerfile) — multi-stage: Node builder → Nginx runtime. Copies the location include into `/etc/nginx/conf.d/`.
- [`nginx.conf`](../../frontend/nginx.conf) — top-level server block, delegates to the include.
- [`forenhive-locations.inc`](../../frontend/forenhive-locations.inc) — SPA fallback (`try_files … /index.html`), `/api` reverse-proxy, static-asset cache headers.
- [`index.html`](../../frontend/index.html) — Vite entry HTML with boot watchdog + global error handler.

### App skeleton

- [`src/main.jsx`](../../frontend/src/main.jsx) — `createRoot` mount, cancels the boot watchdog, imports `style.css`.
- [`src/App.jsx`](../../frontend/src/App.jsx) — providers (`LanguageProvider` → `AuthProvider` → `ModalProvider`), Suspense fallback, route table.
- [`assets/style.css`](../../frontend/assets/style.css) — global theme (CSS variables, dark/light), shared component classes.

### Cross-cutting

- [`src/api.js`](../../frontend/src/api.js) — `fetch` wrapper: prepends JWT, throws on non-2xx, JSON-decodes.
- [`src/constants.js`](../../frontend/src/constants.js) — enums and shared display tables (risk levels, MITRE labels, severity colours).
- [`src/utils.js`](../../frontend/src/utils.js) — formatters (dates, durations, IPs).
- [`src/mockProfiles.js`](../../frontend/src/mockProfiles.js) — demo dataset for the Profiling page's "Demo Data" button.

### Contexts

- [`contexts/AuthContext.jsx`](../../frontend/src/contexts/AuthContext.jsx) — JWT lifecycle, current user + roles.
- [`contexts/LanguageContext.jsx`](../../frontend/src/contexts/LanguageContext.jsx) — EN/FR switch, persisted in `localStorage`.
- [`contexts/ModalContext.jsx`](../../frontend/src/contexts/ModalContext.jsx) — single global modal stack.
- [`i18n/translations.js`](../../frontend/src/i18n/translations.js) — full EN/FR table consumed by `useLanguage().t(...)`.

### Layout / guards

- [`components/Layout.jsx`](../../frontend/src/components/Layout.jsx) — authenticated shell: sidebar, top bar, language switch, lazy-loaded HIVE trigger.
- [`components/ProtectedRoute.jsx`](../../frontend/src/components/ProtectedRoute.jsx) — redirects unauthenticated users to `/login`, enforces role checks.
- [`components/hive-chat.js`](../../frontend/src/components/hive-chat.js) — HIVE assistant widget (multi-session terminal UI).

### Pages (`src/pages/`)

| File | Purpose |
|------|---------|
| [`Landing.jsx`](../../frontend/src/pages/Landing.jsx) + [`landing.css`](../../frontend/src/pages/landing.css) | Public landing page (marketing surface, animated log feed). |
| [`Login.jsx`](../../frontend/src/pages/Login.jsx) | Auth form. |
| [`Dashboard.jsx`](../../frontend/src/pages/Dashboard.jsx) | Redirects to `/stats` (legacy default). |
| [`Stats.jsx`](../../frontend/src/pages/Stats.jsx) | KPI grid + time-series charts of honeypot traffic. |
| [`Alerts.jsx`](../../frontend/src/pages/Alerts.jsx) | Live alert list, ack/suppress actions. |
| [`Sessions.jsx`](../../frontend/src/pages/Sessions.jsx) | Forensic-session table with filters. |
| [`Timeline.jsx`](../../frontend/src/pages/Timeline.jsx) | Per-session millisecond timeline view. |
| [`Reconstruction.jsx`](../../frontend/src/pages/Reconstruction.jsx) | Step-by-step attack reconstruction. |
| [`Evidence.jsx`](../../frontend/src/pages/Evidence.jsx) (admin) | Chain-of-custody browser + verification. |
| [`Profiling.jsx`](../../frontend/src/pages/Profiling.jsx) | Suspect-profile dossiers (LLM output, demo-data button). |
| [`GeoMap.jsx`](../../frontend/src/pages/GeoMap.jsx) | Leaflet world map of attacker IPs. |
| [`Reporting.jsx`](../../frontend/src/pages/Reporting.jsx) | Triggers PDF report generation (EN/FR), downloads result. |
| [`Honeypots.jsx`](../../frontend/src/pages/Honeypots.jsx) (admin) | Per-honeypot status + raw-log peek. |
| [`Access.jsx`](../../frontend/src/pages/Access.jsx) (admin) | User & role management. |
| [`Settings.jsx`](../../frontend/src/pages/Settings.jsx) | Per-user preferences (theme, language, notifications). |
| [`Config.jsx`](../../frontend/src/pages/Config.jsx) (admin) | Platform feature flags / thresholds. |
| [`Audit.jsx`](../../frontend/src/pages/Audit.jsx) | Audit-log viewer. |
| [`Health.jsx`](../../frontend/src/pages/Health.jsx) (admin) | Service health board (backend, ES, PG, engine, Ollama). |

### Reporting (backend collaboration)

Reporting is owned by the backend (`reports.py` router + WeasyPrint templates in Sprint 4) but the SPA is what drives it:

- [`Reporting.jsx`](../../frontend/src/pages/Reporting.jsx) collects the session id and language toggle, POSTs to `/api/reports/{id}?lang=en|fr`, and streams the returned PDF as a download.
- Both templates (`forenhive_rapport_v2.html` and `_fr.html`) render with `StrictUndefined`, so any missing context key surfaces as a 500 instead of a blank cell.

## Challenges & Solutions

- **`react-leaflet` wrapper friction** — dropped during cleanup in favour of raw `leaflet` to avoid version-pinning churn against React 18.
- **Hidden bundle crashes** — added a boot watchdog + global error handler in `index.html` so a broken build does not silently leave the operator on a white screen.
- **Avoiding state-management sprawl** — deliberately kept to React contexts (Auth, Language, Modal) instead of introducing Redux/Zustand; each page owns its own fetch state.
- **Lazy loading for 18 pages** — `React.lazy` + a Suspense shell in `App.jsx` keeps the first-paint bundle small.

## Outcomes / Deliverables

- Production SPA served by Nginx on `:3000` proxying `/api` to the backend.
- Working EN/FR bilingual UI with role-gated admin pages.
- Functional reporting flow producing downloadable PDFs in both languages.
- Validation gates passed:
  1. `npm run build` produces a `dist/` that Nginx serves at `:3000`.
  2. Logging in lands on `/stats`; admin-only routes blocked for non-admin tokens.
  3. Switching EN ↔ FR re-renders every page with translated strings.
  4. GeoMap, Stats, and Timeline each render at least one real data point from the live backend.
  5. Triggering a report from `Reporting.jsx` produces a downloadable PDF in both languages.

## Notes / Next Steps

- All five sprints are now end-to-end: honeypots → pipeline → forensic engine → backend → SPA + reporting.
- No further sprint is planned in the current scope; future work would address operational hardening (e.g. backups, observability dashboards) rather than new product surface.
