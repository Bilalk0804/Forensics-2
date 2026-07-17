# CIAP — Crime Intelligence & Analytical Platform (PRD)

## Original Problem Statement
Karnataka State Police / State Crime Records Bureau (SCRB) needs to move beyond
manual Excel silos to an integrated crime intelligence platform delivering:
(1) advanced visualization + geospatial hotspot maps, (2) network / link
analysis and repeat-offender tracking, (3) AI-driven predictive risk scoring
& anomaly detection, (4) spatiotemporal pattern & trend discovery.

## Architecture
- Frontend: React 18 (CRA) + Tailwind + Recharts + react-leaflet + react-force-graph-2d
- Backend: FastAPI + Motor (MongoDB) + PyJWT + bcrypt + numpy + scikit-learn
- Data: 900 synthetic FIRs across 30 Karnataka districts (2-year window)
- Auth: JWT Bearer tokens (12h expiry), 3 roles (SCRB Admin, District Officer, Station Officer)

## User Personas
- **SCRB Admin** — state-wide oversight, risk leaderboard, all districts
- **District Officer** — district-scoped operational view
- **Station Officer** — station-level case management

## Core Capabilities (Delivered · 2026-01-17)
- Executive Dashboard: 6 KPIs, monthly trend area chart, status mix pie, top-district bars, crime-head volume, emerging trend alerts (red-zone pulse), Top-5 AI risk leaderboard
- Geo Intelligence: Karnataka choropleth map with hotspot circles + KMeans cluster overlay + district ranking + day-of-week × hour-of-day heatmap grid
- Network & Link Analysis: force-directed node graph (case ↔ suspect ↔ victim ↔ location ↔ MO), repeat-offender ringed nodes, entity inspector
- Predictive Intelligence: composite risk score (45% volume · 25% growth · 20% heinous ratio · 10% urbanization; z-normalized), anomaly signals (z ≥ 1.8), KMeans hotspot scatter
- Case Explorer: filterable/searchable FIR list, paginated, drill-down drawer with complainant, victims, accused (with repeat flag), arrests, chargesheet, linked cases (shared accused)
- Repeat Offender Registry: profiles with 3+ cases, cross-jurisdictional dossier + case timeline + signature MO

## Testing Status
- Backend: 25/25 pytest tests passed
- Frontend: All 6 pages verified via Playwright
- No critical issues in iteration_1

## Backlog / Future
- P1: Split backend server.py into routers (auth/analytics/predict/network/cases)
- P1: Loading & error states on all data fetches
- P1: Export to PDF/CSV for reports
- P2: District-level drill-down to police-station map layer
- P2: Real ingest pipeline for CCTNS / actual FIR XML feeds
- P2: LLM-generated intelligence briefs (Claude/Gemini) once budgeted
- P2: httpOnly cookie auth for hardened security
- P2: Role-scoped views (auto-filter to user's district/station)
- P3: Push notifications for critical anomalies
- P3: Multi-lingual (Kannada + English)

## Key Files
- /app/backend/server.py — all FastAPI endpoints + seed logic
- /app/backend/tests/test_ciap_backend.py — 25 regression tests
- /app/frontend/src/App.js — router + AuthProvider
- /app/frontend/src/pages/{Login,Dashboard,GeoMap,Network,Predictive,Cases,Offenders}.js
