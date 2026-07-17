# CIAP Test Credentials

## Application
Crime Intelligence & Analytical Platform for Karnataka State Police / SCRB.
Base URL (frontend): value of `REACT_APP_BACKEND_URL` in `/app/frontend/.env`

## Users (seeded on startup)

| Role | Email | Password |
|------|-------|----------|
| SCRB Admin | admin@ksp.gov.in | Admin@1234 |
| District Officer | district@ksp.gov.in | District@1234 |
| Station Officer | station@ksp.gov.in | Station@1234 |

## Auth Endpoints
- POST `/api/auth/login`   -> `{ email, password }` -> `{ access_token, user }`
- GET  `/api/auth/me`      (Authorization: Bearer <token>)

## Key API Endpoints (all require Bearer token)
- GET `/api/reference` — districts / crime heads / gravities / statuses
- GET `/api/analytics/kpi` — dashboard KPIs (supports filters)
- GET `/api/analytics/by_district`
- GET `/api/analytics/by_crime_head`
- GET `/api/analytics/status_mix`
- GET `/api/analytics/trends?days=365`
- GET `/api/analytics/heatmap?days=180`
- GET `/api/predict/risk` — statistical risk score per district
- GET `/api/predict/anomalies` — z-score anomaly signals
- GET `/api/predict/clusters` — KMeans hotspot clusters
- GET `/api/network/graph?limit=60`
- GET `/api/network/repeat_offenders`
- GET `/api/network/offender/{person_id}`
- GET `/api/cases?district=...&crime_head=...&limit=25&skip=0&q=...`
- GET `/api/cases/{case_id}`

## Seed Data
- 900 synthetic FIRs across 30 Karnataka districts
- 2-year time window; recent 60d Cybercrime spike simulated in Bengaluru Urban
- 25 repeat offenders reused across ~22% of accused entries
- Crime heads: Cybercrime, Property Theft, Narcotics (NDPS), Violent Crime, Financial Fraud, Organized Crime, Crime Against Women, Public Order
