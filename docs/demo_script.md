# PhishGuard AI — Demo Script

Last updated: 2026-11-18

Run this end-to-end against a live backend. All outputs are real; nothing is hand-written.

## Prerequisites

1. Backend running:
   ```bash
   cd backend && ../.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```
2. (Optional) populate demo DB:
   ```bash
   python3 scripts/seed_demo.py   # 12 real scans via /api/v1/analyze/*
   ```
3. Frontend (optional; API demo works without it):
   ```bash
   cd frontend && npm run dev      # http://localhost:5173
   ```

## Scenario A — Brand-lookalike phishing URL (2 min)

1. Open URL Scanner.
2. Click "Brand lookalike" chip: `http://paypal-secure-login.xyz/verify-account`.
3. Click "Analyse URL".
4. Expected: risk 89/100, phishing/critical, model confidence 99.8%.
5. Show: "Brand impersonation (critical)", "Credential-related keywords", "High-abuse TLD"
   indicators; URL ML classifier 100/100 module risk; domain graph "No data" (not scored as zero).

## Scenario B — Popular bare domain stays safe (1 min)

1. URL Scanner → "Google" chip: `https://www.google.com/`.
2. Expected: risk 3/100, safe.
3. Show: model details `"popularity_calibrated": true`, raw probability reduced ×0.3; popularity
   is a weak prior, not a whitelist.

## Scenario C — Deep link on a popular host (1 min)

1. URL Scanner → "GitHub link" chip: `https://github.com/microsoft/vscode`.
2. Expected: safe/low (~18/100). Path depth is **not** treated as malicious by itself.

## Scenario D — Phishing email (2 min)

1. Open Email Scanner.
2. Click "Phishing example" chip (SBI account suspension, OTP request, lookalike link).
3. Click "Analyse email".
4. Expected: risk 98/100, phishing/critical, model confidence 99.97%.
5. Show: 11 indicators (brand impersonation, credential harvesting, account threat, suspicious
   embedded link, high-abuse TLD, …); email model contributes 29.62 points, URL model 31.57 points,
   local LLM 10.52 points; corroboration bonus applied.

## Scenario E — Dashboard & history (1 min)

1. Open Dashboard: 14 real scans (12 seeded + 2 created during screenshot capture), 9 phishing,
   1 suspicious, 4 safe, average risk 59.9. Counts come from the live database.
2. Open Scan History: table with filters/search/pagination; click a row → Scan Detail with full
   component breakdown and privacy notices.

## What to point out to examiners

- Every number comes from `backend/artifacts/metrics.json` (real training run) or the seeded demo
  scans (real API outputs).
- `model_confidence` ≠ `risk_score`.
- Missing graph/LLM components are `no_data`/`unavailable`, not zero-scored.
- URLs are never fetched; full bodies never stored; local LLM is private and on by default, the
  external API is off by default.
- About & Limits page lists all limitations honestly.
- Local LLM: expand the *LLM semantic analysis (DistilBERT)* component in any email result — it shows
  `backend: local_distilbert`, `sent_to_provider: false`, probability and device (`cuda`). Check
  `GET /api/v1/models/status` for `local_llm_available: true` and `llm_backend: local_distilbert`.

## Quick API smoke test

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/analyze/url \
  -H 'Content-Type: application/json' -d '{"url":"https://www.google.com/"}' \
  | python3 -m json.tool | grep -E 'risk_score|classification'
# expect "risk_score": 3, "classification": "safe"

curl -s http://127.0.0.1:8000/api/v1/health
# expect "status": "ok", "artifacts_ready": true
```
