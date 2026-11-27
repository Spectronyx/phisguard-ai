# Testing

Last updated: 2026-11-18

All tests run fully offline: no network access, no LLM key, no URL fetching.

## 1. Backend tests

```bash
cd backend
../.venv/bin/pytest -q
```

Result: **83 passed, 1 warning** (fully offline; no GPU or LLM key required).

Test files:

| File | Coverage |
|---|---|
| `tests/conftest.py` | Shared fixtures: isolated SQLite DB per test, real artifacts, rules-only fallback settings |
| `tests/test_url_features.py` | URL parsing, scheme/HTTPS handling, registrable domains, brand impersonation, popularity flag, deterministic rules |
| `tests/test_risk_engine.py` | Missing-module exclusion, threshold boundaries, corroboration bonus capping |
| `tests/test_models.py` | Artifact loading, graceful degradation, email/URL separation, popularity calibration, raw vs calibrated probability |
| `tests/test_graph.py` | Popular-domain benign context, known-malicious corpus hosts, unknown domain handling, metadata honesty |
| `tests/test_llm.py` | External API: disabled-by-default, mocked success, network failure + retry, client-error non-retry, schema validation, prompt-injection resistance |
| `tests/test_local_llm.py` | Local DistilBERT service (mocked torch/tokenizer), privacy (`sent_to_provider=false`), artifact checks, local-first routing and API fallback |
| `tests/test_pipeline.py` | End-to-end email/URL analysis, benign/phish separation, rules-only fallback without artifacts, no-body-storage, sender-domain graph feeding |
| `tests/test_api.py` | Health/model status, URL/email responses, persistence round-trip, validation errors, pagination filters, dashboard stats/trend |

### Requirements enforced in tests

- **No fabricated metrics:** tests assert against real trained artifacts (`backend/artifacts/*`).
- **Graceful degradation:** `rules_only_settings` points at an empty artifacts directory; pipeline and API still return 200 with `unavailable`/`no_data` components.
- **LLM failure paths:** mock timeouts, network errors, 401, invalid JSON and wrong schema — every path degrades without crashing.
- **Local LLM is GPU-free in tests:** the transformer is fully mocked; tests never import real torch weights.
- **No URL fetch:** no test opens or resolves a submitted URL; all inputs are strings.
- **Body minimisation:** response `details` must not contain the full email body; persisted scans never echo it back.

## 2. Frontend build

```bash
cd frontend
npm run build
```

Result: TypeScript strict check passes, Vite production build succeeds (`dist/index.html`, ~660 kB
JS, ~24 kB CSS). The SPA is served by FastAPI when `frontend/dist` exists.

## 3. Quality gates performed

| Gate | Command | Result |
|---|---|---|
| Backend starts | `uvicorn app.main:app --port 8000` | 200 `/api/v1/health` |
| Backend tests | `../.venv/bin/pytest -q` | 83 passed |
| Frontend build | `npm run build` | built successfully |
| Email endpoint | POST `/analyze/email` | real model + rules output |
| URL endpoint | POST `/analyze/url` | real model + rules output |
| DB persistence | GET `/scans/{id}` round-trip | stored and retrievable |
| Demo scenarios | `python3 scripts/seed_demo.py` | 12 real scans seeded (14 total with UI capture), documented outputs |
