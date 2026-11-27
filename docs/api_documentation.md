# API Documentation

Last updated: 2026-11-18

Base URL: `http://127.0.0.1:8000/api/v1`

All responses are JSON. Error responses use standard HTTP status codes; validation failures return
`422` with a `{"detail": "Validation failed", "errors": [...]}` body.

---

## 1. Authentication

None in this single-user academic deployment. CORS allows configured origins only (default:
`http://localhost:5173`, `http://127.0.0.1:5173`).

---

## 2. Endpoints

### `GET /health`

Service, database and artifact readiness.

**Response:**

```json
{
  "status": "ok",
  "version": "1.0.0",
  "database": "ok",
  "artifacts_ready": true,
  "llm_enabled": false,
  "timestamp": "2026-11-18T00:00:00+00:00"
}
```

### `GET /models/status`

Artifact algorithms, metrics and LLM disclosure.

**Response:**

```json
{
  "email_model": {
    "name": "email_model",
    "available": true,
    "path": ".../email_model.joblib",
    "algorithm": "logistic_regression",
    "trained_at": "...",
    "metrics": { ... },
    "error": null
  },
  "url_model": {
    "name": "url_model",
    "available": true,
    "algorithm": "logistic_regression_host_char_c4",
    "metrics": { ... }
  },
  "domain_graph": { "name": "domain_graph", "available": true, ... },
  "inference_mode": "ml",
  "llm_enabled": false,
  "llm_configured": false,
  "llm_model": "gpt-4o-mini",
  "local_llm_enabled": true,
  "local_llm_available": true,
  "local_llm_model": "distilbert-base-uncased (fine-tuned locally)",
  "llm_backend": "local_distilbert",
  "notes": [ "..." ]
}
```

### `POST /analyze/email`

Analyse an email. The body is never stored.

**Request:**

```json
{
  "subject": "URGENT: Your SBI account will be suspended",
  "body": "Dear Customer, ...",
  "sender": "SBI Support <alerts@sbi-verify.xyz>",
  "urls": ["https://example.com/login"]
}
```

Validation: subject/body max 500/50,000 chars; sender valid email if provided; ≤10 URLs each ≤2,048
chars with a scheme/hostname; subject and body cannot both be empty.

**Response** (`AnalysisResponse`): `scan_id`, `scan_type`, `input_summary`, `classification`,
`risk_level`, `risk_score` (0–100), `model_confidence`, `indicators`, `components`, `explanation`,
`recommendation`, `llm_used`, `llm_sent_to_provider`, `created_at`, `details`, `url_results`.

### `POST /analyze/url`

Analyse one URL string. Never fetched.

**Request:** `{"url": "http://paypal-secure-login.xyz/verify-account"}`

Validation: ≤2,048 chars, no whitespace, scheme required or valid hostname.

### `GET /scans`

Paginated history with optional `search`, `classification` (`safe|suspicious|phishing`),
`scan_type` (`email|url`), `page` (≥1), `page_size` (1–100).

**Response:** `{"items": [...], "total": int, "page": int, "page_size": int, "pages": int}`

### `GET /scans/{id}`

Stored scan detail (reconstructed; full email body not available).

### `GET /dashboard/stats`

Aggregate statistics: counts, average risk score, distribution, recent scans, top indicators.

### `GET /dashboard/trend?days=14`

Daily scan/phishing trend points for up to 90 days.

---

## 3. Component contract

Every analysis component exposes:

| Field | Meaning |
|---|---|
| `name` | `email_model` / `url_model` / `email_rules` / `url_rules` / `graph` / `llm` (local or external) |
| `label` | Human-readable label |
| `status` | `ok`, `degraded`, `no_data`, `unavailable`, `error`, `skipped` |
| `score` | Module risk score 0–100, or null |
| `confidence` | Per-model confidence 0–1, or null |
| `weight` | Renormalised aggregation weight |
| `contribution` | `weight · score` |
| `explanation` | Human-readable rationale |
| `details` | Structured payload (probability, indicators, graph evidence, etc.) |

Missing modules are excluded from the risk mean rather than scored as zero.

---

## 4. Privacy and safety by design

- URLs are parsed as strings only; no HTTP request, DNS lookup, or sandbox detonation.
- Attachments are not accepted by the API and were ignored during dataset build.
- Full email bodies are not persisted; only ≤180-char summary, input hash and derived indicators.
- The local DistilBERT classifier runs in-process; `llm_sent_to_provider` stays `false` and
  `details.llm_backend` is `local_distilbert`.
- External LLM content is sent only when `LLM_ENABLED=true` **and** `LLM_API_KEY` is set **and** the
  local model is unavailable; every such scan is disclosed via `llm_sent_to_provider=true`.
- No API keys are stored in source; configuration via environment variables / `.env`.
