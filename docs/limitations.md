# Limitations

Last updated: 2026-11-18

These limitations are part of the design and are disclosed in the UI (*About & Limits* page) and in
the academic report. They do not indicate bugs; they define the system's honest operating envelope.

## 1. Model performance

| Aspect | Limitation |
|---|---|
| Email model | Test F1 0.9819 is measured against a corpus whose legitimate messages are from **2003** while phishing spans **2019–2025**. The temporal mismatch can inflate measured performance. Do not generalise to modern ham without re-evaluation. |
| URL model | Test F1 0.7403, ROC-AUC 0.8421. Substantially harder than email detection; lexical host features alone cannot catch novel campaigns or page-content-based phishing. |
| False positives | Seen on unseen legitimate hosts and free-hosting platforms (e.g. subdomains of blogspot.com, github.io). A high score is supporting evidence, not proof. |
| Calibration | The 0–100 thresholds and module weights are product heuristics, not scientifically calibrated probabilities. |

## 2. Scope of analysis

- **No live reputation:** no WHOIS, DNS, IP, TLS certificate, sandbox detonation, screenshot or blocklist lookup.
- **No URL fetching:** submitted URLs are parsed as text only. Redirect chains, final destination, page content and active scripts are invisible.
- **No attachment analysis:** attachments are ignored; only URLs in body text are extracted.
- **Static graph:** the domain graph is a corpus snapshot; new domains absent from it receive `no_data` graph risk, which is **not** evidence of safety.
- **No GNN:** graph analytics only (NetworkX); no Graph Neural Network is claimed or implemented.

## 3. Data limitations

- Benign URL corpora are homepage-heavy; path features are excluded from the URL model to avoid a
  dataset artefact where deep legitimate links (e.g. `github.com/microsoft/vscode`) score malicious.
- The Kaggle benign sample is constructed around real ranked domains rather than crawled pages.
- No synthetic data; all samples are real URLs/emails from public corpora.

## 4. Operational limitations

- Single-user academic demo: no authentication, authorisation, RBAC or multi-tenancy.
- SQLite single-writer; not suitable for concurrent production use.
- No model-retraining loop, no streaming ingestion, no drift monitoring.
- Frontend bundle is a single chunk (~660 kB) because Recharts is bundled eagerly.
- No migration framework; schema created via SQLAlchemy `create_all`.

## 5. Optional LLM limitations

- Disabled by default; when enabled as a fallback, email content is sent to an external provider and disclosed.
- Strict JSON validation may reject provider output; failure falls back to rules-only.
- Not tested against a live provider in CI; failure paths are mocked.

## 7. Local LLM limitations

- The local semantic model is a **fine-tuned DistilBERT text classifier**, not a generative LLM and
  not pretrained from scratch. It emits a phishing probability, not free-form reasoning.
- Its training text template is `Subject/URLs/Body`; sender text supplied at inference is extra
  context the classifier was not explicitly trained on.
- It inherits the same 2003 ham / 2019–2025 phishing corpus mismatch as the classical email model.
- **Measured artefact:** its held-out test metrics are all 1.0000 (896 test rows), which reflects near-perfect separation of this specific corpus, not real-world generalisation. A spot check with short, modern legitimate messages (e.g. a meeting reminder or a shipping receipt) produced phishing probabilities around 0.97–0.999. Treat this component as supporting evidence only; it is one weighted module (0.10) and never overrides the other signals.
- On a 4 GB GPU it uses fp16 and a 384-token window; very long emails are truncated.
- The optional `torch`/`transformers` stack is heavy (~4 GB installed); the backend still works
  without it, with the semantic component excluded from risk scoring.

## 6. Academic context

- Built for SIH25159 (AICTE), CSE473, on a student laptop scale with no paid infrastructure.
- Intended as a working demonstrator with genuine trained models, reproducible metrics and honest
  error reporting — not as a production email-security gateway.
