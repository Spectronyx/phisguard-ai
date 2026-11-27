# CHANGELOG.md

## 2026-11-20 — Report heading colour fix

- Changed all 24 heading/title colours in `docs/report/PhishGuard_AI_Report_FINAL_V2.docx` from
  cyan (`22D3EE`) to black (`000000`) with white (`FFFFFF`) paragraph shading; body text unchanged.
- Regenerated the matching `PhishGuard_AI_Report_FINAL_V2.pdf` so both deliverables are consistent.
- Original DOCX backed up to `/tmp/PhishGuard_AI_Report_FINAL_V2_before_bw.docx`.

## 2026-11-18 — Local LLM trained and final delivery

- Completed the real GPU fine-tuning run: `distilbert-base-uncased` on the RTX 3050 Laptop (3.97 GB,
  fp16, 3 epochs, effective batch 16, 249.37 s). Artifact in `backend/artifacts/local_llm/`; real
  metrics in `backend/artifacts/local_llm_metrics.json` (896-row held-out test: accuracy, precision,
  recall, F1 and ROC-AUC all 1.0000).
- Disclosed the 1.0000 result as a corpus artefact (2003 ham vs 2019–2025 phishing) in methodology,
  limitations, viva notes, report and presentation rather than claiming real-world perfection.
- Reset and reseeded the demo DB; dashboard now has 14 real scans (12 seeded + 2 from UI capture),
  6 LLM-assisted. Recaptured all 6 screenshots against the final frontend build.
- Regenerated DOCX/PDF report and PPTX with the local LLM section and real metrics.
- Final gates: backend `83 passed, 1 warning`; frontend production build passes.

## 2026-11-18 — Local LLM added

- Added optional GPU/CPU stack (`backend/requirements-llm.txt`: torch 2.9.1, transformers 4.57.6,
  accelerate 1.12.0) and `backend/scripts/train_local_llm.py` to fine-tune DistilBERT on the real
  email corpus with the RTX 3050.
- New `LocalSemanticService` (`app/services/local_llm_service.py`) loads the fine-tuned artifact
  lazily, runs in-process inference and reports `sent_to_provider=false`.
- New `SemanticRouter` (`app/services/llm_router.py`): local first, external API only as fallback.
- Config: `LOCAL_LLM_ENABLED` (default true), `LOCAL_LLM_MAX_LENGTH`, `LOCAL_LLM_DEVICE`.
- Pipeline, explanation and `/models/status` now disclose which backend was used.
- Added `backend/tests/test_local_llm.py` (8 mocked, GPU-free tests); suite is now 83 passing.
- Documented in README, architecture, methodology, API, testing, limitations, viva notes and demo
  script; decision recorded as ADR-011.

## 2026-11-18 — Milestone: complete deliverables

- Trained URL model updated: hostname char 3–5 gram TF-IDF + host-centric numerics + Cisco
  Umbrella top-10k popularity prior; selected Logistic Regression C=4; test F1 0.7403, precision
  0.7652, recall 0.7170, ROC-AUC 0.8421 (3,576 test rows). Email model unchanged (F1 0.9819,
  ROC-AUC 0.9991).
- URL inference: popularity calibration (×0.3) for bare top-ranked domains suppresses false
  positives on github.com/google.com; raw probability retained in response.
- Graph rebuilt: 40,361 nodes, 12,356 edges, 10,000 popular-domain benign nodes from Umbrella.
- Backend test suite: 75 tests pass (URL features/rules, risk engine, models, graph, LLM failure
  paths, pipeline degradation, API integration, persistence, dashboard).
- Frontend built: React 18 + Vite + TS + Tailwind + Recharts + Lucide; Dashboard, Email Scanner,
  URL Scanner, Scan History, Scan Detail, About & Limits; `npm run build` passes.
- Demo DB populated with 12 real scans via the public API (docs/demo_results.json); 6 screenshots
  captured (dashboard, email result, URL result, history, detail, about).
- Docs: README.md, docs/architecture.md, methodology.md, api_documentation.md, testing.md,
  limitations.md, 8 Mermaid diagrams in docs/diagrams/.
- Deliverables: docs/report/PhishGuard_AI_Report.docx + .pdf (real metrics), docs/presentation/
  PhishGuard_AI_Presentation.pptx, docs/viva_notes.md, docs/demo_script.md.
- Repo hygiene: backend/requirements.txt, requirements-dev.txt, .env.example, .gitignore,
  backend/pytest.ini.

## 2026-11-17 — Project bootstrap

- Inspected environment: Python 3.11.10, Node 20.20.2, npm 12.2.2, ~15 GB disk, network available.
- Created Python 3.11 virtualenv `.venv` and installed backend/ML dependencies.
- Created persistent context files: `AGENTS.md`, `PROJECT_CONTEXT.md`, `PROJECT_STATUS.md`, `TASKS.md`, `DECISIONS.md`, `CHANGELOG.md`.
- Created directory skeleton for backend, frontend, docs and scripts.
- Selected real public datasets (Nazario phishing corpus, SpamAssassin ham, Phishing.Database, Cisco Umbrella top 1M).
