# PROJECT_CONTEXT.md — Single Source of Truth

Last updated: 2026-11-18 (final state)

## 1. Objective
Build a working, explainable, reproducible phishing analysis platform that accepts suspicious emails
and URLs and returns a classification, 0–100 risk score, indicator list, model explanations and
prevention recommendations. Deliverable includes a React dashboard, FastAPI backend, genuine trained
scikit-learn models, graph analytics, optional LLM layer, tests, documentation, academic report and
presentation.

- Project: PhishGuard AI
- Problem statement: SIH25159 (AICTE)
- Context: academic project CSE473, student laptop scale, no paid infrastructure.

## 2. Current state (all verified)
- Backend: FastAPI app factory, SQLAlchemy 2 SQLite, Pydantic v2 schemas, agent pipeline with
  per-stage failure isolation, risk engine, scan persistence, API routers, SPA mount (serves
  frontend/dist when built).
- ML: email model trained (test F1 0.9819, ROC-AUC 0.9991); URL model trained (test F1 0.7403,
  ROC-AUC 0.8421) with hostname char 3–5 grams + popularity prior; artifacts in backend/artifacts/.
- Local LLM: DistilBERT 66M fine-tuned on the RTX 3050 GPU on the real email corpus; private
  in-process inference (`sent_to_provider=false`); local-first router with external API fallback;
  real metrics in `backend/artifacts/local_llm_metrics.json`.
- Graph: NetworkX, 40,361 nodes / 12,356 edges, 10k popular-domain benign nodes; not a GNN.
- Tests: 75 backend tests pass (`../.venv/bin/pytest -q`).
- Frontend: `npm run build` passes; 6 pages with loading/error/empty states.
- Demo: 14 real scans (12 seeded via API + 2 from UI capture); screenshots recaptured.
- Deliverables: README.md, docs/*.md, docs/diagrams/0*.mmd (8), report DOCX+PDF, PPTX, viva notes,
  demo script.

## 3. Technology stack
| Layer | Technology |
|---|---|
| Backend | Python 3.11, FastAPI 0.163.x, Pydantic 2, SQLAlchemy 2, Uvicorn |
| Database | SQLite (`backend/phishguard.db`, not committed) |
| ML | scikit-learn 1.9, pandas 3.1, numpy 2.4, joblib |
| URL ML | Hostname char 3–5 gram TF-IDF + host-centric numerics + Logistic Regression; Logistic Regression baseline comparison |
| Graph | NetworkX domain relationship graph |
| Local LLM | DistilBERT 66M fine-tuned on GPU; torch 2.9.1 + transformers 4.57.6 + accelerate 1.12.0 |
| External LLM | Optional OpenAI-compatible chat completions via httpx (disabled by default, fallback only) |
| Frontend | React 18, Vite 5, TypeScript, Tailwind CSS 3, Recharts, Lucide, React Router 6 |
| Tests | pytest 9.2, FastAPI TestClient (75 tests, offline) |
| Docs | Markdown, Mermaid, python-docx, python-pptx, LibreOffice (PDF) |

## 4. Directory map
```
/ (repo root)
├── README.md
├── AGENTS.md PROJECT_CONTEXT.md PROJECT_STATUS.md TASKS.md DECISIONS.md CHANGELOG.md
├── .env.example .gitignore
├── backend/
│   ├── app/{api,core,database,models,schemas,services,agents,ml,nlp,graph,utils}
│   ├── tests/            # 75 offline tests
│   ├── scripts/          # download/build datasets, train_models.py, build_graph.py, train_local_llm.py
│   ├── artifacts/        # models, metrics.json, graph_metadata.json, local_llm/, local_llm_metrics.json (generated)
│   ├── datasets/         # raw + processed (generated, not committed)
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   ├── requirements-llm.txt
│   └── pytest.ini
├── frontend/             # package.json, vite.config.ts, tailwind.config.js, tsconfig.json, src/, dist/ (built)
├── docs/
│   ├── architecture.md methodology.md api_documentation.md testing.md limitations.md
│   ├── diagrams/01..08.mmd
│   ├── report/PhishGuard_AI_Report.docx + .pdf
│   ├── presentation/PhishGuard_AI_Presentation.pptx
│   ├── demo_results.json
│   ├── screenshots/*.png
│   ├── viva_notes.md demo_script.md
└── scripts/              # generate_report.py, generate_presentation.py, seed_demo.py
```

## 5. Key metrics (real runs)
- Email test: accuracy 0.9889, precision 0.9963, recall 0.9680, F1 0.9819, ROC-AUC 0.9991 (898 rows)
- URL test: accuracy 0.7475, precision 0.7652, recall 0.7170, F1 0.7403, ROC-AUC 0.8421 (3,576 rows)
- Graph: 40,361 nodes, 12,356 edges, 11,994 malicious hostnames, 10,000 popular-domain nodes

## 6. Honest limitations (disclosed in docs + UI)
- Email temporal mismatch (ham 2003 vs phish 2019–2025) may inflate email metrics.
- URL lexical detection generalises poorly; false positives on unseen legitimate hosts.
- Graph static snapshot; no WHOIS/DNS/IP/live reputation; no GNN.
- URLs never fetched; attachments never analysed; full bodies never stored.
- Thresholds/weights are heuristics, not calibrated probabilities.

## 7. Commands
- Backend tests: `cd backend && ../.venv/bin/pytest -q`
- Frontend build: `cd frontend && npm run build`
- Start API: `cd backend && ../.venv/bin/uvicorn app.main:app --port 8000`
- Local LLM: `.venv/bin/pip install -r backend/requirements-llm.txt` then
  `.venv/bin/python backend/scripts/train_local_llm.py` (GPU)
- Demo DB: `python3 scripts/seed_demo.py` (backend running)
- Report: `.venv/bin/python scripts/generate_report.py` then LibreOffice → PDF
- Presentation: `.venv/bin/python scripts/generate_presentation.py`
