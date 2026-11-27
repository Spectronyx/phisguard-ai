Legend: `[ ]` not started · `[~]` in progress · `[x]` completed & verified · `[!]` blocked

## Phase 0 — Setup
- [x] Inspect environment (Python/Node/disk/network) — Architect
- [x] Create context files (AGENTS, CONTEXT, STATUS, TASKS, DECISIONS, CHANGELOG) — Architect
- [x] Download public datasets — ML
- [x] Backend dependency environment — Backend

## Phase 1 — Backend MVP
- [x] FastAPI app factory, config, CORS, error handling
- [x] SQLAlchemy models + DB init
- [x] Pydantic schemas
- [x] Risk aggregation engine
- [x] URL analysis service (lexical + model inference)
- [x] Email analysis service (TF-IDF + rules)
- [x] Scan persistence + history + pagination
- [x] Dashboard stats endpoints
- [x] Health + model status endpoints
- [x] API smoke run via uvicorn

## Phase 2 — ML/NLP
- [x] Dataset download script (reproducible)
- [x] Email dataset build (mbox + ham parsing, dedupe)
- [x] URL dataset build (malicious + constructed benign)
- [x] URL feature extractor (host-centric + char n-grams + popularity)
- [x] Email TF-IDF pipeline
- [x] Train/evaluate email model (F1 0.9819, AUC 0.9991)
- [x] Train/evaluate URL model (+ baselines) (F1 0.7403, AUC 0.8421)
- [x] Model metrics artifact + metadata
- [x] Graph artifact build (40,361 nodes, 10k popular-domain benign nodes)
- [x] Inference fallbacks tested

## Phase 3 — Graph + LLM + Agents
- [x] Domain relationship graph + features
- [x] Optional LLM client + schema validation + injection protection
- [x] Agent pipeline orchestration with per-stage failure isolation
- [x] Component-wise aggregation endpoint output

## Phase 4 — Frontend
- [x] Vite + React + TS + Tailwind scaffold
- [x] API client + types
- [x] Layout/navigation, dark theme
- [x] Dashboard page with real stats/charts
- [x] Email scanner page
- [x] URL scanner page
- [x] Analysis result panel
- [x] Scan history with search/filter/pagination
- [x] Scan detail page
- [x] About/methodology page
- [x] Responsive + empty/error/loading states
- [x] Production build (`npm run build` passes)

## Phase 5 — Integration & QA
- [x] Backend unit tests (URL, email, risk, graph, LLM)
- [x] API integration tests
- [x] Missing artifacts / LLM failure tests
- [x] Frontend build verification
- [x] End-to-end demo scenario verification (12 scenarios via API)
- [x] Security checks (input validation, no URL fetch)

## Phase 6 — Docs & Academic deliverables
- [x] README
- [x] docs/architecture, methodology, api, testing, limitations
- [x] Mermaid diagrams (8) in docs/diagrams/
- [x] Academic report DOCX + PDF via LibreOffice
- [x] Presentation PPTX
- [x] Viva notes + demo script
- [x] Screenshots (6) in docs/screenshots/
- [x] Demo results JSON (12 real scans)

## Phase 8 — Local LLM (ADR-011)
- [x] Install CUDA torch + transformers + accelerate
- [x] Local DistilBERT fine-tuning script on real email corpus / RTX 3050
- [x] LocalSemanticService with lazy load, graceful degradation, privacy disclosure
- [x] SemanticRouter: local first, external API fallback
- [x] Config: LOCAL_LLM_ENABLED / MAX_LENGTH / DEVICE
- [x] Pipeline, explanation, health, /models/status include local backend
- [x] Frontend About page + result badge show local LLM with real metrics
- [x] 8 mocked GPU-free tests; full suite now 83 passing
- [x] Confirm training run + real metrics artifact (RTX 3050, 249.37s, test F1 1.0000 — disclosed as corpus artefact)
- [x] Re-seed demo + recapture screenshots (14 real scans, 6 LLM-assisted)
- [x] Regenerate DOCX/PDF + PPTX with local LLM section

## Phase 7 — Final
- [x] Quality gate checklist (re-run backend tests + frontend build + API smoke)
- [x] Context files finalized
- [x] Final delivery summary
