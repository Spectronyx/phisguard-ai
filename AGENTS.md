# AGENTS.md — PhishGuard AI Development Rules

Read this file and the other context files (`PROJECT_CONTEXT.md`, `PROJECT_STATUS.md`, `TASKS.md`, `DECISIONS.md`) before modifying project files.

## Project
PhishGuard AI — Real-Time AI/ML-Based Phishing Detection and Prevention System.
SIH Problem Statement SIH25159, organisation AICTE. Academic project (CSE473).

## Non-negotiable rules
1. No fabricated metrics, datasets, model scores, or capabilities. Every number in docs/report must come from a real run.
2. Every frontend feature must call a real backend endpoint. Demo-only behaviour must be labelled as such.
3. Never fetch, open, or execute submitted URLs or attachments. URLs are parsed as strings only.
4. Never store full email bodies by default. Store only a short summary plus derived features.
5. Optional modules (LLM, models, graph) must degrade gracefully; their absence must not crash a scan.
6. Do not confuse model confidence with risk score. Risk is an aggregated 0–100 score; confidence is per-model.
7. Do not claim GNN, WHOIS, DNS, or threat-intel enrichment that is not actually performed.
8. No API keys in source. Configuration via environment variables (`.env`, see `.env.example`).
9. Do not log secrets or raw personal email content.
10. Record changes in `CHANGELOG.md`, decisions in `DECISIONS.md`, task state in `TASKS.md`, and progress in `PROJECT_STATUS.md`.

## Architecture rules
- Backend: Python 3.11, FastAPI, Pydantic v2, SQLAlchemy 2, SQLite.
- ML: scikit-learn, pandas, numpy, joblib. Artifacts in `backend/artifacts/`.
- Graph: NetworkX analytics only (no GNN claim).
- Frontend: React + Vite + TypeScript + Tailwind CSS + Recharts + Lucide. Talks only to `/api/v1/*`.
- Modules under `backend/app/`:
  - `api/` routers, `schemas/` request/response models, `services/` business logic,
  - `agents/` pipeline stages, `ml/` model training + inference, `nlp/` email text features,
  - `graph/` domain graph, `database/` session + base, `models/` ORM entities, `core/` config/logging.
- Interfaces between modules are Pydantic models or plain dicts documented in `docs/architecture.md`.
- New optional analysis module = new agent class implementing `analyze(...) -> component dict`, plus config weight and explanation mapping.

## Coding conventions
- Python: type hints, module-level docstrings, no wildcard imports, pathlib paths, deterministic seeds.
- TypeScript: strict mode, no `any` in shared types, typed API client in `src/services/api.ts`.
- Styling: Tailwind utility classes; dark theme tokens defined in `index.css`.
- Commits: meaningful milestones only (repo may start without git).

## Ownership (logical)
- Architect/PM: context files, interfaces, integration.
- ML/Data: `backend/scripts/`, `backend/app/ml/`, `backend/app/nlp/`, `backend/artifacts/`, `backend/datasets/`.
- Backend: `backend/app/api/`, `services/`, `agents/`, `database/`, `models/`, `schemas/`.
- Frontend: `frontend/`.
- QA/Docs: `backend/tests/`, `docs/`, report and presentation.

## Testing requirements
- `cd backend && ../.venv/bin/pytest -q` must pass before milestone completion.
- `cd frontend && npm run build` must pass before frontend milestone completion.
- Tests must never require network access, an LLM key, or a phishing URL visit.

## Handoff protocol
After each major task report: completed work, files created/modified, interfaces, dependencies, tests run/results, known issues, remaining work, next task. Update context files before finishing.
