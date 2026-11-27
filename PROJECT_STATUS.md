# PROJECT_STATUS.md

Phase: Complete — all phases delivered
Last update: 2026-11-18
Completion: **44 / 44** tracked tasks (local LLM added as ADR-011)

## Environment verified
- OS: Linux, Python 3.11.15 at repo `.venv`, Node 20.20.2, npm 12.2.2
- GPU: NVIDIA RTX 3050 Laptop GPU, 3.97 GB VRAM, CUDA 13.5, torch 2.9.1+cu128
- Disk: ~11 GB free
- Network: PyPI and Hugging Face reachable (occasional transient DNS failures; pip `--resume-retries` used)

## Working features (all verified)
- Backend starts on :8000; `/api/v1/health` 200, artifacts ready
- `/api/v1/analyze/email` and `/api/v1/analyze/url` return real model + rules output
- Scan persistence + history + pagination + dashboard stats/trend all 200
- Genuine ML models: email F1 0.9819, URL F1 0.7403, graph 40,361 nodes
- **Local LLM:** DistilBERT 66M fine-tuned on the RTX 3050 (249.37 s, fp16, 3 epochs); private inference,
  local-first router with external API fallback; real metrics in `backend/artifacts/local_llm_metrics.json`
  (test accuracy/precision/recall/F1/ROC-AUC all 1.0000 on 896 rows — disclosed as a corpus artefact,
  not real-world accuracy)
- Backend tests: 83 passed (`cd backend && ../.venv/bin/pytest -q`)
- Frontend build passes (`cd frontend && npm run build`); SPA served by FastAPI
- Demo DB holds 14 real scans (12 seeded via script + 2 from UI capture), 6 LLM-assisted; screenshots recaptured
- DOCX + PDF report, PPTX presentation (both regenerated with local LLM metrics), 8 Mermaid diagrams,
  viva notes, demo script

## Incomplete features
- None

## Known bugs / limitations
- URL model F1 ~0.74 (disclosed; lexical host features only)
- Email metrics may be inflated by 2003 ham / 2019–2025 phishing temporal mismatch (disclosed)
- Local LLM is a fine-tuned classifier, not a generative LLM; 384-token window; its 1.0000 corpus test
  scores overstate real-world quality (short modern legitimate emails can score high) — disclosed
- Frontend bundle is a single chunk (~660 kB); Recharts bundled eagerly
- No authentication; single-user SQLite demo

## Blockers
- None

## Next actions
- None. All milestones complete; backend running on :8000 with local LLM active.
