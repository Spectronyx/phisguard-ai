# PhishGuard AI — Viva Notes

Last updated: 2026-11-18

Use these talking points for the project viva/demo. Every figure below is backed by a real run
(`backend/artifacts/metrics.json`, `docs/demo_results.json`).

---

## 1. Elevator pitch (30 s)

PhishGuard AI analyses a suspicious email or URL and returns a transparent 0–100 risk score,
classification, evidence breakdown and recommended action. It combines a genuine scikit-learn
email classifier, a hostname-aware URL classifier, deterministic threat rules, NetworkX domain-graph
analytics and a locally fine-tuned DistilBERT semantic classifier. URLs are never fetched; full
email bodies are never stored.

---

## 2. What did you actually build?

- FastAPI backend + React/Vite/TypeScript/Tailwind dashboard.
- Real trained models in `backend/artifacts/`: email model, URL model, domain graph, `metrics.json`,
  plus a locally fine-tuned DistilBERT classifier in `local_llm/` with `local_llm_metrics.json`.
- 75 offline backend tests; frontend production build.
- Reproducible dataset-build and training scripts.
- DOCX report + PDF; PPTX presentation; 8 Mermaid diagrams.

---

## 3. Headline results

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---:|---:|---:|---:|---:|
| Email | 0.9889 | 0.9963 | 0.9680 | 0.9819 | 0.9991 |
| URL | 0.7475 | 0.7652 | 0.7170 | 0.7403 | 0.8421 |

Test sets: 898 email rows; 3,576 URL rows. Split 70/15/15 stratified, seed 42; selection on
validation; test evaluated once after refit on train+validation.

---

## 4. Architecture questions

**Q: How does the pipeline work?**
A: InputAgent normalises; URLAnalysisAgent scores each URL (model + rules); EmailAnalysisAgent runs
the TF-IDF model and social-engineering rules, re-scoring rules with URL evidence; DomainIntelAgent
queries the NetworkX graph; optional SemanticAgent calls the LLM; RiskAggregationAgent computes the
weighted mean plus corroboration bonus; Explanation/Response agents build the output.

**Q: How is risk aggregated?**
A: Weighted mean over *available* modules (weights renormalised when modules are missing), plus a
capped corroboration bonus (4 points per extra high-signal module ≥ 60, cap 8). Default weights:
email model 0.30, URL model 0.30, email rules 0.15, URL rules 0.10, graph 0.05, LLM 0.10.

**Q: Is confidence the same as risk?**
A: No. Confidence is per-model (`max(p, 1-p)`); risk is the aggregated 0–100 score. They are
reported as separate fields.

**Q: You have an LLM requirement — what did you actually build?**
A: A local DistilBERT (66M) classifier fine-tuned on the real phishing email corpus using the RTX
3050 GPU. It is the semantic component of the risk score, occupies the `llm` weight (0.10), and is
private: `llm_sent_to_provider=false`. The external API path is kept only as an opt-in fallback.

**Q: Did you pretrain an LLM from scratch?**
A: No — 4 GB VRAM cannot pretrain an LLM. We fine-tuned a public pretrained encoder with a
classification head. `backend/artifacts/local_llm_metrics.json` records the real held-out metrics
and training device; we describe it honestly as a fine-tuned classifier, not a generative LLM.

**Q: The local LLM test F1 is 1.0 — is it perfect?**
A: No. That is the real number on our 896-row held-out test split, but the corpus has a known
temporal mismatch (2003 ham vs 2019–2025 phishing). In a manual spot check, short modern
legitimate emails sometimes received high phishing probabilities. We disclose this as a
limitation: the LLM is only one weighted component (0.10), the probability is shown in the result,
and risk aggregation uses the other models and rules as well.

**Q: What if torch is not installed?**
A: The local component is reported `unavailable` and excluded from aggregation. No crash, no fake
score. Tests mock the transformer entirely.

---

## 5. Data and training questions

**Q: What data did you use?**
A: Nazario phishing corpus 2019–2025 (CC-BY-4.0) + SpamAssassin ham (2003) for email; Kaggle
Malicious URLs (CC0, ISCX-URL-2016-derived) + Phishing.Database active links (CC0) for URLs; Cisco
Umbrella top-1M as a popularity prior only.

**Q: Did you fetch any URLs?**
A: No. URLs are parsed as strings only. No HTTP request, DNS lookup or sandbox is ever performed on
a submitted URL.

**Q: How do you avoid path bias in the URL model?**
A: Benign corpora are homepage-heavy; path length/depth were kept out of model features, and
hostname character n-grams plus a popularity prior carry generalisation. Path/query signals stay in
the rule engine only.

**Q: What about the email corpus being from 2003?**
A: Disclosed limitation. Legitimate mail is 2003 SpamAssassin while phishing is 2019–2025 Nazario;
the temporal gap can inflate measured email performance.

---

## 6. Safety and privacy

**Q: Is data stored?**
A: Only a ≤180-char input summary, SHA-256 input hash, classification, score, indicators and
component breakdown. Full email bodies are not persisted.

**Q: When is the LLM used?**
A: Only when `LLM_ENABLED=true` AND `LLM_API_KEY` is set. Every LLM-assisted scan sets
`llm_sent_to_provider=true`. Output is strictly schema-validated and the system prompt forbids
instruction-following inside the email.

**Q: Any secrets in code?**
A: No. Configuration is environment-based via `.env`/environment variables; `.env` is gitignored.

---

## 7. Honest limitations (examiner-friendly)

- URL F1 ~0.74 — lexical host features can't catch novel campaigns or page-content tricks.
- Email metrics inflated by the 2003/2019–2025 temporal mismatch.
- Graph is a static corpus snapshot; no live reputation.
- No GNN, no WHOIS/DNS/IP enrichment, no attachment analysis.
- Single-user SQLite demo; no auth, no migrations, no retraining loop.

---

## 8. Demo script (2 min)

1. Open `http://127.0.0.1:8000/` — dashboard shows 14 real stored scans (12 seeded via
   `scripts/seed_demo.py` plus 2 from UI capture).
2. Go to URL Scanner → pick "Brand lookalike" (`http://paypal-secure-login.xyz/verify-account`) →
   Analyse URL → shows phishing 89/100, brand-impersonation indicator, module breakdown.
3. Go to URL Scanner → `https://www.google.com/` → safe 3/100; note popularity calibration applied.
4. Go to Email Scanner → pick "Phishing example" → phishing 98/100 critical, 11 indicators,
   per-module weights visible (including the local LLM).
5. About & Limits → shows model metrics loaded from `metrics.json`, graph described as NetworkX
   analytics (not a GNN), and the local DistilBERT card with real held-out metrics.

---

## 9. Where are the artefacts?

- Code: `backend/app/`, `frontend/src/`
- Models + metrics: `backend/artifacts/`
- Datasets: `backend/datasets/` (raw + processed, not committed)
- Tests: `backend/tests/` (run `../.venv/bin/pytest -q`)
- Docs: `docs/` (architecture, methodology, API, testing, limitations, diagrams, report,
  presentation, viva notes, demo script, screenshots)
