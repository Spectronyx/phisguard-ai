# DECISIONS.md — Architecture Decision Log

## ADR-001: Monorepo with FastAPI backend and Vite React frontend
**Decision:** Root-level `backend/` + `frontend/` monorepo, Vite dev proxy to `/api/v1`.
**Reason:** Simplest reproducible setup for a demo on one laptop; no separate deployment needed.
**Alternatives:** Separate repos (harder handoff), Next.js (unneeded SSR), Django (heavier).
**Consequences:** Two dev processes; documented start scripts.

## ADR-002: SQLite + SQLAlchemy 2.0, no migrations framework
**Decision:** SQLite file DB, `Base.metadata.create_all` on startup.
**Reason:** Zero-setup academic deployment; schema is small and stable.
**Consequences:** Not multi-writer production safe; documented limitation.

## ADR-003: Genuine public datasets, downloaded not committed
**Decision:** Nazario phishing corpus + SpamAssassin ham for email; Phishing.Database active links + Cisco Umbrella ranked domains for URL.
**Reason:** Real labelled data, reproducible, licence-compatible; avoids fabricating results.
**Consequences:** Training requires network + download step; raw data gitignored. Benign URL strings are constructed around real domains (disclosed).

## ADR-004: TF-IDF + Logistic Regression for email; tree/linear comparison for URL
**Decision:** Keep classical models for the primary email/URL scores; no GNN. (A small transformer
was later added as the optional semantic component — see ADR-011.)
**Reason:** CPU-only student laptop, explainable, fast training, credible baseline.
**Consequences:** Lower ceiling for the primary models; documented future work.

## ADR-005: Risk score is not model confidence
**Decision:** Each module emits a 0–100 risk score; aggregation is a weighted mean over *available* modules with weight renormalisation plus small corroboration bonus. Confidence reported separately.
**Reason:** Avoid averaging unrelated confidences; handle missing modules honestly.
**Consequences:** Scores are heuristic and thresholds configurable; documented as calibrated to product needs, not scientific boundaries.

## ADR-006: Graph is NetworkX analytics, not a GNN
**Decision:** Build corpus-derived domain/brand graph; use known-malicious lookup, brand-impersonation edges, neighborhood statistics.
**Reason:** No labelled graph dataset or training budget; claiming a GNN would be dishonest.
**Consequences:** Graph module contributes modest weight; interface allows future GNN.

## ADR-007: LLM optional, disabled by default, OpenAI-compatible
**Decision:** Direct httpx call, strict Pydantic JSON schema, timeout, one retry, explicit disclosure flag.
**Reason:** Graceful degradation and privacy; user content leaves the machine only when configured.
**Consequences:** Untestable against live provider in CI; failure paths tested with mocks.

## ADR-008: No URL fetching or sandbox detonation
**Decision:** URLs are parsed as strings only; no HTTP request is made to submitted URLs.
**Reason:** Safety of operator and demo environment.
**Consequences:** No live page content, screenshots, or redirect-chain analysis.

## ADR-009: Store summaries only
**Decision:** Persist ≤180-char input summary + derived indicators; discard full email body.
**Reason:** Privacy / data minimisation required by problem statement.
**Consequences:** History cannot replay exact email content; acceptable for demo.

## ADR-011: Local fine-tuned DistilBERT as the semantic component
**Decision:** Fine-tune `distilbert-base-uncased` (66M) on the real email corpus with the RTX 3050
4 GB GPU; run it locally as the `llm` component, with the external API as an opt-in fallback.
**Reason:** Meets the local-LLM requirement honestly within 4 GB VRAM; keeps email content private
(`llm_sent_to_provider=false`); a fine-tuned classifier is reproducible and measurable.
**Alternatives:** Pretraining from scratch (infeasible on 4 GB), Qwen2.5-0.5B QLoRA (heavier), no
transformer (did not meet the requirement).
**Consequences:** Optional ~4 GB torch/transformers install; component is `unavailable` (excluded)
when missing; metrics in `backend/artifacts/local_llm_metrics.json`; described as a fine-tuned
classifier, not a generative LLM or pretrained-from-scratch model.

## ADR-010: Tailwind CSS v3 + Recharts + Lucide, no component library
**Decision:** Hand-built dark dashboard components.
**Reason:** Small surface area, no heavy dependency, full design control.
**Consequences:** More CSS authoring; consistent tokens in `index.css`.
