# Methodology

Last updated: 2026-11-18

All numbers in this section come from a real training run executed against the downloaded public
datasets. The run is reproducible with `python backend/scripts/train_models.py` (≈25 s on the
reference machine) and its outputs are stored in `backend/artifacts/metrics.json`.

---

## 1. Data

### 1.1 Email dataset (5,983 rows)

| Class | Rows | Source |
|---|---:|---|
| Legitimate | 4,108 | SpamAssassin public corpus: `easy_ham`, `easy_ham_2`, `hard_ham` (2003) |
| Phishing | 1,875 | Nazario Phishing Corpus 2019–2025 |

### 1.2 URL dataset (23,838 usable rows)

| Class | Rows | Source |
|---|---:|---|
| Benign | 11,874 | Kaggle Malicious URLs Dataset (ISCX-URL-2016-derived), homepage-heavy, one URL per hostname |
| Malicious | 11,964 | Kaggle phishing (6,000) + Phishing.Database active links (6,000) |

162 unparseable URLs were dropped during feature extraction.

### 1.3 Data construction notes

- **No URL was fetched, opened, or executed.** Datasets are built from URL strings alone.
- **Deduplication:** one URL per hostname per class; malicious URLs whose registrable domain also
  appears in the benign pool were removed to avoid contradictory labels.
- **Temporal mismatch:** the legitimate email corpus is from 2003 while phishing spans 2019–2025.
  This can inflate measured email performance and is disclosed as a limitation.
- **Homepage/path bias:** benign corpora are homepage-heavy; therefore path length/depth were kept
  out of the URL model features and path/query lexical signals stay in the deterministic rule engine
  only.
- **HTTPS artefact:** `uses_https` was removed from model features. The "No HTTPS" rule fires only
  when the scheme is explicitly provided (`scheme_provided`), so URLs without a scheme are not
  penalised for lacking HTTPS.
- **SHAs:** `backend/datasets/processed/dataset_metadata.json` records SHA-256 hashes and source
  licences.

---

## 2. Splits and evaluation protocol

All splits use `random_state=42` and stratification on label:

1. Hold out **15%** as test (never seen during training or selection).
2. Split the remaining 85% into train (~70%) and validation (~15% of total).
3. Tune/select on validation only.
4. **Refit the selected model on train+validation**, evaluate **once** on held-out test.

Threshold analysis reports precision/recall/F1 at 0.3, 0.5 and 0.7, but selection is at 0.5.

---

## 3. Email model

- **Vectoriser:** TF-IDF, word n-grams (1–2), `min_df=2`, `max_df=0.95`, sublinear TF,
  unicode accents stripped, stop-words default English.
- **Classifier:** Logistic Regression, `solver=lbfgs`, `class_weight=balanced`, `C=1.0`
  (selected from `{0.5, 1.0, 2.0, 4.0}` on validation F1).
- **Refit:** on train+validation; evaluated once on test.

| Metric | Test value |
|---|---:|
| Accuracy | 0.9889 |
| Precision | 0.9963 |
| Recall | 0.9680 |
| F1 | 0.9819 |
| ROC-AUC | 0.9991 |
| Confusion matrix (legit / phish) | TN=616, FP=1, FN=9, TP=272 |

Baseline comparison on the identical split: ComplementNB test F1 0.9838 (slightly higher but not
chosen because token-contribution explainability was preferred).

Top positive tokens for a phishing input include `verify`, `password`, `suspended`, `otp` — genuine
local contributions of the linear model, surfaced in the UI.

---

## 4. URL model

### 4.1 Model inputs

- **Hostname character n-grams:** TF-IDF `char_wb`, n-grams 3–5, `min_df=2`, capped at 6,000
  features, sublinear TF.
- **Host-centric numeric features:** hostname length, domain length, label count, dots, hyphens,
  digits, special chars, entropy, digit ratio, TLD length, suspicious TLD flag, punycode flag,
  percent-encoding count, userinfo flag, shortener flag, brand-impersonation flag, single-char /
  numeric labels, suspicious-keyword counts, query param count.
- **Popularity prior:** `is_popular_domain` = registrable domain present in the Cisco Umbrella
  top-10k ranking. A ranking signal, **not a whitelist**.

### 4.2 Candidate models compared

| Candidate | Validation F1 | Test accuracy | Test precision | Test recall | Test F1 | ROC-AUC |
|---|---:|---:|---:|---:|---:|---:|
| Random Forest, lexical-only | 0.7212 | 0.7215 | 0.7429 | 0.6808 | 0.7105 | 0.8025 |
| Logistic Regression, host char n-grams | 0.7350 | 0.7522 | 0.7800 | 0.7053 | 0.7408 | 0.8430 |
| **Logistic Regression, host char n-grams, C=4 (selected)** | **0.7396** | **0.7475** | **0.7652** | **0.7170** | **0.7403** | **0.8421** |

Selected model: `logistic_regression_host_char_c4`, Logistic Regression with C=4.0. It is the best
validation F1 candidate and has strong AUC (0.8421).

### 4.3 Test set confusion (malicious positive)

| | Predicted benign | Predicted malicious |
|---|---:|---:|
| Actual benign | 1,386 | 395 |
| Actual malicious | 508 | 1,287 |

### 4.4 Popularity calibration (documented post-processing)

At inference, bare registrable domains in the Umbrella top-10k are multiplied by `0.3`
(`URL_POPULARITY_CALIBRATION`). This suppresses false positives on `github.com` and `google.com`
while leaving hosted phishing on subdomains untouched. Test metrics after calibration are
indistinguishable from uncalibrated because only 7 of 3,576 test rows are bare popular domains
(accuracy 0.7475, F1 0.7403, AUC 0.8418). The raw probability is preserved in the response for
transparency.

---

## 5. Deterministic rules

URL and email rules are independent of the ML models:

**URL rule engine** — brand impersonation (critical), embedded credentials (critical), IP host
(high), userinfo (high), punycode (medium), percent encoding (high), suspicious TLD (medium),
non-standard port (medium), embedded protocol (high), very long URL (medium), deep subdomain chain
(medium), credential keywords (medium), URL shortener (medium), no HTTPS when scheme explicit
(low), digit-heavy hostname (medium), hyphenated hostname (low), high hostname randomness
(medium), many dots (low).

**Email rule engine** — urgency/threat language, credential harvesting language, account threat,
sender-brand mismatch, unexpected attachment, suspicious embedded link, high-abuse TLD,
credential-related keywords, anchor mismatch, suspicious extension, etc.

Rules produce a 0–100 score from per-indicator severity points (low 4, medium 10, high 18, critical
28), capped at 100.

---

## 6. Domain graph

Built offline by `scripts/build_graph.py`:

- Nodes: hostnames (from corpus), registrable domains, brand nodes.
- Edges: `subdomain_of` relationships, `brand_impersonation` lexical links.
- Malicious labels from corpus; 11,994 malicious hostnames.
- **New:** top-10k Cisco Umbrella registrable domains added as benign `domain` nodes
  (`umbrella_top`); 9,693 newly added (some already present).
- Result: 40,361 nodes, 12,356 edges.
- This is **NetworkX analytics, not a GNN**. No WHOIS/DNS/IP/live reputation. Static snapshot.

---

## 7. Risk aggregation

Default weights: email model 0.30, URL model 0.30, email rules 0.15, URL rules 0.10, graph 0.05,
LLM 0.10. Weights renormalise over available modules only. Missing modules excluded, never scored as
zero. Corroboration bonus: 4 points per extra high-signal component (≥60), capped at 8.

Thresholds: 0–29 safe/low, 30–59 suspicious, 60–79 phishing/high, 80–100 phishing/critical.

---

## 8. Optional LLM

OpenAI-compatible `/chat/completions` via httpx, disabled by default (`LLM_ENABLED=false`). Strict
Pydantic JSON schema, one retry, 12 s timeout, prompt-injection-resistant system prompt, email body
passed as JSON data. Output excluded if invalid. Explicit `llm_used` / `llm_sent_to_provider`
disclosure in every response. It is used only when the local model is unavailable.

---

## 9. Local LLM (fine-tuned DistilBERT)

The semantic-analysis slot is filled by a **local, fine-tuned transformer classifier**, trained on
the same real email corpus used for the classical email model. It is *not* a generative chat model
and was **not pretrained from scratch**: `distilbert-base-uncased` (66 M parameters) was fine-tuned
with a binary classification head on the RTX 3050 4 GB GPU.

- **Input:** `Subject: …\nURLs: …\nBody: …`, tokenised to at most 384 tokens.
- **Split:** stratified 70/15/15, seed 42 — validation used for monitoring, test evaluated once.
- **Optimisation:** AdamW, LR 2e-5, 3 epochs, batch 8 × grad-accum 2, fp16 on CUDA.
- **Output:** phishing probability → module risk score; `max(p, 1-p)` → per-model confidence.
- **Privacy:** inference runs in-process; `llm_sent_to_provider=false` and `details.llm_backend`
  is `local_distilbert`. No network request is made.
- **Degradation:** if the artifact or the optional `torch`/`transformers` stack is missing, the
  component becomes `unavailable` and is excluded from aggregation; the external API is a fallback.
- **Provenance:** `backend/artifacts/local_llm_metrics.json` records the real held-out metrics,
  device, GPU name, training seconds and package versions.
- **Interpretation:** the held-out test scores are all 1.0000. This is a real measured result on
  896 test rows from this corpus, but it must not be read as real-world accuracy: the legitimate
  class is from 2003 and the phishing class from 2019–2025, so the classifier can separate them
  using corpus-specific cues. A manual spot check with short modern legitimate emails produced
  high phishing probabilities. The component is deliberately only 10% of the risk score and is
  reported alongside its probability so a reviewer can see this behaviour.
