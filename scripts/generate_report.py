#!/usr/bin/env python3
"""Generate the PhishGuard AI academic report (DOCX) from real run data.

Reads backend/artifacts/metrics.json and docs/demo_results.json so every
metric displayed comes from an actual run — nothing is fabricated.
"""

from __future__ import annotations

import json
from pathlib import Path

from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT

ROOT = Path(__file__).resolve().parents[1]
METRICS_PATH = ROOT / "backend" / "artifacts" / "metrics.json"
DEMO_PATH = ROOT / "docs" / "demo_results.json"
LOCAL_LLM_METRICS_PATH = ROOT / "backend" / "artifacts" / "local_llm_metrics.json"
OUT = ROOT / "docs" / "report" / "PhishGuard_AI_Report.docx"

ACCENT = RGBColor(0x22, 0xD3, 0xEE)
DARK = RGBColor(0x07, 0x0B, 0x12)
MUTED = RGBColor(0x8F, 0xA3, 0xBF)


def metrics() -> dict:
    return json.loads(METRICS_PATH.read_text(encoding="utf-8"))


def demo() -> dict:
    if DEMO_PATH.exists():
        return json.loads(DEMO_PATH.read_text(encoding="utf-8"))
    return {"scenarios": []}


def h1(doc: Document, text: str) -> None:
    p = doc.add_heading(text, level=1)
    for run in p.runs:
        run.font.color.rgb = ACCENT
        run.font.size = Pt(18)


def h2(doc: Document, text: str) -> None:
    p = doc.add_heading(text, level=2)
    for run in p.runs:
        run.font.color.rgb = ACCENT
        run.font.size = Pt(14)


def body(doc: Document, text: str, size: int = 10.5) -> None:
    p = doc.add_paragraph()
    r = p.add_run(text)
    r.font.size = Pt(size)
    r.font.color.rgb = DARK


def bullet(doc: Document, text: str) -> None:
    p = doc.add_paragraph(style="List Bullet")
    r = p.add_run(text)
    r.font.size = Pt(10.5)
    r.font.color.rgb = DARK


def kv_table(doc: Document, rows: list[tuple[str, str]]) -> None:
    table = doc.add_table(rows=0, cols=2)
    table.style = "Light Grid Accent 1"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for k, v in rows:
        row = table.add_row()
        row.cells[0].text = k
        row.cells[1].text = v
        for cell in row.cells:
            for paragraph in cell.paragraphs:
                for run in paragraph.runs:
                    run.font.size = Pt(10)


def main() -> None:
    m = metrics()
    d = demo()
    email_m = m["email"]
    url_m = m["url"]
    graph_meta = json.loads((ROOT / "backend" / "artifacts" / "graph_metadata.json").read_text())
    local_meta = (
        json.loads(LOCAL_LLM_METRICS_PATH.read_text(encoding="utf-8"))
        if LOCAL_LLM_METRICS_PATH.exists()
        else None
    )

    doc = Document()

    # Base style
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(10.5)
    style.font.color.rgb = DARK

    # Title
    title = doc.add_heading("PhishGuard AI — Project Report", level=0)
    for run in title.runs:
        run.font.color.rgb = ACCENT
        run.font.size = Pt(26)

    body(doc, "Real-Time AI/ML-Based Phishing Detection and Prevention System", 14)
    body(doc, "SIH Problem Statement SIH25159 · Organisation: AICTE · Academic Project CSE473", 11)
    body(doc, "Prepared by the PhishGuard AI project team — all metrics are from actual training runs.", 10)
    doc.add_paragraph()

    # 1. Executive summary
    h1(doc, "1. Executive Summary")
    body(doc, (
        "PhishGuard AI is a working, explainable phishing-detection platform that analyses suspicious "
        "emails and URLs and returns a 0–100 risk score, a classification (safe / suspicious / "
        "phishing), the evidence behind it, and a recommended action. It combines a genuine "
        "scikit-learn email classifier (TF-IDF + Logistic Regression), a hostname-aware URL "
        "classifier (hostname character 3–5 gram TF-IDF plus host-centric numeric features), "
        "deterministic threat rules, NetworkX domain-graph analytics, and a locally fine-tuned "
        "DistilBERT semantic classifier (a fine-tuned text classifier, not a generative LLM). "
        "The system degrades gracefully: missing or optional modules are excluded from risk "
        "aggregation rather than scored as zero, and no submitted URL is ever fetched."
    ))
    headline = (
        f"Headline results on held-out test sets: email model F1 {email_m['test']['f1']} "
        f"(accuracy {email_m['test']['accuracy']}, ROC-AUC {email_m['test']['roc_auc']}); URL model "
        f"F1 {url_m['test']['f1']} (accuracy {url_m['test']['accuracy']}, ROC-AUC "
        f"{url_m['test']['roc_auc']}). Full metric provenance: backend/artifacts/metrics.json."
    )
    if local_meta:
        headline += (
            f" Local LLM (DistilBERT, fine-tuned on the RTX 3050): test F1 "
            f"{local_meta['test']['metrics']['f1']} "
            f"(ROC-AUC {local_meta['test']['metrics']['roc_auc']}); see "
            f"backend/artifacts/local_llm_metrics.json."
        )
    body(doc, headline)

    # 2. Objectives and scope
    h1(doc, "2. Objectives and Scope")
    for item in [
        "Real-time AI/ML phishing detection for emails and URLs.",
        "Explainable per-module risk scores and weights; model confidence kept separate from risk.",
        "Reproducible trained models from public datasets with published metrics.",
        "Dashboard with real backend endpoints, loading/error/empty states.",
        "Privacy by design: URLs never fetched, full bodies never stored, no secrets in source.",
        "Local LLM trained on the GPU with real held-out metrics; private in-process inference.",
        "Graceful degradation for optional LLM, graph and ML modules.",
    ]:
        bullet(doc, item)

    # 3. Architecture
    h1(doc, "3. Architecture")
    body(doc, (
        "FastAPI backend (Python 3.11, SQLAlchemy 2, SQLite) plus React 18 + Vite + TypeScript + "
        "Tailwind frontend. The backend owns all analysis and persistence; the frontend calls only "
        "/api/v1 endpoints. Analysis flows through an orchestrated pipeline of independent agents: "
        "input normalisation, URL analysis, email analysis, domain-graph lookup, local LLM router, risk "
        "aggregation, explanation and response."
    ))
    body(doc, "See docs/architecture.md for the full architecture, ER model and failure behaviour.")

    # 4. Data and methodology
    h1(doc, "4. Data and Methodology")
    kv_table(doc, [
        ("Email rows", str(email_m["dataset_rows"])),
        ("Email legitimate", str(email_m["label_distribution"]["legitimate"])),
        ("Email phishing", str(email_m["label_distribution"]["phishing"])),
        ("URL rows", str(url_m["dataset_rows"])),
        ("URL benign", str(url_m["label_distribution"]["benign"])),
        ("URL malicious", str(url_m["label_distribution"]["malicious"])),
        ("Split", "70/15/15 stratified, seed 42"),
        ("Selection", "validation F1; refit on train+validation; test once"),
        ("Email source", "Nazario Phishing Corpus 2019–2025 (CC-BY-4.0) + SpamAssassin ham (2003)"),
        ("URL source", "Kaggle Malicious URLs (CC0, ISCX-URL-2016-derived) + Phishing.Database (CC0)"),
        ("Popularity prior", "Cisco Umbrella top-1M, top 10k domains, not a whitelist"),
    ])
    body(doc, (
        "No URL was fetched during dataset construction. Deduplication removes contradictory labels "
        "(a domain labelled both benign and malicious). Path features are excluded from the URL "
        "model to avoid homepage/path corpus bias. The email corpus has a known temporal mismatch "
        "(legitimate 2003 vs phishing 2019–2025), disclosed as a limitation."
    ))

    # 5. Results
    h1(doc, "5. Model Results")
    kv_table(doc, [
        ("Email algorithm", email_m["algorithm"]),
        ("Email test accuracy", f"{email_m['test']['accuracy']:.4f}"),
        ("Email test precision", f"{email_m['test']['precision']:.4f}"),
        ("Email test recall", f"{email_m['test']['recall']:.4f}"),
        ("Email test F1", f"{email_m['test']['f1']:.4f}"),
        ("Email test ROC-AUC", f"{email_m['test']['roc_auc']:.4f}"),
        ("URL algorithm", url_m["selected_algorithm"]),
        ("URL test accuracy", f"{url_m['test']['accuracy']:.4f}"),
        ("URL test precision", f"{url_m['test']['precision']:.4f}"),
        ("URL test recall", f"{url_m['test']['recall']:.4f}"),
        ("URL test F1", f"{url_m['test']['f1']:.4f}"),
        ("URL test ROC-AUC", f"{url_m['test']['roc_auc']:.4f}"),
        ("Graph nodes", str(graph_meta["nodes"])),
        ("Graph edges", str(graph_meta["edges"])),
        ("Graph malicious hostnames", str(graph_meta["malicious_hostnames"])),
    ])

    body(doc, "Email confusion matrix (rows: actual, columns: predicted):", 10.5)
    cm = email_m["test"]["confusion_matrix"]
    table = doc.add_table(rows=3, cols=3)
    table.style = "Light Grid Accent 1"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    data = [
        ["", "Predicted legitimate", "Predicted phishing"],
        ["Actual legitimate", str(cm["true_negative"]), str(cm["false_positive"])],
        ["Actual phishing", str(cm["false_negative"]), str(cm["true_positive"])],
    ]
    for i, row in enumerate(data):
        for j, val in enumerate(row):
            table.cell(i, j).text = val
            for p in table.cell(i, j).paragraphs:
                for run in p.runs:
                    run.font.size = Pt(10)

    body(doc, "URL confusion matrix (rows: actual, columns: predicted):", 10.5)
    cm2 = url_m["test"]["confusion_matrix"]
    table2 = doc.add_table(rows=3, cols=3)
    table2.style = "Light Grid Accent 1"
    table2.alignment = WD_TABLE_ALIGNMENT.CENTER
    data2 = [
        ["", "Predicted benign", "Predicted malicious"],
        ["Actual benign", str(cm2["true_negative"]), str(cm2["false_positive"])],
        ["Actual malicious", str(cm2["false_negative"]), str(cm2["true_positive"])],
    ]
    for i, row in enumerate(data2):
        for j, val in enumerate(row):
            table2.cell(i, j).text = val
            for p in table2.cell(i, j).paragraphs:
                for run in p.runs:
                    run.font.size = Pt(10)

    body(doc, (
        "URL detection is substantially harder than email detection; lexical host features alone "
        "cannot catch novel or page-content-based campaigns. The URL score should be treated as "
        "supporting evidence within the aggregated risk, not as a standalone verdict."
    ), 10)

    # 5b. Local LLM
    h1(doc, "5b. Local LLM (fine-tuned DistilBERT)")
    if local_meta:
        local_test = local_meta["test"]["metrics"]
        local_train = local_meta["training"]
        kv_table(doc, [
            ("Base model", local_meta["base_model"]),
            ("Fine-tuned locally", str(local_meta["fine_tuned"])),
            ("Device", str(local_train["device"])),
            ("GPU", str(local_train.get("gpu_name") or "CPU")),
            ("Epochs", str(local_train["epochs"])),
            ("Effective batch size", str(local_train["effective_batch_size"])),
            ("Max tokens", str(local_train["max_length"])),
            ("Training seconds", str(local_train["training_seconds"])),
            ("Test accuracy", f"{local_test['accuracy']:.4f}"),
            ("Test precision", f"{local_test['precision']:.4f}"),
            ("Test recall", f"{local_test['recall']:.4f}"),
            ("Test F1", f"{local_test['f1']:.4f}"),
            ("Test ROC-AUC", f"{local_test['roc_auc']:.4f}"),
        ])
        body(doc, local_meta["disclosure"])
        body(doc, (
            "The local model occupies the LLM component (weight 0.10). Its inference is in-process; "
            "llm_sent_to_provider stays false. If the artifact or torch/transformers are absent, the "
            "component is excluded from aggregation rather than scored as zero."
        ))
        body(doc, (
            "Interpretation caveat: the 1.0000 held-out test scores are a real result on this corpus, "
            "but the legitimate messages date from 2003 while phishing messages span 2019–2025. "
            "A manual spot check with short modern legitimate emails produced high phishing "
            "probabilities. The LLM is therefore supporting evidence only, never a standalone verdict."
        ))
    else:
        body(doc, (
            "No local LLM metrics artifact is present yet. Run backend/scripts/train_local_llm.py "
            "to fine-tune the model on the GPU and generate real metrics."
        ))

    # 6. Risk aggregation
    h1(doc, "6. Risk Aggregation")
    body(doc, (
        "The final risk score is a weighted mean over available modules, with weights renormalised "
        "when modules are missing, plus a capped corroboration bonus (4 points per extra high-signal "
        "module ≥ 60, capped at 8). Default weights: email model 0.30, URL model 0.30, email rules "
        "0.15, URL rules 0.10, graph 0.05, LLM 0.10. Thresholds: 0–29 safe/low, 30–59 suspicious, "
        "60–79 phishing/high, 80–100 phishing/critical. Model confidence is reported separately and "
        "is never confused with risk."
    ))

    # 7. Demo scenarios
    h1(doc, "7. Demo Scenarios (real API outputs)")
    body(doc, (
        "The demo database holds 14 real scans: 12 seeded through the public API by "
        "scripts/seed_demo.py plus 2 more produced while capturing the UI screenshots. The 12 seeded "
        "outputs are recorded in docs/demo_results.json; screenshots are in docs/screenshots/. "
        "Nothing below is hand-written."
    ))
    for scenario in d.get("scenarios", []):
        h2(doc, f"{scenario['name']} — scan #{scenario['scan_id']}")
        body(doc, f"Verdict: {scenario['classification'].upper()} · risk score {scenario['risk_score']} · "
                  f"{scenario['risk_level']} · model confidence {scenario['model_confidence']}")
        body(doc, f"Note: {scenario['note']}")
        if scenario.get("indicators"):
            body(doc, "Indicators: " + ", ".join(scenario["indicators"]))
        body(doc, f"Recommendation: {scenario['recommendation']}")
        doc.add_paragraph()

    # 8. Limitations
    h1(doc, "8. Limitations")
    for item in [
        "Email test data mixes 2003 ham with 2019–2025 phishing; temporal mismatch can inflate performance.",
        "URL detection F1 is ~0.74; lexical host features cannot catch novel campaigns or page-content tricks.",
        "False positives occur on unseen legitimate hosts and hosting-platform subdomains.",
        "Graph is a static corpus snapshot; no WHOIS, DNS, IP reputation or live blocklists.",
        "No GNN, no URL fetching, no sandbox detonation, no attachment analysis.",
        "Thresholds and weights are product heuristics, not scientific probabilities.",
    ]:
        bullet(doc, item)

    # 9. Reproducibility
    h1(doc, "9. Reproducibility")
    for item in [
        "Backend: python3.11 -m venv .venv && pip install -r backend/requirements-dev.txt",
        "Rebuild artifacts: cd backend && ../.venv/bin/python scripts/download_datasets.py && "
        "../.venv/bin/python scripts/build_datasets.py && ../.venv/bin/python scripts/train_models.py && "
        "../.venv/bin/python scripts/build_graph.py",
        "Run tests: cd backend && ../.venv/bin/pytest -q",
        "Frontend: cd frontend && npm install && npm run build",
        "Start API: cd backend && ../.venv/bin/uvicorn app.main:app --port 8000",
        "Populate demo DB: python3 scripts/seed_demo.py (backend must be running)",
        "All metrics: backend/artifacts/metrics.json",
    ]:
        bullet(doc, item)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    doc.save(OUT)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
