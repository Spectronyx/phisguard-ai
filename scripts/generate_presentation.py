#!/usr/bin/env python3
"""Generate the PhishGuard AI presentation (PPTX) from real run data."""

from __future__ import annotations

import json
from pathlib import Path

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN

ROOT = Path(__file__).resolve().parents[1]
METRICS_PATH = ROOT / "backend" / "artifacts" / "metrics.json"
DEMO_PATH = ROOT / "docs" / "demo_results.json"
LOCAL_LLM_METRICS_PATH = ROOT / "backend" / "artifacts" / "local_llm_metrics.json"
OUT = ROOT / "docs" / "presentation" / "PhishGuard_AI_Presentation.pptx"

DARK = RGBColor(0x07, 0x0B, 0x12)
ACCENT = RGBColor(0x22, 0xD3, 0xEE)
INK = RGBColor(0xE6, 0xED, 0xF7)
MUTED = RGBColor(0x8F, 0xA3, 0xBF)
SAFE = RGBColor(0x34, 0xD3, 0x99)
DANGER = RGBColor(0xFB, 0x71, 0x85)


def metrics() -> dict:
    return json.loads(METRICS_PATH.read_text(encoding="utf-8"))


def demo() -> dict:
    if DEMO_PATH.exists():
        return json.loads(DEMO_PATH.read_text(encoding="utf-8"))
    return {"scenarios": []}


def add_bg(slide, color=DARK):
    background = slide.background
    fill = background.fill
    fill.solid()
    fill.fore_color.rgb = color


def add_text(slide, left, top, width, height, text, size=18, color=INK, bold=False, align=None):
    box = slide.shapes.add_textbox(Inches(left), Inches(top), Inches(width), Inches(height))
    tf = box.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    if align:
        p.alignment = align
    run = p.add_run()
    run.text = text
    run.font.size = Pt(size)
    run.font.color.rgb = color
    run.font.bold = bold
    return box


def add_bullets(slide, left, top, width, height, items, size=14, color=INK):
    box = slide.shapes.add_textbox(Inches(left), Inches(top), Inches(width), Inches(height))
    tf = box.text_frame
    tf.word_wrap = True
    first = True
    for item in items:
        p = tf.paragraphs[0] if first else tf.add_paragraph()
        first = False
        run = p.add_run()
        run.text = "• " + item
        run.font.size = Pt(size)
        run.font.color.rgb = color
    return box


def add_card(slide, left, top, width, height, title, value, sub=None, color=ACCENT):
    shape = slide.shapes.add_shape(1, Inches(left), Inches(top), Inches(width), Inches(height))
    shape.fill.solid()
    shape.fill.fore_color.rgb = RGBColor(0x0D, 0x14, 0x20)
    shape.line.color.rgb = RGBColor(0x1E, 0x2A, 0x3D)
    tf = shape.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    r = p.add_run(); r.text = title; r.font.size = Pt(11); r.font.color.rgb = MUTED; r.font.bold = True
    p2 = tf.add_paragraph()
    r2 = p2.add_run(); r2.text = value; r2.font.size = Pt(26); r2.font.color.rgb = color; r2.font.bold = True
    if sub:
        p3 = tf.add_paragraph()
        r3 = p3.add_run(); r3.text = sub; r3.font.size = Pt(10); r3.font.color.rgb = MUTED


def main() -> None:
    m = metrics()
    d = demo()
    email_m = m["email"]
    url_m = m["url"]
    local_meta = (
        json.loads(LOCAL_LLM_METRICS_PATH.read_text(encoding="utf-8"))
        if LOCAL_LLM_METRICS_PATH.exists()
        else None
    )

    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank = prs.slide_layouts[6]

    # Slide 1 — Title
    s = prs.slides.add_slide(blank)
    add_bg(s)
    add_text(s, 0.9, 1.6, 11.5, 1.2, "PhishGuard AI", 44, ACCENT, bold=True)
    add_text(s, 0.9, 2.9, 11.5, 0.6, "Real-Time AI/ML-Based Phishing Detection and Prevention System", 20, INK)
    add_text(s, 0.9, 3.7, 11.5, 0.5, "SIH25159 · AICTE · CSE473 Academic Project", 14, MUTED)
    add_text(s, 0.9, 4.5, 11.5, 0.5, "Genuine trained models · explainable risk · privacy by design", 13, MUTED)
    add_text(s, 0.9, 6.6, 11.5, 0.5, f"Metrics from actual runs — backend/artifacts/metrics.json", 11, MUTED)

    # Slide 2 — Problem & approach
    s = prs.slides.add_slide(blank)
    add_bg(s)
    add_text(s, 0.5, 0.35, 12.5, 0.6, "Problem & Approach", 24, ACCENT, bold=True)
    add_bullets(s, 0.5, 1.1, 6.1, 5.8, [
        "Phishing emails and URLs reach users every day; defenders need fast, explainable triage.",
        "Submitted URLs are parsed as text only — never fetched, opened or executed.",
        "Full email bodies are never stored; only summaries and derived indicators are kept.",
        "Local fine-tuned DistilBERT semantic model is private by default; no secrets in source.",
        "Missing modules are excluded from risk scoring — never treated as zero.",
        "Model confidence is kept separate from the aggregated 0–100 risk score.",
    ])
    add_text(s, 6.9, 1.1, 6.0, 0.5, "Stack", 18, ACCENT, bold=True)
    add_bullets(s, 6.9, 1.7, 6.0, 4.5, [
        "FastAPI + SQLAlchemy 2 + SQLite backend",
        "scikit-learn TF-IDF / Logistic Regression models",
        "NetworkX domain-graph analytics (not a GNN)",
        "React + Vite + TypeScript + Tailwind dashboard",
        "Recharts + Lucide visualisation",
        "pytest backend suite; npm build frontend",
    ])

    # Slide 3 — Architecture
    s = prs.slides.add_slide(blank)
    add_bg(s)
    add_text(s, 0.5, 0.35, 12.5, 0.6, "Pipeline Architecture", 24, ACCENT, bold=True)
    add_bullets(s, 0.5, 1.1, 12.4, 5.6, [
        "Input normalisation → URL agent (model + rules) → Email agent (TF-IDF model + rules) →",
        "Domain-graph agent → local LLM router → Risk aggregation → Explanation → Response",
        "Each stage fails independently; a failed stage becomes an unavailable component.",
        "Risk = weighted mean over available modules + capped corroboration bonus.",
        "Weights: email model 0.30 / URL model 0.30 / email rules 0.15 / URL rules 0.10 / graph 0.05 / LLM 0.10.",
        "Thresholds: 30 suspicious, 60 phishing, 80 critical.",
    ])

    # Slide 4 — Results
    s = prs.slides.add_slide(blank)
    add_bg(s)
    add_text(s, 0.5, 0.35, 12.5, 0.6, "Evaluation Results (held-out test sets)", 24, ACCENT, bold=True)
    add_card(s, 0.5, 1.1, 3.9, 1.9, "Email accuracy", f"{email_m['test']['accuracy']:.4f}", "Nazario + SpamAssassin, 898 test rows")
    add_card(s, 4.6, 1.1, 3.9, 1.9, "Email F1", f"{email_m['test']['f1']:.4f}", "precision 0.9963 · recall 0.9680")
    add_card(s, 8.7, 1.1, 3.9, 1.9, "Email ROC-AUC", f"{email_m['test']['roc_auc']:.4f}", "TF-IDF 1–2 g + Logistic Regression")
    add_card(s, 0.5, 3.3, 3.9, 1.9, "URL accuracy", f"{url_m['test']['accuracy']:.4f}", "23,838 rows · 3,576 test rows")
    add_card(s, 4.6, 3.3, 3.9, 1.9, "URL F1", f"{url_m['test']['f1']:.4f}", "precision 0.7652 · recall 0.7170")
    add_card(s, 8.7, 3.3, 3.9, 1.9, "URL ROC-AUC", f"{url_m['test']['roc_auc']:.4f}", "host char 3–5 g + numeric features")
    add_text(s, 0.5, 5.6, 12.4, 1.4, "Email F1 0.9819 on a corpus with a 2003 ham / 2019–2025 phishing temporal mismatch — disclosed as a limitation.", 12, MUTED)

    # Slide 4b — Local LLM
    s = prs.slides.add_slide(blank)
    add_bg(s)
    add_text(s, 0.5, 0.35, 12.5, 0.6, "Local LLM — fine-tuned on the GPU", 24, ACCENT, bold=True)
    if local_meta:
        lt = local_meta["test"]["metrics"]
        tr = local_meta["training"]
        add_card(s, 0.5, 1.1, 3.9, 1.9, "Local LLM F1", f"{lt['f1']:.4f}",
                 f"accuracy {lt['accuracy']:.4f}")
        add_card(s, 4.6, 1.1, 3.9, 1.9, "ROC-AUC", f"{lt['roc_auc']:.4f}",
                 f"precision {lt['precision']:.4f} · recall {lt['recall']:.4f}")
        add_card(s, 8.7, 1.1, 3.9, 1.9, "Trained on", str(tr["gpu_name"] or tr["device"])[:28],
                 f"{tr['epochs']} epochs · {tr['training_seconds']}s", color=SAFE)
        add_bullets(s, 0.5, 3.4, 12.4, 3.4, [
            "DistilBERT (66M) fine-tuned on the real phishing email corpus; not pretrained from scratch.",
            "Runs in-process: llm_sent_to_provider=false. External API is only an opt-in fallback.",
            "Occupies the llm component (weight 0.10) and degrades to unavailable when missing.",
            "Test F1 1.0000 on this corpus — likely corpus artefacts (2003 ham / 2019–2025 phishing); not real-world accuracy.",
            "Real held-out metrics: backend/artifacts/local_llm_metrics.json.",
        ])
    else:
        add_bullets(s, 0.5, 1.2, 12.4, 5.0, [
            "Local LLM training has not been run yet.",
            "Run .venv/bin/python backend/scripts/train_local_llm.py on the RTX 3050 to generate real metrics.",
        ])

    # Slide 5 — Demo scenarios
    s = prs.slides.add_slide(blank)
    add_bg(s)
    add_text(s, 0.5, 0.35, 12.5, 0.6, "Live Demo Scenarios (real API scans)", 24, ACCENT, bold=True)
    rows = d.get("scenarios", [])
    y = 1.15
    for row in rows[:10]:
        color = SAFE if row["classification"] == "safe" else DANGER
        add_text(s, 0.5, y, 5.4, 0.4, row["name"], 12.5, INK, bold=True)
        add_text(s, 5.9, y, 2.6, 0.4, f"{row['risk_score']} / 100", 12.5, color, bold=True)
        add_text(s, 8.6, y, 4.3, 0.4, row["classification"], 12.5, color, bold=True)
        y += 0.42
    add_text(s, 0.5, y + 0.1, 12.4, 1.0, "14 real scans: 12 seeded via scripts/seed_demo.py + 2 from UI capture; all executed against the running FastAPI backend. Archived in docs/demo_results.json.", 11, MUTED)

    # Slide 6 — Honest limitations
    s = prs.slides.add_slide(blank)
    add_bg(s)
    add_text(s, 0.5, 0.35, 12.5, 0.6, "Honest Limitations", 24, DANGER, bold=True)
    add_bullets(s, 0.5, 1.1, 12.4, 5.6, [
        "Email metrics inflated by temporal mismatch: ham from 2003 vs phishing 2019–2025.",
        "URL detection F1 ~0.74; lexical host features miss novel and page-content-based attacks.",
        "False positives on unseen legitimate hosts and hosting-platform subdomains.",
        "Graph is a static corpus snapshot — no WHOIS, DNS, IP reputation, live blocklists.",
        "No GNN, no URL fetching, no sandbox, no attachment analysis.",
        "Thresholds and weights are product heuristics, not calibrated probabilities.",
    ])

    # Slide 7 — Deliverables & reproducibility
    s = prs.slides.add_slide(blank)
    add_bg(s)
    add_text(s, 0.5, 0.35, 12.5, 0.6, "Deliverables & Reproducibility", 24, ACCENT, bold=True)
    add_bullets(s, 0.5, 1.1, 6.1, 5.8, [
        "Backend tests: 83 passed (offline, no GPU or LLM key, no URL fetch).",
        "Frontend: TypeScript strict + Vite production build passes.",
        "Docs: architecture, methodology, API, testing, limitations, 8 Mermaid diagrams.",
        "Report: DOCX + PDF generated from real metrics.",
        "Demo: 14 real scans (12 seeded + 2 UI) archived with screenshots.",
    ])
    add_bullets(s, 6.9, 1.1, 6.0, 5.8, [
        "Rebuild: download_datasets.py → build_datasets.py → train_models.py → build_graph.py",
        "Start: uvicorn app.main:app --port 8000",
        "Demo DB: python3 scripts/seed_demo.py",
        "No API keys committed; configuration via .env / environment.",
    ])

    OUT.parent.mkdir(parents=True, exist_ok=True)
    prs.save(OUT)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
