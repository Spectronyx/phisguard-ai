#!/usr/bin/env python3
"""Fine-tune a local DistilBERT phishing text classifier on the real email corpus.

This script trains the model used by ``app.services.local_llm_service`` on the
RTX 3050 GPU (falls back to CPU when CUDA is unavailable). It is a supervised
*text classifier* fine-tuning run, not LLM pretraining; the report says so
explicitly so no capability is overclaimed.

Run from the repository root::

    .venv/bin/python backend/scripts/train_local_llm.py

Outputs:

* ``backend/artifacts/local_llm/`` — model + tokenizer (loaded at inference)
* ``backend/artifacts/local_llm_metrics.json`` — real evaluation numbers

Only the public dataset already present in ``backend/datasets/processed`` is
used. No email address is contacted and no submitted URL is fetched.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
    set_seed,
)

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
DATA_PATH = BACKEND / "datasets" / "processed" / "email_dataset.csv"
ARTIFACTS = BACKEND / "artifacts"
MODEL_DIR = ARTIFACTS / "local_llm"
METRICS_PATH = ARTIFACTS / "local_llm_metrics.json"

BASE_MODEL = "distilbert-base-uncased"
SEED = 42
MAX_LENGTH = 384
EPOCHS = 3
TRAIN_BATCH = 8
GRAD_ACCUM = 2
LEARNING_RATE = 2e-5
PHISH_LABELS = {"phishing", "phish", "malicious", "1"}


class EmailDataset(torch.utils.data.Dataset):
    """Minimal tokenised dataset for the sequence classifier."""

    def __init__(self, texts: list[str], labels: list[int], tokenizer) -> None:
        self.encodings = tokenizer(texts, truncation=True, max_length=MAX_LENGTH)
        self.labels = labels

    def __len__(self) -> int:
        return len(self.labels)

    def __getitem__(self, index: int) -> dict[str, torch.Tensor]:
        item = {key: torch.tensor(values[index]) for key, values in self.encodings.items()}
        item["labels"] = torch.tensor(self.labels[index], dtype=torch.long)
        return item


def compose_text(subject: str, body: str) -> str:
    """Match the inference-time template in LocalSemanticService._compose_text."""
    urls = re.findall(r"https?://\S+", body or "")[:5]
    lines = []
    if subject:
        lines.append("Subject: " + str(subject)[:500])
    if urls:
        lines.append("URLs: " + " ".join(u[:300] for u in urls))
    if body:
        lines.append("Body: " + str(body)[:6_000])
    return "\n".join(lines)[:8_000]


def compute_metrics(eval_prediction):
    logits, labels = eval_prediction
    probabilities = torch.softmax(torch.tensor(logits), dim=-1).numpy()
    predictions = np.argmax(probabilities, axis=-1)
    positive = probabilities[:, 1]
    return {
        "accuracy": accuracy_score(labels, predictions),
        "precision": precision_score(labels, predictions, zero_division=0),
        "recall": recall_score(labels, predictions, zero_division=0),
        "f1": f1_score(labels, predictions, zero_division=0),
        "roc_auc": roc_auc_score(labels, positive),
    }


def confusion(labels: np.ndarray, predictions: np.ndarray) -> dict[str, int]:
    matrix = confusion_matrix(labels, predictions, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    return {
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
    }


def evaluate(model, dataset, batch_size: int = 16) -> tuple[dict[str, float], dict[str, int]]:
    args = TrainingArguments(
        output_dir=str(MODEL_DIR / "eval_tmp"),
        per_device_eval_batch_size=batch_size,
        report_to=[],
        seed=SEED,
        use_cpu=not torch.cuda.is_available(),
    )
    trainer = Trainer(model=model, args=args, data_collator=DataCollatorWithPadding(tokenizer=TOKENIZER))
    prediction = trainer.predict(dataset)
    metrics = compute_metrics((prediction.predictions, prediction.label_ids))
    labels = np.asarray(prediction.label_ids)
    predictions = np.argmax(prediction.predictions, axis=-1)
    return {key: round(float(value), 4) for key, value in metrics.items()}, confusion(labels, predictions)


TOKENIZER = None  # set in main(); used by the evaluate() data collator


def main() -> None:
    global TOKENIZER
    if not DATA_PATH.exists():
        raise SystemExit(f"Dataset not found: {DATA_PATH}. Run build_datasets.py first.")

    set_seed(SEED)
    started = time.perf_counter()
    device = "cuda" if torch.cuda.is_available() else "cpu"
    gpu_name = torch.cuda.get_device_name(0) if device == "cuda" else None
    print(f"Training local LLM on {device}" + (f" ({gpu_name})" if gpu_name else ""))

    frame = pd.read_csv(DATA_PATH)
    frame = frame.dropna(subset=["subject", "body", "label"])
    labels = frame["label"].astype(str).str.strip().str.lower().map(
        lambda value: 1 if value in PHISH_LABELS else 0
    ).tolist()
    texts = [compose_text(subject, body) for subject, body in zip(frame["subject"], frame["body"])]

    # Stratified 70/15/15 split, identical protocol to the other model scripts.
    train_texts, holdout_texts, train_labels, holdout_labels = train_test_split(
        texts, labels, test_size=0.30, random_state=SEED, stratify=labels
    )
    val_texts, test_texts, val_labels, test_labels = train_test_split(
        holdout_texts, holdout_labels, test_size=0.50, random_state=SEED, stratify=holdout_labels
    )

    TOKENIZER = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL,
        num_labels=2,
        id2label={0: "legitimate", 1: "phishing"},
        label2id={"legitimate": 0, "phishing": 1},
    )
    train_dataset = EmailDataset(train_texts, train_labels, TOKENIZER)
    val_dataset = EmailDataset(val_texts, val_labels, TOKENIZER)
    test_dataset = EmailDataset(test_texts, test_labels, TOKENIZER)

    args = TrainingArguments(
        output_dir=str(MODEL_DIR / "train_tmp"),
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=TRAIN_BATCH,
        per_device_eval_batch_size=16,
        gradient_accumulation_steps=GRAD_ACCUM,
        learning_rate=LEARNING_RATE,
        weight_decay=0.01,
        warmup_ratio=0.06,
        eval_strategy="epoch",
        logging_steps=50,
        save_strategy="no",
        report_to=[],
        fp16=(device == "cuda"),
        seed=SEED,
        dataloader_num_workers=0,
        use_cpu=(device == "cpu"),
    )
    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        processing_class=TOKENIZER,
        data_collator=DataCollatorWithPadding(tokenizer=TOKENIZER),
        compute_metrics=compute_metrics,
    )
    trainer.train()

    val_metrics, val_confusion = evaluate(model, val_dataset)
    test_metrics, test_confusion = evaluate(model, test_dataset)
    training_seconds = round(time.perf_counter() - started, 2)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(MODEL_DIR)
    TOKENIZER.save_pretrained(MODEL_DIR)

    metrics = {
        "generated_on": datetime.now(timezone.utc).isoformat(),
        "base_model": BASE_MODEL,
        "fine_tuned": True,
        "task": "binary email phishing text classification (not generative LLM)",
        "disclosure": (
            "A 66M-parameter DistilBERT encoder fine-tuned on the real phishing corpus. "
            "It outputs a phishing probability, not generated text, and is not pretrained from scratch."
        ),
        "dataset": {
            "path": str(DATA_PATH.relative_to(ROOT)),
            "rows": len(frame),
            "label_distribution": {
                "legitimate": labels.count(0),
                "phishing": labels.count(1),
            },
            "split": {
                "train": len(train_labels),
                "validation": len(val_labels),
                "test": len(test_labels),
            },
            "seed": SEED,
        },
        "training": {
            "device": device,
            "gpu_name": gpu_name,
            "epochs": EPOCHS,
            "batch_size": TRAIN_BATCH,
            "gradient_accumulation_steps": GRAD_ACCUM,
            "effective_batch_size": TRAIN_BATCH * GRAD_ACCUM,
            "learning_rate": LEARNING_RATE,
            "max_length": MAX_LENGTH,
            "fp16": device == "cuda",
            "training_seconds": training_seconds,
            "torch_version": torch.__version__,
        },
        "validation": {"metrics": val_metrics, "confusion_matrix": val_confusion},
        "test": {"metrics": test_metrics, "confusion_matrix": test_confusion},
    }
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"Saved local LLM to {MODEL_DIR.relative_to(ROOT)}")
    print(f"Test metrics: {json.dumps(test_metrics)}")
    print(f"Wrote {METRICS_PATH.relative_to(ROOT)} (took {training_seconds}s)")


if __name__ == "__main__":
    main()
