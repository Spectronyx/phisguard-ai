"""Train and evaluate the email and URL phishing classifiers.

Method:
- Stratified 70/15/15 train/validation/test split (seed 42).
- Validation set used for model/hyperparameter selection only.
- Selected model refit on train+validation, then evaluated once on the held-out
  test set. Test data never influences training or selection.
- Metrics include accuracy, precision, recall, F1, ROC-AUC and confusion matrix.

Usage:
    python backend/scripts/train_models.py [--quick]
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import ComplementNB
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import get_settings  # noqa: E402
from app.ml.popularity import load_popular_domains  # noqa: E402
from app.ml.url_features import MODEL_FEATURE_NAMES, extract_features, registrable_domain  # noqa: E402
from app.nlp.features import normalize_text  # noqa: E402

PROCESSED_DIR = BACKEND_DIR / "datasets" / "processed"
ARTIFACTS_DIR = BACKEND_DIR / "artifacts"
POPULARITY_PATH = BACKEND_DIR / "datasets" / "raw" / "top-1m.csv.zip"
POPULAR_LIMIT = 10_000
SEED = 42


def metrics_block(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: np.ndarray,
    labels: tuple[str, str] = ("legitimate", "phishing"),
) -> dict:
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, y_proba)), 4),
        "confusion_matrix": {
            "labels": [labels[0], labels[1]],
            "matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
        "support": {labels[0]: int((y_true == 0).sum()), labels[1]: int((y_true == 1).sum())},
    }


def threshold_table(y_true: np.ndarray, y_proba: np.ndarray) -> list[dict]:
    rows = []
    for threshold in (0.3, 0.5, 0.7):
        pred = (y_proba >= threshold).astype(int)
        rows.append({
            "threshold": threshold,
            "precision": round(float(precision_score(y_true, pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_true, pred, zero_division=0)), 4),
            "f1": round(float(f1_score(y_true, pred, zero_division=0)), 4),
        })
    return rows


def split_indices(y: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    indices = np.arange(len(y))
    train_val, test = train_test_split(indices, test_size=0.15, stratify=y, random_state=SEED)
    train, validation = train_test_split(
        train_val, test_size=0.176470588, stratify=y[train_val], random_state=SEED
    )  # 0.17647 of 85% ≈ 15% of all data
    return train, validation, test


def train_email(quick: bool = False) -> dict:
    path = PROCESSED_DIR / "email_dataset.csv"
    df = pd.read_csv(path).fillna("")
    df = df[df["body"].str.len() >= 20].reset_index(drop=True)
    y = df["label"].astype(int).to_numpy()
    texts = [normalize_text(str(s), str(b)) for s, b in zip(df["subject"], df["body"])]
    train, validation, test = split_indices(y)
    print(f"[email] rows={len(df)} train={len(train)} validation={len(validation)} test={len(test)}")

    vectorizer = TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.95,
        sublinear_tf=True,
        strip_accents="unicode",
    )
    x_train = vectorizer.fit_transform([texts[i] for i in train])
    x_val = vectorizer.transform([texts[i] for i in validation])
    y_train, y_val = y[train], y[validation]

    candidates = [0.5, 1.0, 2.0, 4.0] if not quick else [1.0]
    tuning = []
    best_c, best_f1 = 1.0, -1.0
    for c_value in candidates:
        clf = LogisticRegression(C=c_value, max_iter=2000, class_weight="balanced", solver="lbfgs")
        clf.fit(x_train, y_train)
        val_proba = clf.predict_proba(x_val)[:, 1]
        val_pred = (val_proba >= 0.5).astype(int)
        val_f1 = float(f1_score(y_val, val_pred, zero_division=0))
        tuning.append({
            "C": c_value,
            "validation_f1": round(val_f1, 4),
            "validation_precision": round(float(precision_score(y_val, val_pred, zero_division=0)), 4),
            "validation_recall": round(float(recall_score(y_val, val_pred, zero_division=0)), 4),
        })
        if val_f1 > best_f1:
            best_c, best_f1 = c_value, val_f1

    # Refit selected model on train+validation, evaluate once on test.
    train_val = np.concatenate([train, validation])
    x_train_val = vectorizer.transform([texts[i] for i in train_val])
    y_train_val = y[train_val]
    x_test = vectorizer.transform([texts[i] for i in test])
    y_test = y[test]

    final_clf = LogisticRegression(C=best_c, max_iter=2000, class_weight="balanced", solver="lbfgs")
    final_clf.fit(x_train_val, y_train_val)
    test_proba = final_clf.predict_proba(x_test)[:, 1]
    test_pred = (test_proba >= 0.5).astype(int)
    test_metrics = metrics_block(y_test, test_pred, test_proba)

    # Baseline comparison on the identical split.
    baseline = ComplementNB()
    baseline.fit(x_train_val, y_train_val)
    baseline_proba = baseline.predict_proba(x_test)[:, 1]
    baseline_pred = (baseline_proba >= 0.5).astype(int)
    baseline_metrics = metrics_block(y_test, baseline_pred, baseline_proba)

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            min_df=2,
            max_df=0.95,
            sublinear_tf=True,
            strip_accents="unicode",
        )),
        ("clf", LogisticRegression(C=best_c, max_iter=2000, class_weight="balanced", solver="lbfgs")),
    ])
    pipeline.fit([texts[i] for i in train_val], y_train_val)

    metadata = {
        "task": "email_phishing_detection",
        "dataset": "Nazario phishing corpus (2019-2025) + SpamAssassin ham",
        "dataset_rows": int(len(df)),
        "label_distribution": {
            "legitimate": int((y == 0).sum()),
            "phishing": int((y == 1).sum()),
        },
        "split": {"train": int(len(train)), "validation": int(len(validation)), "test": int(len(test))},
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "seed": SEED,
        "selected_C": best_c,
        "threshold": 0.5,
        "selection_metric": "validation F1",
        "notes": (
            "class_weight=balanced compensates for class imbalance. Metrics at 0.5 threshold. "
            "Confidence is max(p, 1-p) and is NOT the risk score."
        ),
    }
    metrics = {
        "task": "email_phishing_detection",
        "dataset": metadata["dataset"],
        "dataset_rows": metadata["dataset_rows"],
        "label_distribution": metadata["label_distribution"],
        "split": metadata["split"],
        "algorithm": f"TF-IDF (1-2 grams) + Logistic Regression (C={best_c})",
        "threshold": 0.5,
        "validation": max(tuning, key=lambda row: row["validation_f1"]),
        "test": test_metrics,
        "threshold_analysis": threshold_table(y_test, test_proba),
        "baseline_complement_nb": baseline_metrics,
        "tuning": tuning,
        "seed": SEED,
    }

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "pipeline": pipeline,
            "algorithm": "logistic_regression",
            "features": "tfidf_word_1_2",
            "metadata": metadata,
            "metrics": metrics,
        },
        ARTIFACTS_DIR / "email_model.joblib",
        compress=3,
    )
    print(f"[email] selected C={best_c}; test F1={test_metrics['f1']} precision={test_metrics['precision']} recall={test_metrics['recall']}")
    return metrics


def extract_url_features_batch(
    urls: list[str], popular_domains: set[str] | None = None
) -> tuple[np.ndarray, list[str], list[int]]:
    rows: list[list[float]] = []
    hosts: list[str] = []
    invalid: list[int] = []
    for index, url in enumerate(urls):
        try:
            features, parsed = extract_features(url, popular_domains=popular_domains)
            if not parsed.is_valid:
                invalid.append(index)
                continue
            rows.append([features[name] for name in MODEL_FEATURE_NAMES])
            hosts.append(parsed.host)
        except Exception:
            invalid.append(index)
    return np.asarray(rows, dtype=float), hosts, invalid


def build_url_candidates(quick: bool = False) -> dict[str, Pipeline]:
    """Return the candidate URL pipelines.

    Numeric host/path features are shared. The second candidate adds character
    n-grams of the raw hostname so the classifier can generalise across
    lookalike spellings instead of relying on a handful of aggregate ratios.
    """

    numeric = ColumnTransformer(
        [("num", StandardScaler(), MODEL_FEATURE_NAMES)], remainder="drop"
    )
    host_chars = ColumnTransformer(
        [
            (
                "host",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    min_df=2,
                    max_features=6_000,
                    sublinear_tf=True,
                    lowercase=True,
                ),
                "host",
            ),
            ("num", StandardScaler(), MODEL_FEATURE_NAMES),
        ],
        remainder="drop",
    )

    return {
        "random_forest_lexical": Pipeline([
            ("cols", numeric),
            ("clf", RandomForestClassifier(
                n_estimators=150 if quick else 400,
                min_samples_leaf=2,
                max_features="sqrt",
                class_weight="balanced",
                random_state=SEED,
                n_jobs=-1,
            )),
        ]),
        "logistic_regression_host_char": Pipeline([
            ("cols", host_chars),
            ("clf", LogisticRegression(C=1.0, max_iter=3000, class_weight="balanced", solver="lbfgs")),
        ]),
        "logistic_regression_host_char_c4": Pipeline([
            ("cols", host_chars),
            ("clf", LogisticRegression(C=4.0, max_iter=3000, class_weight="balanced", solver="lbfgs")),
        ]),
    }


def train_url(quick: bool = False) -> dict:
    path = PROCESSED_DIR / "url_dataset.csv"
    df = pd.read_csv(path).fillna("")
    y_all = df["label"].astype(int).to_numpy()
    urls = df["url"].astype(str).tolist()

    popular_domains: set[str] = set()
    if POPULARITY_PATH.exists():
        popular_domains = load_popular_domains(POPULARITY_PATH, limit=POPULAR_LIMIT)
        print(f"[url] popularity prior: {len(popular_domains)} registrable domains from Cisco Umbrella top-1M")
    else:
        print("[url] popularity prior unavailable; is_popular_domain will be constant 0")

    matrix, hosts, invalid = extract_url_features_batch(urls, popular_domains)
    if invalid:
        print(f"[url] dropping {len(invalid)} unparseable URLs")
        invalid_set = set(invalid)
        keep = [i for i in range(len(urls)) if i not in invalid_set]
        urls = [urls[i] for i in keep]
        y_all = y_all[keep]
    y = y_all
    train, validation, test = split_indices(y)
    print(f"[url] rows={len(y)} train={len(train)} validation={len(validation)} test={len(test)}")

    frame = pd.DataFrame(matrix, columns=MODEL_FEATURE_NAMES)
    frame["host"] = hosts
    frame["label"] = y

    train_frame = frame.iloc[train]
    val_frame = frame.iloc[validation]
    train_val_frame = frame.iloc[np.concatenate([train, validation])]
    test_frame = frame.iloc[test]
    y_train, y_val = y[train], y[validation]
    y_train_val, y_test = y[np.concatenate([train, validation])], y[test]

    tuning = []
    for name, pipeline in build_url_candidates(quick=quick).items():
        started = time.perf_counter()
        pipeline.fit(train_frame, y_train)
        val_proba = pipeline.predict_proba(val_frame)[:, 1]
        val_pred = (val_proba >= 0.5).astype(int)
        tuning.append({
            "algorithm": name,
            "validation_f1": round(float(f1_score(y_val, val_pred, zero_division=0)), 4),
            "validation_precision": round(float(precision_score(y_val, val_pred, zero_division=0)), 4),
            "validation_recall": round(float(recall_score(y_val, val_pred, zero_division=0)), 4),
            "fit_seconds": round(time.perf_counter() - started, 2),
        })
        print(f"[url] {name}: validation F1={tuning[-1]['validation_f1']}")

    best = max(tuning, key=lambda row: row["validation_f1"])
    chosen_name = best["algorithm"]
    print(f"[url] selected {chosen_name}")

    # Refit every candidate on train+validation for an apples-to-apples test comparison.
    comparison = {}
    final_model: Pipeline | None = None
    test_proba = np.zeros(len(y_test))
    for name, pipeline in build_url_candidates(quick=quick).items():
        pipeline.fit(train_val_frame, y_train_val)
        proba = pipeline.predict_proba(test_frame)[:, 1]
        pred = (proba >= 0.5).astype(int)
        comparison[name] = metrics_block(y_test, pred, proba, labels=("benign", "malicious"))
        if name == chosen_name:
            final_model = pipeline
            test_proba = proba

    assert final_model is not None
    test_pred = (test_proba >= 0.5).astype(int)
    test_metrics = metrics_block(y_test, test_pred, test_proba, labels=("benign", "malicious"))

    # Transparency check: how the documented popularity calibration used at
    # inference time would affect the held-out test set. This is not tuned on
    # test data; the factor is a fixed setting.
    calibration_factor = float(get_settings().url_popularity_calibration)
    bare_popular = (
        (test_frame["is_popular_domain"].to_numpy() == 1)
        & (test_frame["host"].map(registrable_domain).to_numpy() == test_frame["host"].to_numpy())
    )
    calibrated_proba = np.where(bare_popular, test_proba * calibration_factor, test_proba)
    calibrated_metrics = metrics_block(
        y_test, (calibrated_proba >= 0.5).astype(int), calibrated_proba, labels=("benign", "malicious")
    )
    calibrated_metrics["calibration_factor"] = calibration_factor
    calibrated_metrics["calibrated_rows"] = int(bare_popular.sum())


    feature_importance = []
    column_names = [str(name).split("__", 1)[-1] for name in final_model.named_steps["cols"].get_feature_names_out()]
    if chosen_name.startswith("random_forest"):
        values = final_model.named_steps["clf"].feature_importances_
    else:
        values = final_model.named_steps["clf"].coef_[0]
    feature_importance = sorted(
        [{"feature": name, "importance": round(float(value), 4)} for name, value in zip(column_names, values)],
        key=lambda row: abs(row["importance"]),
        reverse=True,
    )

    metadata = {
        "task": "url_phishing_detection",
        "dataset": "Kaggle Malicious URLs (benign+phishing, derived from ISCX-URL-2016) + Phishing.Database active links",
        "dataset_rows": int(len(y)),
        "label_distribution": {"benign": int((y == 0).sum()), "malicious": int((y == 1).sum())},
        "split": {"train": int(len(train)), "validation": int(len(validation)), "test": int(len(test))},
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "seed": SEED,
        "selected_algorithm": chosen_name,
        "features": MODEL_FEATURE_NAMES,
        "model_inputs": "hostname character n-grams (3-5) + host-centric numeric features",
        "popularity_prior": {
            "source": "Cisco Umbrella top-1M (public ranking)",
            "domains": len(popular_domains),
            "usage": "is_popular_domain feature only; not a whitelist",
        },
        "threshold": 0.5,
        "selection_metric": "validation F1",
        "notes": (
            "All samples are real URLs; no URL was fetched. Samples are deduplicated to one URL per hostname. "
            "Path/query lexical features are included in the numeric vector but benign corpora are homepage-heavy, "
            "so hostname character n-grams and the popularity prior carry most of the generalisation. "
            "Model selection used validation F1; test metrics are from the refit selected model. "
            f"At inference, bare registrable domains in the popularity ranking are calibrated by x{calibration_factor} "
            "post-processing; raw test metrics are reported separately from the calibrated check."
        ),
    }
    metrics = {
        "task": "url_phishing_detection",
        "dataset": metadata["dataset"],
        "dataset_rows": metadata["dataset_rows"],
        "label_distribution": metadata["label_distribution"],
        "split": metadata["split"],
        "selected_algorithm": chosen_name,
        "threshold": 0.5,
        "validation": best,
        "test": test_metrics,
        "test_with_popularity_calibration": calibrated_metrics,
        "threshold_analysis": threshold_table(y_test, test_proba),
        "comparison": comparison,
        "tuning": tuning,
        "feature_importance": feature_importance[:15],
        "seed": SEED,
    }

    joblib.dump(
        {
            "model": final_model,
            "algorithm": chosen_name,
            "features": MODEL_FEATURE_NAMES,
            "popular_domains": popular_domains,
            "metadata": metadata,
            "metrics": metrics,
        },
        ARTIFACTS_DIR / "url_model.joblib",
        compress=3,
    )
    print(f"[url] test F1={test_metrics['f1']} precision={test_metrics['precision']} recall={test_metrics['recall']} AUC={test_metrics['roc_auc']}")
    return metrics


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true", help="fewer trees / single email C for smoke runs")
    args = parser.parse_args()
    started = time.perf_counter()
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    email_metrics = train_email(quick=args.quick)
    url_metrics = train_url(quick=args.quick)

    dataset_metadata_path = PROCESSED_DIR / "dataset_metadata.json"
    dataset_metadata = (
        json.loads(dataset_metadata_path.read_text()) if dataset_metadata_path.exists() else {}
    )
    combined = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "training_seconds": round(time.perf_counter() - started, 2),
        "seed": SEED,
        "environment": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "pandas": pd.__version__,
            "numpy": np.__version__,
        },
        "dataset_metadata": dataset_metadata,
        "email": email_metrics,
        "url": url_metrics,
    }
    (ARTIFACTS_DIR / "metrics.json").write_text(json.dumps(combined, indent=2), encoding="utf-8")
    print(f"\nWrote {ARTIFACTS_DIR / 'metrics.json'}")
    print(f"Total training time: {combined['training_seconds']} s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
