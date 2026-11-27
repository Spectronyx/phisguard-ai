"""Artifact loading and model inference.

Artifacts are created by ``scripts/train_models.py``. If an artifact is
missing or corrupt, the registry reports it as unavailable and callers fall
back to deterministic analysis. Missing artifacts never crash the API.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from app.core.config import Settings
from app.ml.url_features import MODEL_FEATURE_NAMES

logger = logging.getLogger(__name__)


@dataclass
class LoadedArtifact:
    name: str
    path: Path
    payload: dict[str, Any] | None
    error: str | None = None

    @property
    def available(self) -> bool:
        return self.payload is not None


class ModelRegistry:
    """Thread-safe lazy loader for the email, URL and graph artifacts."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._lock = threading.Lock()
        self._email: LoadedArtifact | None = None
        self._url: LoadedArtifact | None = None
        self._graph: LoadedArtifact | None = None

    # ------------------------------------------------------------------
    def _load(self, filename: str, name: str, loader=joblib.load) -> LoadedArtifact:
        path = self.settings.artifacts_dir / filename
        if not path.exists():
            return LoadedArtifact(name=name, path=path, payload=None, error="artifact not found")
        try:
            payload = loader(path)
            if not isinstance(payload, dict):
                raise ValueError("unexpected artifact format")
            return LoadedArtifact(name=name, path=path, payload=payload)
        except Exception as exc:  # corrupt artifact must not crash startup
            logger.warning("Failed to load artifact %s: %s", path, exc)
            return LoadedArtifact(name=name, path=path, payload=None, error=f"load error: {type(exc).__name__}")

    def email_artifact(self) -> LoadedArtifact:
        with self._lock:
            if self._email is None:
                self._email = self._load("email_model.joblib", "email_model")
            return self._email

    def url_artifact(self) -> LoadedArtifact:
        with self._lock:
            if self._url is None:
                self._url = self._load("url_model.joblib", "url_model")
            return self._url

    def graph_artifact(self) -> LoadedArtifact:
        with self._lock:
            if self._graph is None:
                self._graph = self._load("domain_graph.pkl", "domain_graph")
            return self._graph

    def reload(self) -> None:
        with self._lock:
            self._email = self._url = self._graph = None

    # ------------------------------------------------------------------
    def predict_email(self, text: str) -> tuple[float, float, str]:
        """Return (phishing probability, confidence, model name)."""
        artifact = self.email_artifact()
        if not artifact.available:
            raise ModelUnavailable("email model artifact is not available")
        pipeline = artifact.payload.get("pipeline")
        if pipeline is None:
            raise ModelUnavailable("email model artifact has no pipeline")
        proba = float(pipeline.predict_proba([text])[0][1])
        confidence = max(proba, 1.0 - proba)
        model_name = artifact.payload.get("algorithm", "logistic_regression")
        return proba, confidence, model_name

    def email_top_tokens(self, text: str, limit: int = 6) -> list[dict[str, float]]:
        """Top positive TF-IDF tokens for the linear email model.

        This is a genuine (local) explanation of the logistic regression
        contribution, not a generated rationale.
        """
        artifact = self.email_artifact()
        if not artifact.available:
            return []
        pipeline = artifact.payload.get("pipeline")
        try:
            vectorizer = pipeline.named_steps["tfidf"]
            classifier = pipeline.named_steps["clf"]
            matrix = vectorizer.transform([text])
            if matrix.nnz == 0:
                return []
            coefficients = classifier.coef_[0]
            rows, cols = matrix.nonzero()
            names = vectorizer.get_feature_names_out()
            scored: dict[str, float] = {}
            for row, col in zip(rows, cols):
                contribution = float(matrix[row, col] * coefficients[col])
                if contribution > 0:
                    token = str(names[col])
                    scored[token] = scored.get(token, 0.0) + contribution
            ordered = sorted(scored.items(), key=lambda item: item[1], reverse=True)[:limit]
            return [{"token": token, "contribution": round(value, 4)} for token, value in ordered]
        except Exception:
            return []

    def predict_url(self, features: dict[str, float], host: str = "") -> tuple[float, float, str]:
        """Return (malicious probability, confidence, model name)."""
        artifact = self.url_artifact()
        if not artifact.available:
            raise ModelUnavailable("URL model artifact is not available")
        model = artifact.payload.get("model")
        if model is None:
            raise ModelUnavailable("URL model artifact has no estimator")
        names = artifact.payload.get("features", MODEL_FEATURE_NAMES)
        frame = pd.DataFrame([{name: float(features.get(name, 0.0)) for name in names}])
        frame["host"] = host
        proba = float(model.predict_proba(frame)[0][1])
        confidence = max(proba, 1.0 - proba)
        model_name = artifact.payload.get("algorithm", "random_forest")
        return proba, confidence, model_name

    def popular_domains(self) -> set[str]:
        artifact = self.url_artifact()
        if not artifact.available:
            return set()
        return set(artifact.payload.get("popular_domains", set()))

    def graph_payload(self) -> dict[str, Any] | None:
        artifact = self.graph_artifact()
        return artifact.payload if artifact.available else None

    # ------------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        email = self.email_artifact()
        url = self.url_artifact()
        graph = self.graph_artifact()
        mode = "ml" if (email.available or url.available) else "heuristic_fallback"
        return {
            "email_model": self._artifact_status(email, "TF-IDF + Logistic Regression"),
            "url_model": self._artifact_status(url, "Random Forest (selected)"),
            "domain_graph": self._artifact_status(graph, "NetworkX domain graph"),
            "email_available": email.available,
            "url_available": url.available,
            "graph_available": graph.available,
            "inference_mode": mode,
        }

    @staticmethod
    def _artifact_status(artifact: LoadedArtifact, default_algorithm: str) -> dict[str, Any]:
        payload = artifact.payload or {}
        meta = payload.get("metadata", {}) if payload else {}
        metrics = payload.get("metrics", {}) if payload else {}
        return {
            "name": artifact.name,
            "available": artifact.available,
            "path": str(artifact.path),
            "algorithm": payload.get("algorithm", default_algorithm) if payload else default_algorithm,
            "trained_at": meta.get("trained_at"),
            "metrics": metrics,
            "error": artifact.error,
        }

    def metrics_summary(self) -> dict[str, Any]:
        return {
            "email": (self.email_artifact().payload or {}).get("metrics", {}),
            "url": (self.url_artifact().payload or {}).get("metrics", {}),
        }

    def metrics_json(self) -> str:
        return json.dumps(self.metrics_summary(), indent=2, default=str)


class ModelUnavailable(RuntimeError):
    """Raised when inference is requested but no usable artifact exists."""
