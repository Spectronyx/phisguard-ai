"""Local transformer-based semantic classifier (fine-tuned DistilBERT).

This is the private, on-machine alternative to the external ``SemanticService``.
It never sends email content to a network provider and degrades to an
``unavailable`` component (excluded from risk aggregation) when the artifact or
the optional ML dependencies are missing.

The model is a 66M-parameter DistilBERT sequence classifier fine-tuned on the
real phishing/legitimate email corpus with ``scripts/train_local_llm.py``. It is
a text classifier, *not* a generative chat model; the component is still called
``llm`` because it occupies the semantic-analysis slot in the risk engine.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from app.core.config import Settings

logger = logging.getLogger(__name__)

_REQUIRED_FILES = ("config.json", "tokenizer_config.json")
_PHISH_LABELS = {"phishing", "phish", "malicious", "label_1", "1"}


class LocalSemanticService:
    """Runs a locally fine-tuned DistilBERT classifier. Never raises to callers."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._model_dir = settings.local_llm_dir
        self._model: Any = None
        self._tokenizer: Any = None
        self._device: str | None = None
        self._phish_index: int = 1
        self._lock = threading.Lock()
        self._load_attempted = False
        self._load_error: str | None = None

    # ------------------------------------------------------------------
    @property
    def model_name(self) -> str:
        return "distilbert-base-uncased (fine-tuned locally)"

    @property
    def available(self) -> bool:
        """Cheap artifact check that does not import torch or load weights."""
        return all((self._model_dir / name).exists() for name in _REQUIRED_FILES)

    @property
    def enabled(self) -> bool:
        return bool(self.settings.local_llm_enabled and self.available)

    def status(self) -> dict[str, Any]:
        """Lightweight descriptor for the /models/status endpoint."""
        return {
            "name": "local_llm",
            "available": self.available,
            "enabled": self.settings.local_llm_enabled,
            "device": self._device,
            "load_error": self._load_error,
            "model": self.model_name,
        }

    # ------------------------------------------------------------------
    def _unavailable(self, explanation: str, error: str | None = None) -> dict[str, Any]:
        details: dict[str, Any] = {
            "llm_used": False,
            "sent_to_provider": False,
            "backend": "local_distilbert",
        }
        if error:
            details["error"] = error
        return {
            "name": "llm",
            "label": "Local LLM semantic analysis",
            "status": "unavailable",
            "score": None,
            "confidence": None,
            "explanation": explanation,
            "details": details,
        }

    def _ensure_loaded(self) -> bool:
        if self._model is not None:
            return True
        if self._load_attempted:
            return False
        with self._lock:
            if self._model is not None:
                return True
            if self._load_attempted:
                return False
            self._load_attempted = True
            if not self.available:
                self._load_error = "model artifacts missing"
                return False
            try:
                import torch
                from transformers import AutoModelForSequenceClassification, AutoTokenizer

                configured = self.settings.local_llm_device
                if configured == "auto":
                    device = "cuda" if torch.cuda.is_available() else "cpu"
                else:
                    device = configured

                self._tokenizer = AutoTokenizer.from_pretrained(
                    str(self._model_dir), local_files_only=True
                )
                self._model = AutoModelForSequenceClassification.from_pretrained(
                    str(self._model_dir), local_files_only=True
                )
                self._model.to(device)
                self._model.eval()
                self._device = device

                id2label = getattr(getattr(self._model, "config", None), "id2label", None) or {}
                for idx, label in id2label.items():
                    if str(label).strip().lower() in _PHISH_LABELS:
                        self._phish_index = int(idx)
                        break
                logger.info("Local LLM loaded on %s (phish class index %s)", device, self._phish_index)
                return True
            except Exception as exc:  # optional module must never crash a scan
                self._model = None
                self._tokenizer = None
                self._load_error = f"{type(exc).__name__}: {exc}"
                logger.warning("Local LLM failed to load: %s", self._load_error)
                return False

    # ------------------------------------------------------------------
    @staticmethod
    def _compose_text(
        subject: str,
        body: str,
        sender: str | None,
        urls: list[str],
        max_body_chars: int,
    ) -> str:
        """Build a plain-text view for the classifier. All inputs are untrusted data."""
        parts: list[str] = []
        if subject:
            parts.append("Subject: " + subject[:500])
        if sender:
            parts.append("From: " + sender[:320])
        if urls:
            parts.append("URLs: " + " ".join(str(u)[:300] for u in urls[:5]))
        if body:
            parts.append("Body: " + body[:max_body_chars])
        return "\n".join(parts)[: max_body_chars + 2_000]

    def analyze(
        self,
        subject: str,
        body: str,
        sender: str | None,
        urls: list[str],
        detected_indicators: list[dict],
    ) -> dict[str, Any]:
        """Return a component dict. Never raises."""
        if not self.settings.local_llm_enabled:
            return self._unavailable("Local LLM analysis is disabled.")
        if not self.available:
            return self._unavailable(
                "Local LLM artifacts are not present; use scripts/train_local_llm.py to build them."
            )
        if not self._ensure_loaded():
            return self._unavailable(
                "Local LLM could not be loaded; local models and rules were used.",
                error=self._load_error,
            )

        try:
            import torch

            text = self._compose_text(
                subject or "",
                body or "",
                sender,
                list(urls or [])[:5],
                self.settings.max_body_chars_for_llm,
            )
            encoded = self._tokenizer(
                text,
                truncation=True,
                max_length=self.settings.local_llm_max_length,
                return_tensors="pt",
            )
            inputs = {key: value.to(self._device) for key, value in encoded.items()}
            with torch.inference_mode():
                logits = self._model(**inputs).logits
                probabilities = torch.softmax(logits, dim=-1)[0]

            p_phish = float(probabilities[self._phish_index])
            p_benign = float(probabilities[1 - self._phish_index])
            confidence = max(p_phish, p_benign)
            score = round(p_phish * 100.0, 2)
            if p_phish >= 0.7:
                classification = "phishing"
            elif p_phish >= 0.35:
                classification = "suspicious"
            else:
                classification = "safe"

            explanation = (
                f"A locally fine-tuned DistilBERT text classifier estimated a {p_phish:.0%} "
                f"phishing probability for the email text. No content was sent to any external service."
            )
            indicators: list[dict[str, Any]] = []
            if p_phish >= 0.7:
                indicators.append({
                    "name": "Local LLM flagged phishing intent",
                    "severity": "high",
                    "description": "The local semantic classifier scored the message text as phishing-like.",
                    "source": "local_llm",
                })

            return {
                "name": "llm",
                "label": "Local LLM semantic analysis (DistilBERT)",
                "status": "ok",
                "score": score,
                "confidence": round(confidence, 4),
                "explanation": explanation,
                "details": {
                    "llm_used": True,
                    "sent_to_provider": False,
                    "backend": "local_distilbert",
                    "model": self.model_name,
                    "device": self._device,
                    "llm_classification": classification,
                    "probability_phishing": round(p_phish, 4),
                    "probability_legitimate": round(p_benign, 4),
                    "tokens_analysed": int(inputs["input_ids"].shape[1]),
                    "rule_indicator_count": len(detected_indicators or []),
                },
                "indicators": indicators,
            }
        except Exception as exc:  # defensive: optional module must not crash a scan
            logger.warning("Local LLM inference failed: %s", type(exc).__name__)
            return self._unavailable(
                "Local LLM inference failed; local models and rules were used.",
                error=f"{type(exc).__name__}: {exc}",
            )


__all__ = ["LocalSemanticService"]
