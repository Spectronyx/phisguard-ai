"""Email analysis service (TF-IDF model + explainable deterministic rules)."""

from __future__ import annotations

from typing import Any

from app.ml.model_registry import ModelRegistry, ModelUnavailable
from app.nlp.features import (
    anchor_mismatches,
    evaluate_email_rules,
    extract_sender_domain,
    extract_urls,
    normalize_text,
)


class EmailAnalysisService:
    def __init__(self, registry: ModelRegistry) -> None:
        self.registry = registry

    def analyze(
        self,
        subject: str,
        body: str,
        sender: str | None = None,
        provided_urls: list[str] | None = None,
        max_urls: int = 5,
    ) -> dict[str, Any]:
        text = normalize_text(subject, body)
        urls = extract_urls(f"{subject}\n{body}", provided=provided_urls, limit=max_urls)
        mismatches = anchor_mismatches(body)

        # The rule engine is fed URL indicators by the orchestrator after the
        # URL stage; here we produce the email-only evidence first.
        rule_result = evaluate_email_rules(
            subject=subject,
            body=body,
            sender=sender,
            urls=urls,
            anchor_mismatch_list=mismatches,
        )

        result: dict[str, Any] = {
            "text_length": len(text),
            "urls": urls,
            "sender_domain": extract_sender_domain(sender),
            "anchor_mismatches": mismatches,
            "indicators": rule_result.indicators,
            "rules_component": {
                "name": "email_rules",
                "label": "Email social-engineering rules",
                "status": "ok",
                "score": rule_result.score,
                "confidence": None,
                "explanation": (
                    f"{len(rule_result.indicators)} social-engineering indicator(s) detected."
                    if rule_result.indicators
                    else "No social-engineering warning indicators were triggered."
                ),
                "details": {"indicator_count": len(rule_result.indicators)},
            },
        }

        try:
            probability, confidence, algorithm = self.registry.predict_email(text)
            top_tokens = self.registry.email_top_tokens(text)
            result["model_component"] = {
                "name": "email_model",
                "label": "Email NLP classifier",
                "status": "ok",
                "score": round(probability * 100, 2),
                "confidence": round(confidence, 4),
                "explanation": (
                    f"The TF-IDF + {algorithm.replace('_', ' ')} model estimated a "
                    f"{probability * 100:.1f}% phishing probability."
                ),
                "details": {
                    "algorithm": algorithm,
                    "probability": round(probability, 4),
                    "top_tokens": top_tokens,
                    "text_length": len(text),
                },
            }
        except ModelUnavailable as exc:
            result["model_component"] = {
                "name": "email_model",
                "label": "Email NLP classifier",
                "status": "unavailable",
                "score": None,
                "confidence": None,
                "explanation": f"Email model unavailable ({exc}); rules-only assessment.",
                "details": {"fallback": "rules_only"},
            }
        except Exception as exc:
            result["model_component"] = {
                "name": "email_model",
                "label": "Email NLP classifier",
                "status": "error",
                "score": None,
                "confidence": None,
                "explanation": f"Email model inference failed ({type(exc).__name__}).",
                "details": {"fallback": "rules_only"},
            }

        return result

    def enrich_with_url_indicators(
        self,
        analysis: dict[str, Any],
        url_indicators: list[dict],
        subject: str,
        body: str,
        sender: str | None,
    ) -> dict[str, Any]:
        """Re-run the email rule engine with link evidence for a final score."""
        rule_result = evaluate_email_rules(
            subject=subject,
            body=body,
            sender=sender,
            urls=analysis["urls"],
            url_indicators=url_indicators,
            anchor_mismatch_list=analysis["anchor_mismatches"],
        )
        analysis["indicators"] = rule_result.indicators
        analysis["rules_component"]["score"] = rule_result.score
        analysis["rules_component"]["explanation"] = (
            f"{len(rule_result.indicators)} social-engineering indicator(s) detected "
            "(including embedded-link evidence)."
            if rule_result.indicators
            else "No social-engineering warning indicators were triggered."
        )
        analysis["rules_component"]["details"] = {"indicator_count": len(rule_result.indicators)}
        return analysis
