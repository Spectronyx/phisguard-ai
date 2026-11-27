"""Transparent risk aggregation.

The final risk score is a weighted mean of *available* module risk scores,
followed by a small, capped corroboration bonus when multiple independent
modules agree that the item is high risk. Missing modules are excluded from
the mean instead of being treated as zero.

Model confidence is kept separate from the risk score.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.core.config import Settings

AVAILABLE_STATUSES = {"ok"}


@dataclass
class AggregatedRisk:
    risk_score: int
    risk_level: str
    classification: str
    model_confidence: float | None
    base_score: float
    corroboration_bonus: float
    breakdown: list[dict[str, Any]]
    skipped: list[dict[str, Any]]
    weights_used: dict[str, float]
    high_signal_components: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "classification": self.classification,
            "model_confidence": self.model_confidence,
            "base_score": round(self.base_score, 2),
            "corroboration_bonus": round(self.corroboration_bonus, 2),
            "breakdown": self.breakdown,
            "skipped": self.skipped,
            "weights_used": self.weights_used,
            "high_signal_components": self.high_signal_components,
        }


class RiskEngine:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def aggregate(self, components: list[dict[str, Any]]) -> AggregatedRisk:
        configured = self.settings.component_weights()
        available: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []

        for component in components:
            name = component.get("name", "unknown")
            score = component.get("score")
            status = component.get("status", "unavailable")
            if status in AVAILABLE_STATUSES and score is not None:
                available.append(component)
            else:
                skipped.append({
                    "name": name,
                    "status": status,
                    "reason": component.get("explanation", "no score produced"),
                })

        total_weight = sum(configured.get(c["name"], 0.0) for c in available)
        breakdown: list[dict[str, Any]] = []
        weights_used: dict[str, float] = {}
        base_score = 0.0

        for component in available:
            name = component["name"]
            weight = configured.get(name, 0.0)
            normalised = (weight / total_weight) if total_weight > 0 else 0.0
            contribution = normalised * float(component["score"])
            base_score += contribution
            weights_used[name] = round(normalised, 4)
            breakdown.append({
                "name": name,
                "label": component.get("label", name),
                "status": component.get("status", "ok"),
                "score": round(float(component["score"]), 2),
                "confidence": component.get("confidence"),
                "configured_weight": weight,
                "weight": round(normalised, 4),
                "contribution": round(contribution, 2),
                "explanation": component.get("explanation", ""),
                "details": component.get("details", {}),
            })

        high_signals = [c["name"] for c in available if float(c["score"]) >= self.settings.corroboration_high_score]
        bonus = 0.0
        if len(high_signals) >= 2:
            bonus = min(
                float(self.settings.corroboration_max_bonus),
                float(self.settings.corroboration_bonus) * (len(high_signals) - 1),
            )

        final = max(0, min(100, round(base_score + bonus)))
        classification = self._classify(final)
        risk_level = self._risk_level(final)

        model_confidence = None
        for component in available:
            if component["name"] in {"email_model", "url_model"} and component.get("confidence") is not None:
                model_confidence = max(model_confidence or 0.0, float(component["confidence"]))

        return AggregatedRisk(
            risk_score=final,
            risk_level=risk_level,
            classification=classification,
            model_confidence=round(model_confidence, 4) if model_confidence is not None else None,
            base_score=round(base_score, 2),
            corroboration_bonus=round(bonus, 2),
            breakdown=breakdown,
            skipped=skipped,
            weights_used=weights_used,
            high_signal_components=high_signals,
        )

    def _classify(self, score: int) -> str:
        if score >= self.settings.threshold_high:
            return "phishing"
        if score >= self.settings.threshold_suspicious:
            return "suspicious"
        return "safe"

    def _risk_level(self, score: int) -> str:
        if score >= self.settings.threshold_critical:
            return "critical"
        if score >= self.settings.threshold_high:
            return "high"
        if score >= self.settings.threshold_suspicious:
            return "suspicious"
        return "low"
