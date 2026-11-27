"""Risk aggregation: missing modules, calibration boundaries and scoring."""

from __future__ import annotations

from app.core.config import Settings
from app.services.risk_engine import RiskEngine


def component(name: str, score: float | None, status: str = "ok") -> dict:
    return {
        "name": name,
        "label": name,
        "status": status,
        "score": score,
        "confidence": 0.9,
        "explanation": f"{name} explanation",
        "details": {},
    }


class TestRiskEngine:
    def test_missing_modules_are_excluded_not_zeroed(self, settings: Settings):
        engine = RiskEngine(settings)
        result = engine.aggregate([
            component("email_model", 80.0),
            component("email_rules", 40.0),
            component("url_model", None, "skipped"),
            component("url_rules", None, "unavailable"),
            component("graph", None, "no_data"),
            component("llm", None, "unavailable"),
        ])
        # 0.30/0.15 weights renormalise to 2/3 and 1/3.
        assert result.breakdown[0]["weight"] == 0.6667
        assert result.base_score == 66.67
        assert result.risk_score == 67
        assert result.classification == "phishing"
        assert {item["name"] for item in result.skipped} == {"url_model", "url_rules", "graph", "llm"}

    def test_empty_breakdown(self, settings: Settings):
        result = RiskEngine(settings).aggregate([component("llm", None, "unavailable")])
        assert result.breakdown == []
        assert result.risk_score == 0
        assert result.classification == "safe"

    def test_corroboration_bonus_is_capped(self, settings: Settings):
        result = RiskEngine(settings).aggregate([
            component("email_model", 90.0),
            component("email_rules", 80.0),
            component("url_model", 70.0),
            component("url_rules", 60.0),
            component("graph", 65.0),
            component("llm", 70.0),
        ])
        assert result.base_score > 70
        assert result.corroboration_bonus == settings.corroboration_max_bonus
        assert result.risk_score <= 100
        assert result.high_signal_components == [
            "email_model", "email_rules", "url_model", "url_rules", "graph", "llm",
        ]

    def test_single_high_signal_gets_no_bonus(self, settings: Settings):
        result = RiskEngine(settings).aggregate([
            component("email_model", 80.0),
            component("email_rules", 10.0),
        ])
        assert result.corroboration_bonus == 0.0

    def test_threshold_boundaries(self, settings: Settings):
        engine = RiskEngine(settings)
        boundaries = [
            (0.0, "safe", "low"),
            (29.4, "safe", "low"),
            (30.0, "suspicious", "suspicious"),
            (59.9, "suspicious", "suspicious"),
            (60.0, "phishing", "high"),
            (80.0, "phishing", "critical"),
        ]
        for score, classification, level in boundaries:
            assert engine._classify(int(score)) == classification
            assert engine._risk_level(int(score)) == level
