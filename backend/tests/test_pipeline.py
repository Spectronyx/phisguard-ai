"""End-to-end pipeline behaviour, including rules-only degradation."""

from __future__ import annotations

from app.agents.pipeline import AnalysisOrchestrator
from app.core.config import Settings
from app.ml.model_registry import ModelRegistry

PHISH_EMAIL = {
    "subject": "URGENT: Your SBI account will be suspended",
    "body": (
        "Dear Customer, we detected unauthorized access to your account. You must verify "
        "your account within 24 hours or it will be permanently suspended. Enter your password "
        "and OTP at http://sbi-secure-login.xyz/verify to restore access."
    ),
    "sender": "SBI Support <alerts@sbi-verify.xyz>",
}

LEGIT_EMAIL = {
    "subject": "CS473 project review schedule",
    "body": (
        "Hi Rajneesh, the project review is on Friday at 3 PM in Lab 4. "
        "Please bring the current report and demo."
    ),
    "sender": "sharma@university.edu",
}


class TestPipeline:
    def test_phishing_email_is_detected(self, settings: Settings):
        result = AnalysisOrchestrator(settings).analyze_email(**PHISH_EMAIL)
        assert result["classification"] == "phishing"
        assert result["risk_score"] >= 60
        assert result["risk_level"] in {"high", "critical"}
        names = {component["name"] for component in result["components"]}
        assert {"email_model", "email_rules", "url_model", "url_rules", "graph", "llm"} <= names
        assert result["url_results"]
        assert result["llm_used"] is False

    def test_legitimate_email_is_not_phishing(self, settings: Settings):
        result = AnalysisOrchestrator(settings).analyze_email(**LEGIT_EMAIL)
        assert result["classification"] in {"safe", "suspicious"}
        assert result["risk_score"] < 60

    def test_phishing_url_is_detected(self, settings: Settings):
        result = AnalysisOrchestrator(settings).analyze_url(
            "http://adobe-reader-283901.standard.us-east-1.oortech.com/documents.org?778780"
        )
        assert result["classification"] == "phishing"
        assert result["risk_score"] >= 60

    def test_benign_url_is_safe(self, settings: Settings):
        result = AnalysisOrchestrator(settings).analyze_url("https://www.google.com/")
        assert result["classification"] == "safe"
        assert result["risk_score"] < 30

    def test_risk_confidence_are_separate_fields(self, settings: Settings):
        result = AnalysisOrchestrator(settings).analyze_url("https://example.com/")
        assert isinstance(result["risk_score"], int)
        assert result["model_confidence"] is None or 0.5 <= result["model_confidence"] <= 1.0

    def test_rules_only_fallback_without_artifacts(self, rules_only_settings: Settings):
        orchestrator = AnalysisOrchestrator(rules_only_settings)
        result = orchestrator.analyze_url("http://paypal-secure.xyz/verify-account")
        assert result["classification"] == "suspicious" or result["classification"] == "phishing"
        component_status = {c["name"]: c["status"] for c in result["components"]}
        assert component_status["url_model"] == "unavailable"
        assert component_status["url_rules"] == "ok"
        # No exception raised, and the result is still explainable.
        assert result["explanation"]
        assert result["recommendation"]

    def test_missing_graph_does_not_crash_email(self, rules_only_settings: Settings):
        result = AnalysisOrchestrator(rules_only_settings).analyze_email(**LEGIT_EMAIL)
        component_status = {c["name"]: c["status"] for c in result["components"]}
        assert component_status["email_model"] == "unavailable"
        assert component_status["graph"] == "no_data"
        assert result["classification"] in {"safe", "suspicious"}

    def test_url_not_fetched_notice(self, settings: Settings):
        result = AnalysisOrchestrator(settings).analyze_url("https://example.com/")
        assert "never fetched" in result["details"]["notice"]
        assert result["llm_sent_to_provider"] is False

    def test_email_body_is_not_stored(self, settings: Settings):
        result = AnalysisOrchestrator(settings).analyze_email(**PHISH_EMAIL)
        assert "body" not in result["details"]
        assert "notice" in result["details"]
        assert "full email body is not stored" in result["details"]["notice"].lower()

    def test_sender_domain_feeds_graph_stage(self, settings: Settings):
        result = AnalysisOrchestrator(settings).analyze_email(**PHISH_EMAIL)
        graph = next(c for c in result["components"] if c["name"] == "graph")
        assert "sbi-verify.xyz" in graph["details"]["domains"]
