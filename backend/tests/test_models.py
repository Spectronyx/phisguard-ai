"""Model artifact loading, inference and graceful degradation."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.ml.model_registry import ModelRegistry, ModelUnavailable
from app.ml.url_features import extract_features
from app.services.url_service import URLAnalysisService


class TestArtifacts:
    def test_status_reports_real_artifacts(self, settings: Settings):
        registry = ModelRegistry(settings)
        status = registry.status()
        assert status["email_available"] is True
        assert status["url_available"] is True
        assert status["graph_available"] is True
        assert status["inference_mode"] == "ml"

    def test_missing_artifacts_degrade(self, rules_only_settings: Settings):
        registry = ModelRegistry(rules_only_settings)
        status = registry.status()
        assert status["email_available"] is False
        assert status["url_available"] is False
        assert status["graph_available"] is False
        assert status["inference_mode"] == "heuristic_fallback"
        with pytest.raises(ModelUnavailable):
            registry.predict_email("hello")
        with pytest.raises(ModelUnavailable):
            registry.predict_url({"hostname_length": 10.0})

    def test_email_model_separates_phishing(self, settings: Settings):
        registry = ModelRegistry(settings)
        legit, legit_conf, algorithm = registry.predict_email(
            "Hi, the project review is on Friday at 3 PM in Lab 4. Please bring the report."
        )
        phish, phish_conf, _ = registry.predict_email(
            "URGENT: your account will be suspended. Verify your password and OTP immediately "
            "at http://secure-login-verify.example to restore access."
        )
        assert algorithm == "logistic_regression"
        assert 0.0 <= legit <= 1.0 and 0.0 <= phish <= 1.0
        assert phish > legit
        assert phish > 0.5
        assert legit_conf >= 0.5 and phish_conf >= 0.5

    def test_email_local_token_explanation(self, settings: Settings):
        registry = ModelRegistry(settings)
        tokens = registry.email_top_tokens(
            "Verify your account password immediately or it will be suspended."
        )
        assert tokens
        assert all(item["contribution"] > 0 for item in tokens)
        assert len(tokens) <= 6

    def test_url_model_separates_phishing_host(self, settings: Settings):
        registry = ModelRegistry(settings)
        popular = registry.popular_domains()
        assert "google.com" in popular

        benign_features, _ = extract_features("https://www.google.com/", popular)
        phish_features, _ = extract_features(
            "http://adobe-reader-283901.standard.us-east-1.oortech.com/documents.org?778780"
        )
        benign_prob, _, _ = registry.predict_url(benign_features, host="google.com")
        phish_prob, _, _ = registry.predict_url(phish_features, host="adobe-reader-283901.standard.us-east-1.oortech.com")
        assert 0.0 <= benign_prob <= 1.0
        assert phish_prob > 0.5
        assert phish_prob > benign_prob

    def test_popular_bare_domain_is_calibrated_but_raw_is_kept(self, settings: Settings):
        service = URLAnalysisService(ModelRegistry(settings))
        result = service.analyze("https://github.com/microsoft/vscode")
        assert result["model"]["status"] == "ok"
        details = result["model"]["details"]
        assert details["popularity_calibrated"] is True
        assert details["probability_raw"] > details["probability"]
        assert details["probability"] == pytest.approx(
            details["probability_raw"] * settings.url_popularity_calibration, rel=1e-3
        )
        assert result["classification"] == "safe"

    def test_popular_subdomain_is_not_calibrated(self, settings: Settings):
        service = URLAnalysisService(ModelRegistry(settings))
        result = service.analyze("https://evil-hosted-page.github.io/login")
        assert result["model"]["status"] == "ok"
        assert result["model"]["details"]["popularity_calibrated"] is False

    def test_url_scores_are_bounded(self, settings: Settings):
        service = URLAnalysisService(ModelRegistry(settings))
        for url in ["https://example.com/", "http://paypal-secure.xyz/verify", "not a url"]:
            result = service.analyze(url)
            assert 0.0 <= result["risk_score"] <= 100.0
            assert result["classification"] in {"safe", "suspicious", "phishing"}
