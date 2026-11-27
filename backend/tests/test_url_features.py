"""Lexical URL parsing, feature extraction and deterministic rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.ml.popularity import load_popular_domains, registrable
from app.ml.url_features import (
    FEATURE_NAMES,
    MODEL_FEATURE_NAMES,
    brand_impersonation,
    evaluate_url_rules,
    extract_features,
    normalize_url,
    registrable_domain,
)

DATASETS_DIR = Path(__file__).resolve().parents[1] / "datasets"


class TestNormalisation:
    def test_adds_scheme_and_strips_www(self):
        parsed = normalize_url("www.Example.com/login?x=1")
        assert parsed.is_valid
        assert parsed.scheme == "http"
        assert parsed.host == "example.com"
        assert parsed.path == "/login"
        assert parsed.scheme_provided is False

    def test_preserves_explicit_https(self):
        parsed = normalize_url("https://example.com/a/b?q=2")
        assert parsed.scheme == "https"
        assert parsed.scheme_provided is True
        assert parsed.normalized == "https://example.com/a/b?q=2"

    @pytest.mark.parametrize("value", ["", "http://", "http://exa mple.com"])
    def test_invalid_urls_are_rejected(self, value):
        assert normalize_url(value).is_valid is False

    def test_ip_and_punycode_hosts(self):
        assert normalize_url("http://192.168.1.10/admin").is_valid
        assert normalize_url("http://xn--pple-43d.com/").is_valid

    def test_registrable_domain(self):
        assert registrable_domain("mail.google.com") == "google.com"
        assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
        assert registrable_domain("192.168.0.1") == "192.168.0.1"

    def test_brand_impersonation(self):
        flagged, brand = brand_impersonation("paypal-secure-login.xyz")
        assert flagged is True and brand == "paypal"
        assert brand_impersonation("www.paypal.com")[0] is False
        assert brand_impersonation("github.com")[0] is False


class TestFeatures:
    def test_feature_vectors_are_numeric_and_complete(self):
        features, parsed = extract_features("https://example.com/path?q=1")
        assert parsed.is_valid
        for name in (*FEATURE_NAMES, *MODEL_FEATURE_NAMES):
            assert name in features
            assert isinstance(features[name], float)

    def test_model_feature_names_exclude_obvious_corpus_artefacts(self):
        # Path-length/depth features are intentionally not model inputs because
        # public benign URL corpora are homepage-heavy.
        assert "path_length" not in MODEL_FEATURE_NAMES
        assert "uses_https" not in MODEL_FEATURE_NAMES
        assert "is_popular_domain" in MODEL_FEATURE_NAMES

    def test_popularity_prior_flag(self):
        path = DATASETS_DIR / "raw" / "top-1m.csv.zip"
        if not path.exists():
            pytest.skip("popularity dataset is not downloaded")
        popular = load_popular_domains(path)
        features, _ = extract_features("https://www.google.com/", popular_domains=popular)
        assert features["is_popular_domain"] == 1.0
        unknown, _ = extract_features("https://not-in-the-ranking.example/", popular_domains=popular)
        assert unknown["is_popular_domain"] == 0.0

    def test_popularity_helper_registrable(self):
        assert registrable("news.example.co.uk") == "example.co.uk"


class TestRules:
    def test_benign_url_has_no_indicators(self):
        result = evaluate_url_rules("https://www.google.com/")
        assert result.indicators == []
        assert result.score == 0.0

    def test_ip_and_credentials_are_flagged(self):
        result = evaluate_url_rules("http://user:pass@192.168.1.10/login")
        names = {item["name"] for item in result.indicators}
        assert "IP address host" in names
        assert "Embedded credentials" in names
        assert "Userinfo in URL" in names
        assert result.score > 40

    def test_brand_lookalike_is_critical(self):
        result = evaluate_url_rules("http://paypal-secure.xyz/verify-account")
        severities = {item["name"]: item["severity"] for item in result.indicators}
        assert severities.get("Brand impersonation") == "critical"
        assert severities.get("High-abuse TLD") == "medium"

    def test_http_warning_only_when_scheme_explicit(self):
        explicit = evaluate_url_rules("http://example.com/")
        implicit = evaluate_url_rules("example.com/")
        assert any(item["name"] == "No HTTPS" for item in explicit.indicators)
        assert not any(item["name"] == "No HTTPS" for item in implicit.indicators)

    def test_shortener_and_punycode(self):
        short = evaluate_url_rules("https://bit.ly/abc123")
        assert any(item["name"] == "URL shortener" for item in short.indicators)
        puny = evaluate_url_rules("https://xn--pple-43d.com/login")
        assert any(item["name"] == "Punycode host" for item in puny.indicators)

    def test_malformed_url_scores_medium(self):
        result = evaluate_url_rules("http://exa mple.com")
        assert result.score == 50.0
        assert result.indicators[0]["name"] == "Malformed URL"
