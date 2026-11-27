"""HTTP API contract, persistence and validation."""

from __future__ import annotations

from fastapi.testclient import TestClient

API = "/api/v1"


def analyze_url(client: TestClient, url: str) -> dict:
    response = client.post(f"{API}/analyze/url", json={"url": url})
    assert response.status_code == 200, response.text
    return response.json()


def analyze_email(client: TestClient, payload: dict) -> dict:
    response = client.post(f"{API}/analyze/email", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


class TestSystem:
    def test_health(self, client: TestClient):
        response = client.get(f"{API}/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["database"] == "ok"
        assert body["artifacts_ready"] is True
        assert body["llm_enabled"] is False

    def test_model_status(self, client: TestClient):
        response = client.get(f"{API}/models/status")
        assert response.status_code == 200
        body = response.json()
        assert body["email_model"]["available"] is True
        assert body["url_model"]["available"] is True
        assert body["domain_graph"]["available"] is True
        assert body["llm_enabled"] is False
        assert any("not a Graph Neural Network" in note for note in body["notes"])


class TestUrlAnalysis:
    def test_benign_url(self, client: TestClient):
        body = analyze_url(client, "https://www.google.com/")
        assert body["scan_type"] == "url"
        assert body["classification"] == "safe"
        assert body["risk_score"] < 30
        assert body["scan_id"] > 0
        assert 0.5 <= body["model_confidence"] <= 1.0
        assert body["llm_used"] is False

    def test_phishing_url(self, client: TestClient):
        body = analyze_url(client, "http://paypal-secure-login.xyz/verify-account")
        assert body["classification"] == "phishing"
        assert body["risk_score"] >= 60
        indicator_names = {item["name"] for item in body["indicators"]}
        assert "Brand impersonation" in indicator_names

    def test_response_contains_all_component_states(self, client: TestClient):
        body = analyze_url(client, "https://example.com/")
        components = {item["name"]: item for item in body["components"]}
        assert set(components) == {"url_model", "url_rules", "graph"}
        assert components["url_rules"]["status"] == "ok"
        # Missing components must be skipped, not scored as zero.
        assert all(item["score"] is not None for item in components.values())

    def test_scan_is_persisted(self, client: TestClient):
        created = analyze_url(client, "https://example.com/")
        response = client.get(f"{API}/scans/{created['scan_id']}")
        assert response.status_code == 200
        stored = response.json()
        assert stored["scan_id"] == created["scan_id"]
        assert stored["risk_score"] == created["risk_score"]
        assert stored["details"]["url"]

    def test_unknown_scan_is_404(self, client: TestClient):
        response = client.get(f"{API}/scans/999999")
        assert response.status_code == 404
        assert response.json()["detail"] == "Scan not found"


class TestEmailAnalysis:
    PHISH = {
        "subject": "URGENT: Account suspended",
        "body": (
            "Verify your password and OTP immediately at http://sbi-secure-login.xyz/verify "
            "or your account will be permanently suspended."
        ),
        "sender": "SBI Support <alerts@sbi-verify.xyz>",
    }
    LEGIT = {
        "subject": "Project review",
        "body": "The review is on Friday at 3 PM in Lab 4.",
        "sender": "sharma@university.edu",
    }

    def test_phishing_email(self, client: TestClient):
        body = analyze_email(client, self.PHISH)
        assert body["classification"] == "phishing"
        assert body["risk_score"] >= 60
        assert body["url_results"]
        assert body["llm_sent_to_provider"] is False

    def test_legitimate_email(self, client: TestClient):
        body = analyze_email(client, self.LEGIT)
        assert body["risk_score"] < 60
        assert body["classification"] in {"safe", "suspicious"}

    def test_full_body_is_not_echoed_or_stored(self, client: TestClient):
        secret = "CONFIDENTIAL-BODY-MARKER-9271"
        body = analyze_email(client, {
            "subject": "Hello",
            "body": f"{secret} please review the attached schedule.",
            "sender": "colleague@example.com",
        })
        assert secret not in str(body.get("details", {}))
        stored = client.get(f"{API}/scans/{body['scan_id']}").json()
        assert secret not in str(stored)


class TestValidation:
    def test_empty_email_rejected(self, client: TestClient):
        response = client.post(f"{API}/analyze/email", json={"subject": " ", "body": " "})
        assert response.status_code == 422
        assert response.json()["detail"] == "Validation failed"

    def test_invalid_sender_rejected(self, client: TestClient):
        response = client.post(
            f"{API}/analyze/email",
            json={"subject": "Hi", "body": "Body", "sender": "not-an-email"},
        )
        assert response.status_code == 422

    def test_oversized_body_rejected(self, client: TestClient):
        response = client.post(
            f"{API}/analyze/email",
            json={"subject": "Hi", "body": "x" * 50_001},
        )
        assert response.status_code == 422

    def test_url_without_scheme_or_host_rejected(self, client: TestClient):
        for value in ["not a url", "http://", "javascript:alert(1)"]:
            response = client.post(f"{API}/analyze/url", json={"url": value})
            assert response.status_code == 422, value

    def test_unexpected_fields_are_ignored(self, client: TestClient):
        response = client.post(
            f"{API}/analyze/url",
            json={"url": "https://example.com/", "unexpected": "ignored"},
        )
        assert response.status_code == 200


class TestHistoryAndDashboard:
    def _seed(self, client: TestClient):
        analyze_url(client, "https://www.google.com/")
        analyze_url(client, "http://paypal-secure-login.xyz/verify")
        analyze_email(client, {
            "subject": "Invoice overdue",
            "body": "Pay immediately at http://docusign-billing.top/login",
            "sender": "billing@docusign-billing.top",
        })

    def test_list_and_filters(self, client: TestClient):
        self._seed(client)
        response = client.get(f"{API}/scans")
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 3
        assert len(body["items"]) == 3
        assert body["pages"] == 1

        phishing = client.get(f"{API}/scans", params={"classification": "phishing"}).json()
        assert phishing["total"] >= 1
        assert all(item["classification"] == "phishing" for item in phishing["items"])

        urls = client.get(f"{API}/scans", params={"scan_type": "url"}).json()
        assert urls["total"] == 2

        search = client.get(f"{API}/scans", params={"search": "Invoice"}).json()
        assert search["total"] == 1

    def test_pagination_limits(self, client: TestClient):
        self._seed(client)
        response = client.get(f"{API}/scans", params={"page_size": 2})
        assert response.json()["page_size"] == 2
        assert len(response.json()["items"]) == 2
        assert response.json()["pages"] == 2
        assert client.get(f"{API}/scans", params={"page_size": 101}).status_code == 422

    def test_dashboard_stats(self, client: TestClient):
        self._seed(client)
        body = client.get(f"{API}/dashboard/stats").json()
        assert body["total_scans"] == 3
        assert body["email_scans"] == 1
        assert body["url_scans"] == 2
        assert body["phishing_detections"] >= 1
        assert 0 <= body["average_risk_score"] <= 100
        assert sum(item["value"] for item in body["distribution"]) == 3
        assert len(body["recent_scans"]) == 3

    def test_dashboard_trend(self, client: TestClient):
        self._seed(client)
        body = client.get(f"{API}/dashboard/trend", params={"days": 7}).json()
        assert body["days"] == 7
        assert len(body["points"]) == 7
        assert sum(point["scans"] for point in body["points"]) == 3
        assert client.get(f"{API}/dashboard/trend", params={"days": 0}).status_code == 422
