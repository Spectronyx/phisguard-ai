"""Email analysis agent."""

from __future__ import annotations

from typing import Any

from app.services.email_service import EmailAnalysisService


class EmailAnalysisAgent:
    name = "email_analysis"

    def __init__(self, service: EmailAnalysisService, max_urls: int = 5) -> None:
        self.service = service
        self.max_urls = max_urls

    def analyze(
        self,
        subject: str,
        body: str,
        sender: str | None,
        provided_urls: list[str] | None,
        url_indicators: list[dict] | None = None,
    ) -> dict[str, Any]:
        result = self.service.analyze(
            subject=subject,
            body=body,
            sender=sender,
            provided_urls=provided_urls,
            max_urls=self.max_urls,
        )
        if url_indicators:
            result = self.service.enrich_with_url_indicators(
                result, url_indicators, subject=subject, body=body, sender=sender
            )
        return result
