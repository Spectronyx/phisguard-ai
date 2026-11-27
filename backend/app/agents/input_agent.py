"""Input normalisation stage."""

from __future__ import annotations

from typing import Any

from app.nlp.features import extract_sender_domain, extract_urls
from app.utils.text import redact_url, sha256_text, truncate


class InputAgent:
    name = "input"

    def __init__(self, max_email_chars: int = 50_000, max_url_chars: int = 2_048, max_urls: int = 5) -> None:
        self.max_email_chars = max_email_chars
        self.max_url_chars = max_url_chars
        self.max_urls = max_urls

    def prepare_email(
        self,
        subject: str,
        body: str,
        sender: str | None,
        provided_urls: list[str] | None,
    ) -> dict[str, Any]:
        subject = (subject or "").strip()[:500]
        body = (body or "")[: self.max_email_chars]
        sender = (sender or "").strip() or None
        urls = extract_urls(f"{subject}\n{body}", provided=provided_urls, limit=self.max_urls)
        summary_source = subject if subject else body
        return {
            "subject": subject,
            "body": body,
            "sender": sender,
            "sender_domain": extract_sender_domain(sender),
            "urls": urls,
            "input_summary": truncate(summary_source, 180),
            "input_hash": sha256_text(f"{subject}\n{body}"),
        }

    def prepare_url(self, url: str) -> dict[str, Any]:
        url = (url or "").strip()[: self.max_url_chars]
        return {
            "url": url,
            "input_summary": redact_url(url),
            "input_hash": sha256_text(url.lower()),
        }
