"""Pydantic request/response schemas for analysis endpoints."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

Severity = Literal["low", "medium", "high", "critical"]
Classification = Literal["safe", "suspicious", "phishing"]
RiskLevel = Literal["low", "suspicious", "high", "critical"]

_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^\s]+$")


class EmailAnalysisRequest(BaseModel):
    """Raw email content submitted by the user."""

    subject: str = Field(default="", max_length=500)
    body: str = Field(default="", max_length=50_000)
    sender: str | None = Field(default=None, max_length=320)
    urls: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("urls")
    @classmethod
    def _validate_urls(cls, urls: list[str]) -> list[str]:
        cleaned: list[str] = []
        for url in urls:
            url = url.strip()
            if not url:
                continue
            if len(url) > 2_048:
                raise ValueError("URL exceeds 2048 characters")
            if not _URL_RE.match(url):
                raise ValueError(f"Invalid URL (scheme required): {url[:60]}")
            cleaned.append(url)
        return cleaned

    @model_validator(mode="after")
    def _require_content(self) -> "EmailAnalysisRequest":
        if not self.subject.strip() and not self.body.strip():
            raise ValueError("Email subject and body cannot both be empty")
        if self.sender and ("@" not in self.sender or self.sender.startswith("@") or self.sender.endswith("@")):
            raise ValueError("Sender must be a valid email address")
        return self


class UrlAnalysisRequest(BaseModel):
    """A single URL string. It is never fetched."""

    url: str = Field(min_length=3, max_length=2_048)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("URL cannot be empty")
        if any(ch.isspace() for ch in value):
            raise ValueError("URL cannot contain whitespace")
        if not _URL_RE.match(value) and not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$", value):
            raise ValueError("URL must include a valid scheme or hostname")
        return value


class IndicatorOut(BaseModel):
    name: str
    severity: Severity
    description: str
    source: str = "rules"


class ComponentOut(BaseModel):
    name: str
    label: str
    status: Literal["ok", "degraded", "no_data", "unavailable", "error", "skipped"]
    score: float | None = None
    confidence: float | None = None
    weight: float | None = None
    contribution: float | None = None
    explanation: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class UrlResultSummary(BaseModel):
    url: str
    domain: str
    risk_score: float
    classification: Classification
    indicators: list[IndicatorOut] = Field(default_factory=list)
    error: str | None = None


class AnalysisResponse(BaseModel):
    scan_id: int
    scan_type: Literal["email", "url"]
    input_summary: str
    classification: Classification
    risk_level: RiskLevel
    risk_score: int
    model_confidence: float | None = None
    indicators: list[IndicatorOut] = Field(default_factory=list)
    components: list[ComponentOut] = Field(default_factory=list)
    explanation: str
    recommendation: str
    llm_used: bool = False
    llm_sent_to_provider: bool = False
    created_at: datetime
    details: dict[str, Any] = Field(default_factory=dict)
    url_results: list[UrlResultSummary] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: str
    version: str
    database: str
    artifacts_ready: bool
    llm_enabled: bool
    timestamp: datetime
