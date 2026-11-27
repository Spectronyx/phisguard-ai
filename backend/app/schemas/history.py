"""Schemas for scan history, dashboard statistics and model status."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.analysis import AnalysisResponse, Classification, ComponentOut, IndicatorOut, RiskLevel


class ScanListItem(BaseModel):
    id: int
    scan_type: str
    input_summary: str
    classification: Classification
    risk_level: RiskLevel
    risk_score: int
    model_confidence: float | None = None
    llm_used: bool = False
    indicator_count: int = 0
    created_at: datetime


class ScanPage(BaseModel):
    items: list[ScanListItem]
    total: int
    page: int
    page_size: int
    pages: int


class ScanDetailResponse(BaseModel):
    scan: AnalysisResponse


class RecentScan(BaseModel):
    id: int
    scan_type: str
    input_summary: str
    classification: str
    risk_level: str
    risk_score: int
    created_at: datetime


class DistributionPoint(BaseModel):
    name: str
    value: int


class IndicatorCount(BaseModel):
    name: str
    count: int


class DashboardStats(BaseModel):
    total_scans: int
    phishing_detections: int
    suspicious_detections: int
    safe_detections: int
    critical_detections: int
    average_risk_score: float
    email_scans: int
    url_scans: int
    llm_assisted_scans: int
    recent_scans: list[RecentScan] = []
    distribution: list[DistributionPoint] = []
    top_indicators: list[IndicatorCount] = []


class TrendPoint(BaseModel):
    date: date
    scans: int
    phishing: int
    average_risk_score: float


class TrendResponse(BaseModel):
    days: int
    points: list[TrendPoint]


class ArtifactStatus(BaseModel):
    name: str
    available: bool
    path: str
    algorithm: str | None = None
    trained_at: str | None = None
    metrics: dict[str, Any] = Field(default_factory=dict)


class ModelStatusResponse(BaseModel):
    email_model: ArtifactStatus
    url_model: ArtifactStatus
    domain_graph: ArtifactStatus
    inference_mode: str
    llm_enabled: bool
    llm_configured: bool
    llm_model: str
    local_llm: ArtifactStatus | None = None
    local_llm_enabled: bool = False
    local_llm_available: bool = False
    local_llm_model: str | None = None
    llm_backend: str | None = None
    notes: list[str] = []


class ComponentDetailOut(ComponentOut):
    pass


__all__ = [
    "AnalysisResponse",
    "ComponentOut",
    "ComponentDetailOut",
    "IndicatorOut",
    "ScanListItem",
    "ScanPage",
    "ScanDetailResponse",
    "DashboardStats",
    "TrendResponse",
    "ModelStatusResponse",
]
