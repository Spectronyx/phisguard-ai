"""FastAPI dependencies backed by application state."""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.agents.pipeline import AnalysisOrchestrator
from app.core.config import Settings
from app.ml.model_registry import ModelRegistry
from app.services.scan_service import ScanService


def get_db(request: Request) -> Generator[Session, None, None]:
    session: Session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_registry(request: Request) -> ModelRegistry:
    return request.app.state.registry


def get_orchestrator(request: Request) -> AnalysisOrchestrator:
    return request.app.state.orchestrator


def get_scan_service(request: Request) -> ScanService:
    return request.app.state.scan_service


def api_meta() -> dict[str, Any]:
    return {"api": "PhishGuard AI", "version": "1.0"}
