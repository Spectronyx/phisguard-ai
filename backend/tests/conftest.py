"""Shared pytest fixtures.

Tests run fully offline: no network access, no LLM key and no URL fetching.
Each API test gets an isolated SQLite database.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app

BACKEND_DIR = Path(__file__).resolve().parents[1]
ARTIFACTS_DIR = BACKEND_DIR / "artifacts"
PROCESSED_DIR = BACKEND_DIR / "datasets" / "processed"


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        artifacts_dir=ARTIFACTS_DIR,
        local_llm_enabled=False,
        llm_enabled=False,
        llm_api_key=None,
        environment="test",
    )


@pytest.fixture()
def app(settings: Settings):
    return create_app(settings)


@pytest.fixture()
def client(app) -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def rules_only_settings(tmp_path: Path) -> Settings:
    empty = tmp_path / "empty_artifacts"
    empty.mkdir()
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'fallback.db'}",
        artifacts_dir=empty,
        local_llm_enabled=False,
        llm_enabled=False,
        llm_api_key=None,
        environment="test",
    )
