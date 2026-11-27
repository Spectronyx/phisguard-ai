"""Local LLM service and local-first routing tests.

All inference is mocked: the test suite stays offline, keyless and GPU-free.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core.config import Settings
from app.services.local_llm_service import LocalSemanticService
from app.services.llm_router import SemanticRouter


class _FakeTensor:
    shape = (1, 12)

    def to(self, device):  # noqa: ANN001 - test double
        return self


class _FakeRow:
    """One row of class probabilities [legitimate, phishing]."""

    def __getitem__(self, index):  # noqa: ANN001
        return 0.1 if index == 0 else 0.9


class _FakeTensorList:
    def __getitem__(self, index):  # noqa: ANN001, ARG002
        return _FakeRow()

    def __iter__(self):
        return iter([0.1, 0.9])


class _FakeModel:
    config = SimpleNamespace(id2label={0: "legitimate", 1: "phishing"})

    def to(self, device):  # noqa: ANN001
        return self

    def eval(self):
        return self

    def __call__(self, **inputs):  # noqa: ANN003
        return SimpleNamespace(logits=_FakeTensorList())


class _FakeTokenizer:
    def __call__(self, text, **kwargs):  # noqa: ANN001, ANN003
        return {"input_ids": _FakeTensor(), "attention_mask": _FakeTensor()}


class _FakeTorch:
    @staticmethod
    def inference_mode():
        return contextlib.nullcontext()

    @staticmethod
    def softmax(value, dim):  # noqa: ARG004
        return _FakeTensorList()


@pytest.fixture()
def local_service(settings: Settings, monkeypatch, tmp_path: Path) -> LocalSemanticService:
    local_settings = settings.model_copy(
        update={"artifacts_dir": tmp_path / "artifacts", "local_llm_enabled": True}
    )
    local_settings.local_llm_dir.mkdir(parents=True, exist_ok=True)
    service = LocalSemanticService(local_settings)
    (local_settings.local_llm_dir / "config.json").write_text("{}")
    (local_settings.local_llm_dir / "tokenizer_config.json").write_text("{}")
    monkeypatch.setitem(sys.modules, "torch", _FakeTorch)
    monkeypatch.setattr(service, "_ensure_loaded", _loaded(service))
    return service


def _loaded(service: LocalSemanticService):
    def load() -> bool:
        service._model = _FakeModel()
        service._tokenizer = _FakeTokenizer()
        service._device = "cpu"
        service._phish_index = 1
        return True

    return load


class _FakeService:
    def __init__(self, enabled: bool, result: dict) -> None:
        self.enabled = enabled
        self.result = result

    def analyze(self, **kwargs):  # noqa: ANN003
        return self.result


def _component(status: str = "ok") -> dict:
    return {
        "name": "llm",
        "label": "semantic",
        "status": status,
        "score": 80.0,
        "confidence": 0.8,
        "explanation": "test",
        "details": {"provider_model": "gpt-4o-mini", "model": "distilbert"},
        "indicators": [],
    }


class TestLocalSemanticService:
    def test_disabled_by_default_without_artifacts(self, tmp_path: Path):
        settings = Settings(
            database_url=f"sqlite:///{tmp_path / 'a.db'}",
            artifacts_dir=tmp_path / "empty_artifacts",
            local_llm_enabled=True,
        )
        service = LocalSemanticService(settings)
        assert service.available is False
        result = service.analyze("s", "b", None, [], [])
        assert result["status"] == "unavailable"
        assert result["details"]["sent_to_provider"] is False
        assert result["details"]["backend"] == "local_distilbert"

    def test_explicitly_disabled(self, settings: Settings):
        service = LocalSemanticService(settings)
        result = service.analyze("s", "b", None, [], [])
        assert "disabled" in result["explanation"].lower()

    def test_successful_local_inference_never_sends_to_provider(self, local_service: LocalSemanticService):
        result = local_service.analyze(
            "Verify your account",
            "Please confirm your password at http://example.xyz/login",
            "alerts@example.xyz",
            ["http://example.xyz/login"],
            [],
        )
        assert result["status"] == "ok"
        assert result["score"] == 90.0
        assert result["confidence"] == 0.9
        assert result["details"]["llm_used"] is True
        assert result["details"]["sent_to_provider"] is False
        assert result["details"]["backend"] == "local_distilbert"
        assert result["details"]["device"] == "cpu"
        assert result["details"]["probability_phishing"] == 0.9
        assert result["indicators"][0]["source"] == "local_llm"

    def test_status_reports_artifacts_without_loading(self, settings: Settings, tmp_path: Path):
        local_settings = settings.model_copy(
            update={"artifacts_dir": tmp_path / "artifacts", "local_llm_enabled": True}
        )
        local_settings.local_llm_dir.mkdir(parents=True, exist_ok=True)
        service = LocalSemanticService(local_settings)
        (local_settings.local_llm_dir / "config.json").write_text("{}")
        (local_settings.local_llm_dir / "tokenizer_config.json").write_text("{}")
        status = service.status()
        assert status["available"] is True
        assert status["enabled"] is True
        assert status["device"] is None  # not loaded yet


class TestSemanticRouter:
    def test_prefers_local_model(self, settings: Settings):
        local = _FakeService(True, _component())
        api = _FakeService(True, _component())
        router = SemanticRouter(settings, local=local, api=api)
        result = router.analyze("s", "b", None, [], [])
        assert result["backend"] == "local_distilbert"
        assert result["sent_to_provider"] is False
        assert result["component"] is local.result
        assert router.backend == "local_distilbert"

    def test_falls_back_to_api_when_local_unavailable(self, settings: Settings):
        local = _FakeService(False, _component("unavailable"))
        api = _FakeService(True, _component())
        router = SemanticRouter(settings, local=local, api=api)
        result = router.analyze("s", "b", None, [], [])
        assert result["backend"] == "api"
        assert result["sent_to_provider"] is True
        assert result["model"] == "gpt-4o-mini"

    def test_no_backend_when_nothing_configured(self, settings: Settings):
        local = _FakeService(False, _component("unavailable"))
        api = _FakeService(False, _component("unavailable"))
        router = SemanticRouter(settings, local=local, api=api)
        result = router.analyze("s", "b", None, [], [])
        assert result["used"] is False
        assert result["backend"] is None
        assert result["sent_to_provider"] is False

    def test_local_failure_falls_through_to_api(self, settings: Settings):
        local = _FakeService(True, _component("unavailable"))
        api = _FakeService(True, _component())
        router = SemanticRouter(settings, local=local, api=api)
        result = router.analyze("s", "b", None, [], [])
        assert result["backend"] == "api"
        assert result["sent_to_provider"] is True
