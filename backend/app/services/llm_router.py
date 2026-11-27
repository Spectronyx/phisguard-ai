"""Local-first LLM router.

The private, locally fine-tuned DistilBERT classifier is preferred. The
external OpenAI-compatible service is used only when the local model is
unavailable *and* the API has been explicitly enabled with a key. Both paths
return the same component contract, so the risk engine and API output stay
unchanged.
"""

from __future__ import annotations

from typing import Any

from app.core.config import Settings
from app.services.local_llm_service import LocalSemanticService
from app.services.llm_service import SemanticService


class SemanticRouter:
    """Chooses between local and external semantic analysis."""

    def __init__(
        self,
        settings: Settings,
        local: LocalSemanticService | None = None,
        api: SemanticService | None = None,
    ) -> None:
        self.settings = settings
        self.local = local or LocalSemanticService(settings)
        self.api = api or SemanticService(settings)

    @property
    def backend(self) -> str | None:
        """The backend that would be used for the next analysis, if any."""
        if self.local.enabled:
            return "local_distilbert"
        if self.api.enabled:
            return "api"
        return None

    def analyze(
        self,
        subject: str,
        body: str,
        sender: str | None,
        urls: list[str],
        detected_indicators: list[dict],
    ) -> dict[str, Any]:
        """Analyse untrusted email text. Never raises to the pipeline."""
        common = {
            "subject": subject,
            "body": body,
            "sender": sender,
            "urls": urls,
            "detected_indicators": detected_indicators,
        }

        local_result: dict[str, Any] | None = None
        if self.local.enabled:
            local_result = self.local.analyze(**common)
            if local_result.get("status") == "ok":
                return self._wrap(local_result, backend="local_distilbert", sent_to_provider=False)

        if self.api.enabled:
            api_result = self.api.analyze(**common)
            if api_result.get("status") == "ok":
                return self._wrap(api_result, backend="api", sent_to_provider=True)

        if local_result is not None:
            return self._wrap(local_result, backend="local_distilbert", sent_to_provider=False)
        unavailable = self.api.analyze(**common)
        return self._wrap(unavailable, backend="api", sent_to_provider=False)

    @staticmethod
    def _wrap(
        component: dict[str, Any],
        backend: str,
        sent_to_provider: bool,
    ) -> dict[str, Any]:
        model: str | None = None
        if sent_to_provider:
            model = component.get("details", {}).get("provider_model")
        elif backend == "local_distilbert" and component.get("status") == "ok":
            model = component.get("details", {}).get("model")

        return {
            "component": component,
            "indicators": component.get("indicators", []),
            "used": component.get("status") == "ok",
            "backend": backend if component.get("status") == "ok" else None,
            "sent_to_provider": bool(sent_to_provider and component.get("status") == "ok"),
            "model": model,
        }


__all__ = ["SemanticRouter"]
