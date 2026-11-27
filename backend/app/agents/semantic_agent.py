"""Optional semantic analysis agent."""

from __future__ import annotations

from typing import Any


class SemanticAgent:
    name = "semantic"

    def __init__(self, service) -> None:  # noqa: ANN001 - router or service with analyze()
        self.service = service

    def analyze(
        self,
        subject: str,
        body: str,
        sender: str | None,
        urls: list[str],
        detected_indicators: list[dict],
    ) -> dict[str, Any]:
        result = self.service.analyze(
            subject=subject,
            body=body,
            sender=sender,
            urls=urls,
            detected_indicators=detected_indicators,
        )
        # A SemanticRouter returns the full envelope; older services return a
        # bare component. Support both so existing API-only tests still pass.
        if "component" in result:
            return {
                "component": result["component"],
                "indicators": result.get("indicators", []),
                "used": bool(result.get("used")),
                "backend": result.get("backend"),
                "sent_to_provider": bool(result.get("sent_to_provider")),
                "model": result.get("model"),
            }
        return {
            "component": result,
            "indicators": result.get("indicators", []),
            "used": result.get("status") == "ok",
            "backend": "api",
            "sent_to_provider": result.get("status") == "ok",
            "model": None,
        }
