"""URL analysis agent."""

from __future__ import annotations

from typing import Any

from app.services.url_service import URLAnalysisService


class URLAnalysisAgent:
    name = "url_analysis"

    def __init__(self, service: URLAnalysisService) -> None:
        self.service = service

    def analyze_one(self, url: str) -> dict[str, Any]:
        result = self.service.analyze(url)
        return {
            "component_model": result["model"],
            "component_rules": result["rules"],
            "indicators": [dict(item, source="url_rules") for item in result["indicators"]],
            "result": result,
            "status": "ok" if result["valid"] else "error",
            "error": result["error"],
        }

    def analyze_many(self, urls: list[str]) -> dict[str, Any]:
        if not urls:
            return {
                "component_model": _empty_component(
                    "url_model", "URL ML classifier", "No URLs were present in the email."
                ),
                "component_rules": _empty_component(
                    "url_rules", "URL rule engine", "No URLs were present in the email."
                ),
                "indicators": [],
                "results": [],
                "summaries": [],
                "status": "no_data",
            }
        payload = self.service.analyze_many(urls)
        return {
            "component_model": payload["model_component"],
            "component_rules": payload["rules_component"],
            "indicators": payload["indicators"],
            "results": payload["results"],
            "summaries": payload["summaries"],
            "status": "ok",
        }


def _empty_component(name: str, label: str, explanation: str) -> dict[str, Any]:
    return {
        "name": name,
        "label": label,
        "status": "skipped",
        "score": None,
        "confidence": None,
        "explanation": explanation,
        "details": {},
    }
