"""Response assembly stage.

Converts pipeline outputs into the API response contract and decides which
component information is safe to persist. Full email bodies are never included.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.core.config import Settings
from app.utils.text import truncate

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class ResponseAgent:
    name = "response"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def assemble(
        self,
        scan_type: str,
        input_summary: str,
        input_hash: str,
        components: list[dict[str, Any]],
        aggregated: dict[str, Any],
        indicators: list[dict[str, Any]],
        explanation: str,
        recommendation: str,
        details: dict[str, Any],
        url_results: list[dict[str, Any]] | None = None,
        llm_used: bool = False,
        llm_sent_to_provider: bool = False,
        duration_ms: int | None = None,
    ) -> dict[str, Any]:
        components_out = self._merge_components(components, aggregated)
        merged_indicators = self._dedupe_indicators(indicators)

        details = dict(details)
        details["pipeline"] = {
            "duration_ms": duration_ms,
            "components_run": [c["name"] for c in components if c.get("status") == "ok"],
            "components_unavailable": [
                c["name"] for c in components if c.get("status") not in {"ok", "skipped"}
            ],
            "llm_used": llm_used,
            "llm_sent_to_provider": llm_sent_to_provider,
            "risk_weights": aggregated.get("weights_used", {}),
            "base_score": aggregated.get("base_score"),
            "corroboration_bonus": aggregated.get("corroboration_bonus"),
        }

        return {
            "scan_type": scan_type,
            "input_summary": truncate(input_summary, 180),
            "input_hash": input_hash,
            "classification": aggregated["classification"],
            "risk_level": aggregated["risk_level"],
            "risk_score": aggregated["risk_score"],
            "model_confidence": aggregated.get("model_confidence"),
            "indicators": merged_indicators,
            "components": components_out,
            "explanation": explanation,
            "recommendation": recommendation,
            "llm_used": llm_used,
            "llm_sent_to_provider": llm_sent_to_provider,
            "created_at": datetime.now(timezone.utc),
            "details": details,
            "url_results": url_results or [],
        }

    @staticmethod
    def _merge_components(
        components: list[dict[str, Any]], aggregated: dict[str, Any]
    ) -> list[dict[str, Any]]:
        by_name = {item["name"]: item for item in aggregated.get("breakdown", [])}
        output: list[dict[str, Any]] = []
        for component in components:
            name = component.get("name", "unknown")
            if name in by_name:
                merged = dict(by_name[name])
                merged["details"] = component.get("details", {})
            else:
                merged = {
                    "name": name,
                    "label": component.get("label", name),
                    "status": component.get("status", "unavailable"),
                    "score": component.get("score"),
                    "confidence": component.get("confidence"),
                    "weight": None,
                    "contribution": None,
                    "explanation": component.get("explanation", ""),
                    "details": component.get("details", {}),
                }
            output.append(merged)
        return output

    @staticmethod
    def _dedupe_indicators(indicators: list[dict[str, Any]]) -> list[dict[str, Any]]:
        unique: dict[str, dict[str, Any]] = {}
        for item in indicators:
            name = item.get("name", "Indicator")
            severity = item.get("severity", "low")
            existing = unique.get(name)
            if existing is None or _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(existing.get("severity", "low"), 0):
                unique[name] = {
                    "name": name,
                    "severity": severity,
                    "description": truncate(item.get("description", ""), 400),
                    "source": item.get("source", "rules"),
                }
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(unique.values(), key=lambda item: (order.get(item["severity"], 9), item["name"]))
