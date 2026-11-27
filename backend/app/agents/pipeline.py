"""Analysis pipeline orchestration.

Stages are independent agents. Each stage is wrapped so that a failure or
missing optional artifact degrades the result instead of crashing the request.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from app.agents.aggregation_agent import RiskAggregationAgent
from app.agents.domain_agent import DomainIntelAgent
from app.agents.email_agent import EmailAnalysisAgent
from app.agents.explanation_agent import ExplanationAgent
from app.agents.input_agent import InputAgent
from app.agents.response_agent import ResponseAgent
from app.agents.semantic_agent import SemanticAgent
from app.agents.url_agent import URLAnalysisAgent
from app.core.config import Settings
from app.ml.model_registry import ModelRegistry
from app.services.email_service import EmailAnalysisService
from app.services.graph_service import DomainGraphService
from app.services.llm_router import SemanticRouter
from app.services.risk_engine import RiskEngine
from app.services.url_service import URLAnalysisService
from app.utils.text import redact_url

logger = logging.getLogger(__name__)


class AnalysisUnavailable(RuntimeError):
    """Raised when no analysis component could produce a score."""


class AnalysisOrchestrator:
    def __init__(self, settings: Settings, registry: ModelRegistry | None = None) -> None:
        self.settings = settings
        self.registry = registry or ModelRegistry(settings)
        url_service = URLAnalysisService(self.registry)
        email_service = EmailAnalysisService(self.registry)
        graph_service = DomainGraphService(self.registry)
        semantic_service = SemanticRouter(settings)

        self.input_agent = InputAgent(
            max_email_chars=settings.max_email_chars,
            max_url_chars=settings.max_url_chars,
            max_urls=settings.max_urls_per_email,
        )
        self.url_agent = URLAnalysisAgent(url_service)
        self.email_agent = EmailAnalysisAgent(email_service, max_urls=settings.max_urls_per_email)
        self.domain_agent = DomainIntelAgent(graph_service)
        self.semantic_agent = SemanticAgent(semantic_service)
        self.risk_agent = RiskAggregationAgent(RiskEngine(settings))
        self.explanation_agent = ExplanationAgent()
        self.response_agent = ResponseAgent(settings)

    # ------------------------------------------------------------------
    def analyze_email(
        self,
        subject: str,
        body: str,
        sender: str | None = None,
        urls: list[str] | None = None,
    ) -> dict[str, Any]:
        started = time.perf_counter()
        prepared = self.input_agent.prepare_email(subject, body, sender, urls)
        errors: list[dict[str, str]] = []
        indicators: list[dict[str, Any]] = []

        url_payload = self._url_stage_many(prepared["urls"], errors)
        indicators.extend(url_payload["indicators"])

        try:
            email_result = self.email_agent.analyze(
                subject=prepared["subject"],
                body=prepared["body"],
                sender=prepared["sender"],
                provided_urls=prepared["urls"],
                url_indicators=url_payload["indicators"],
            )
            email_model = email_result["model_component"]
            email_rules = email_result["rules_component"]
            indicators.extend(email_result["indicators"])
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Email analysis stage failed")
            errors.append({"stage": "email_analysis", "error": type(exc).__name__})
            email_result = {"urls": prepared["urls"], "sender_domain": prepared["sender_domain"]}
            email_model = _error_component("email_model", "Email NLP classifier", "Email model stage failed.")
            email_rules = _error_component("email_rules", "Email social-engineering rules", "Email rules stage failed.")

        hosts = [r["domain"] for r in url_payload["results"] if r.get("domain")]
        if prepared["sender_domain"]:
            hosts.append(prepared["sender_domain"])
        graph_component = self._graph_stage(hosts, errors)
        indicators.extend(graph_component.get("indicators", []))

        semantic = self._semantic_stage(
            subject=prepared["subject"],
            body=prepared["body"],
            sender=prepared["sender"],
            urls=prepared["urls"],
            indicators=indicators,
            errors=errors,
        )
        indicators.extend(semantic["indicators"])

        components = [email_model, email_rules, url_payload["component_model"], url_payload["component_rules"], graph_component, semantic["component"]]
        aggregated = self.risk_agent.aggregate(components)
        if not aggregated["breakdown"]:
            raise AnalysisUnavailable("No analysis component produced a risk score.")

        llm_used = bool(semantic["used"])
        llm_backend = semantic.get("backend")
        llm_sent_to_provider = bool(semantic.get("sent_to_provider"))
        build = self.explanation_agent.build(
            scan_type="email",
            aggregated=aggregated,
            components=components,
            indicators=indicators,
            llm_used=llm_used,
            llm_model=semantic.get("model"),
            llm_backend=llm_backend,
            target_label="email message",
        )

        details = {
            "subject": prepared["subject"][:200],
            "sender_domain": prepared["sender_domain"],
            "extracted_urls": [redact_url(u) for u in prepared["urls"]],
            "url_count": len(prepared["urls"]),
            "body_characters_analyzed": len(prepared["body"]),
            "anchor_mismatches": email_result.get("anchor_mismatches", [])[:5],
            "stage_errors": errors,
            "notice": (
                "The full email body is not stored. Only this summary and derived indicators are persisted."
            ),
        }
        if llm_used:
            if llm_backend == "local_distilbert":
                details["llm_disclosure"] = (
                    "A locally fine-tuned DistilBERT classifier analysed the email text on this machine; "
                    "no content was sent to any external provider."
                )
            else:
                details["llm_disclosure"] = (
                    "Email content was sent to the configured external LLM provider because LLM analysis is enabled."
                )
        details["llm_backend"] = llm_backend

        duration_ms = int((time.perf_counter() - started) * 1000)
        return self.response_agent.assemble(
            scan_type="email",
            input_summary=prepared["input_summary"],
            input_hash=prepared["input_hash"],
            components=components,
            aggregated=aggregated,
            indicators=indicators,
            explanation=build["explanation"],
            recommendation=build["recommendation"],
            details=details,
            url_results=url_payload["summaries"],
            llm_used=llm_used,
            llm_sent_to_provider=llm_sent_to_provider,
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------
    def analyze_url(self, url: str) -> dict[str, Any]:
        started = time.perf_counter()
        prepared = self.input_agent.prepare_url(url)
        errors: list[dict[str, str]] = []

        try:
            url_payload = self.url_agent.analyze_one(prepared["url"])
            model_component = url_payload["component_model"]
            rules_component = url_payload["component_rules"]
            indicators = list(url_payload["indicators"])
            result = url_payload["result"]
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("URL analysis stage failed")
            errors.append({"stage": "url_analysis", "error": type(exc).__name__})
            model_component = _error_component("url_model", "URL ML classifier", "URL model stage failed.")
            rules_component = _error_component("url_rules", "URL rule engine", "URL rules stage failed.")
            indicators = []
            result = {"valid": False, "domain": "", "host": "", "features": {}, "risk_score": 0.0, "error": "stage failed"}

        graph_component = self._graph_stage([result.get("domain") or result.get("host") or ""], errors)
        indicators.extend(graph_component.get("indicators", []))

        components = [model_component, rules_component, graph_component]
        aggregated = self.risk_agent.aggregate(components)
        if not aggregated["breakdown"]:
            raise AnalysisUnavailable("No analysis component produced a risk score.")

        build = self.explanation_agent.build(
            scan_type="url",
            aggregated=aggregated,
            components=components,
            indicators=indicators,
            llm_used=False,
            target_label="URL",
        )

        details = {
            "url": redact_url(prepared["url"]),
            "raw_length": len(prepared["url"]),
            "host": result.get("host", ""),
            "registrable_domain": result.get("domain", ""),
            "valid": result.get("valid", False),
            "features": result.get("features", {}),
            "stage_errors": errors,
            "notice": "The submitted URL was parsed as text only; it was never fetched or opened.",
        }
        duration_ms = int((time.perf_counter() - started) * 1000)
        return self.response_agent.assemble(
            scan_type="url",
            input_summary=prepared["input_summary"],
            input_hash=prepared["input_hash"],
            components=components,
            aggregated=aggregated,
            indicators=indicators,
            explanation=build["explanation"],
            recommendation=build["recommendation"],
            details=details,
            llm_used=False,
            llm_sent_to_provider=False,
            duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------
    def _url_stage_many(self, urls: list[str], errors: list[dict[str, str]]) -> dict[str, Any]:
        try:
            return self.url_agent.analyze_many(urls)
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("URL stage failed")
            errors.append({"stage": "url_analysis", "error": type(exc).__name__})
            return {
                "component_model": _error_component("url_model", "URL ML classifier", "URL model stage failed."),
                "component_rules": _error_component("url_rules", "URL rule engine", "URL rules stage failed."),
                "indicators": [],
                "results": [],
                "summaries": [],
            }

    def _graph_stage(self, hosts: list[str], errors: list[dict[str, str]]) -> dict[str, Any]:
        hosts = [h for h in hosts if h]
        if not hosts:
            return {
                "name": "graph",
                "label": "Domain relationship graph",
                "status": "no_data",
                "score": None,
                "confidence": None,
                "explanation": "No domain was available for graph analysis.",
                "details": {},
                "indicators": [],
            }
        try:
            return self.domain_agent.analyze(hosts)
        except Exception as exc:
            logger.exception("Domain graph stage failed")
            errors.append({"stage": "domain_intel", "error": type(exc).__name__})
            return _error_component(
                "graph", "Domain relationship graph", "Domain graph stage failed."
            ) | {"indicators": []}

    def _semantic_stage(
        self,
        subject: str,
        body: str,
        sender: str | None,
        urls: list[str],
        indicators: list[dict[str, Any]],
        errors: list[dict[str, str]],
    ) -> dict[str, Any]:
        try:
            return self.semantic_agent.analyze(subject, body, sender, urls, indicators)
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Semantic stage failed")
            errors.append({"stage": "semantic", "error": type(exc).__name__})
            component = _error_component("llm", "LLM semantic analysis", "Semantic stage failed.")
            return {
                "component": component,
                "indicators": [],
                "used": False,
                "backend": None,
                "sent_to_provider": False,
                "model": None,
            }


def _error_component(name: str, label: str, explanation: str) -> dict[str, Any]:
    return {
        "name": name,
        "label": label,
        "status": "error",
        "score": None,
        "confidence": None,
        "explanation": explanation,
        "details": {},
    }
