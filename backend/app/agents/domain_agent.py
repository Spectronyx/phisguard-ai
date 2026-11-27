"""Domain intelligence (graph) agent."""

from __future__ import annotations

from typing import Any

from app.services.graph_service import DomainGraphService


class DomainIntelAgent:
    name = "domain_intel"

    def __init__(self, service: DomainGraphService) -> None:
        self.service = service

    def analyze(self, hosts: list[str]) -> dict[str, Any]:
        return self.service.analyze_many(hosts)
