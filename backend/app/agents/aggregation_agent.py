"""Risk aggregation agent."""

from __future__ import annotations

from typing import Any

from app.services.risk_engine import RiskEngine


class RiskAggregationAgent:
    name = "risk_aggregation"

    def __init__(self, engine: RiskEngine) -> None:
        self.engine = engine

    def aggregate(self, components: list[dict[str, Any]]) -> dict[str, Any]:
        return self.engine.aggregate(components).to_dict()
