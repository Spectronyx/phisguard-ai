"""Domain graph analytics against the built artifact."""

from __future__ import annotations

import networkx as nx

from app.core.config import Settings
from app.ml.model_registry import ModelRegistry
from app.services.graph_service import DomainGraphService


class TestDomainGraph:
    def test_popular_domain_is_benign_context(self, settings: Settings):
        service = DomainGraphService(ModelRegistry(settings))
        result = service.analyze("github.com")
        assert result["status"] == "ok"
        assert result["score"] == 8.0
        assert result["details"]["popular_domain"] is True
        assert result["details"]["domain_malicious"] is False

    def test_known_malicious_host_from_corpus(self, settings: Settings):
        registry = ModelRegistry(settings)
        payload = registry.graph_payload()
        assert payload is not None
        graph: nx.Graph = payload["graph"]
        malicious_host = next(
            node for node, data in graph.nodes(data=True)
            if data.get("kind") == "hostname" and data.get("malicious")
        )
        result = DomainGraphService(registry).analyze(malicious_host)
        assert result["status"] == "ok"
        assert result["score"] >= 88.0
        assert any(item["name"] == "Host in malicious corpus" for item in result["indicators"])

    def test_unknown_domain_returns_no_data(self, settings: Settings):
        result = DomainGraphService(ModelRegistry(settings)).analyze(
            "definitely-not-in-the-local-corpus-8f2a.example"
        )
        assert result["status"] == "no_data"
        assert result["score"] is None

    def test_aggregate_takes_highest_risk_domain(self, settings: Settings):
        result = DomainGraphService(ModelRegistry(settings)).analyze_many(
            ["github.com", "definitely-not-in-the-local-corpus-8f2a.example"]
        )
        assert result["status"] == "ok"
        assert result["details"]["matched"] == 1

    def test_graph_metadata_is_honest(self, settings: Settings):
        payload = ModelRegistry(settings).graph_payload()
        assert payload is not None
        metadata = payload["metadata"]
        assert "not a Graph Neural Network" in metadata["method"] or "No WHOIS" in metadata["method"]
        assert any("Umbrella" in source for source in metadata["sources"])
        assert metadata["popular_domain_nodes"] > 0
