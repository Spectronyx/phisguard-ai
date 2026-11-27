"""Domain relationship graph analytics.

The graph is built offline from the real URL corpora (Phishing.Database and
Cisco Umbrella rankings) plus lexical brand relationships. It is a NetworkX
graph-analytics module — **not** a Graph Neural Network.
"""

from __future__ import annotations

from typing import Any

import networkx as nx

from app.ml.model_registry import ModelRegistry
from app.ml.url_features import brand_impersonation, registrable_domain


class DomainGraphService:
    def __init__(self, registry: ModelRegistry) -> None:
        self.registry = registry
        self._cached_graph: nx.Graph | None = None
        self._cached_meta: dict[str, Any] = {}

    def _load(self) -> tuple[nx.Graph | None, dict[str, Any]]:
        payload = self.registry.graph_payload()
        if not payload or "graph" not in payload:
            return None, {}
        if self._cached_graph is not payload.get("graph"):
            self._cached_graph = payload["graph"]
            self._cached_meta = payload.get("metadata", {})
        return self._cached_graph, self._cached_meta

    def analyze(self, host: str) -> dict[str, Any]:
        graph, meta = self._load()
        empty = {
            "name": "graph",
            "label": "Domain relationship graph",
            "status": "no_data",
            "score": None,
            "confidence": None,
            "explanation": "Domain graph artifact is not available; no graph risk was added.",
            "details": {},
        }
        if graph is None or not host:
            return empty

        host = host.lower().strip(".")
        domain = registrable_domain(host)
        details: dict[str, Any] = {
            "queried_host": host,
            "registrable_domain": domain,
            "corpus": meta.get("description", "local domain corpus"),
            "graph_nodes": graph.number_of_nodes(),
            "graph_edges": graph.number_of_edges(),
        }

        host_data = graph.nodes.get(host, {})
        domain_data = graph.nodes.get(domain, {})
        if not host_data and not domain_data:
            empty["explanation"] = (
                "The host and its registrable domain are not present in the local domain corpus, "
                "so graph analysis produced no risk signal (this does not mean the domain is safe)."
            )
            return empty

        indicators: list[dict] = []
        host_malicious = bool(host_data.get("malicious"))
        domain_malicious = bool(domain_data.get("malicious"))
        degree = graph.degree(host) if host_data else 0
        domain_degree = graph.degree(domain) if domain_data else 0

        # Neighbours in the corpus that are known malicious hostnames.
        neighbour_hosts = {
            n for n in graph.neighbors(host) if graph.nodes[n].get("kind") == "hostname"
        } if host_data else set()
        malicious_neighbours = [
            n for n in neighbour_hosts if graph.nodes[n].get("malicious")
        ]
        brand_edges = []
        if host_data:
            brand_edges = [
                n for n in graph.neighbors(host) if graph.nodes[n].get("kind") == "brand"
            ]
        domain_malicious_hosts = 0
        if domain_data:
            domain_malicious_hosts = sum(
                1
                for n in graph.neighbors(domain)
                if graph.nodes[n].get("kind") == "hostname" and graph.nodes[n].get("malicious")
            )

        component_size = 0
        component_ratio = 0.0
        if host_data:
            component = nx.node_connected_component(graph, host)
            host_nodes = [n for n in component if graph.nodes[n].get("kind") == "hostname"]
            component_size = len(component)
            if host_nodes:
                component_ratio = sum(
                    1 for n in host_nodes if graph.nodes[n].get("malicious")
                ) / len(host_nodes)

        if host_malicious:
            indicators.append(_indicator(
                "Host in malicious corpus", "critical",
                "The exact hostname appears in the local malicious-URL corpus.",
            ))
        if domain_malicious:
            indicators.append(_indicator(
                "Domain in malicious corpus", "high",
                f"The registrable domain '{domain}' appears in the local malicious-URL corpus.",
            ))
        if domain_malicious_hosts >= 3:
            indicators.append(_indicator(
                "Multiple malicious subdomains", "high",
                f"{domain_malicious_hosts} malicious hostnames share the registrable domain '{domain}'.",
            ))
        if malicious_neighbours:
            indicators.append(_indicator(
                "Suspicious graph neighbours", "high",
                f"{len(malicious_neighbours)} directly connected host(s) are known malicious.",
            ))
        if brand_edges:
            indicators.append(_indicator(
                "Brand-lookalike domain", "medium",
                "The domain is lexically linked to a brand it does not officially belong to.",
            ))
        if component_ratio >= 0.8 and component_size >= 5:
            indicators.append(_indicator(
                "Dense malicious component", "medium",
                f"{component_ratio * 100:.0f}% of hosts in this graph component are malicious.",
            ))

        # Score is derived only from observed graph evidence.
        if host_malicious:
            score = 95.0
            rationale = "The exact hostname is already known to be malicious in the local corpus."
        elif domain_malicious:
            score = 88.0
            rationale = "The registrable domain is listed as malicious in the local corpus."
        elif malicious_neighbours:
            score = min(85.0, 55.0 + 6.0 * len(malicious_neighbours) + (10.0 if brand_edges else 0.0))
            rationale = "The host is linked to known-malicious infrastructure in the graph."
        elif brand_edges:
            score = 45.0
            rationale = "A brand-lookalike relationship exists, but the host is not confirmed malicious."
        elif domain_malicious_hosts:
            score = 50.0
            rationale = "Malicious hostnames share this registrable domain, though this host is unknown."
        else:
            score = 8.0
            rationale = (
                "The domain is a known popular domain in the local corpus with no threat association; "
                "this is weak positive evidence, not a guarantee of safety."
            )

        details.update({
            "host_known": bool(host_data),
            "domain_known": bool(domain_data),
            "popular_domain": bool(host_data.get("popular") or domain_data.get("popular")),
            "host_malicious": host_malicious,
            "domain_malicious": domain_malicious,
            "degree": degree,
            "domain_degree": domain_degree,
            "malicious_neighbours": malicious_neighbours[:10],
            "brand_neighbours": brand_edges[:10],
            "malicious_subdomains": domain_malicious_hosts,
            "component_size": component_size,
            "component_malicious_ratio": round(component_ratio, 4),
            "graph_nodes": graph.number_of_nodes(),
            "graph_edges": graph.number_of_edges(),
        })

        return {
            "name": "graph",
            "label": "Domain relationship graph",
            "status": "ok",
            "score": round(score, 1),
            "confidence": None,
            "explanation": rationale,
            "details": details,
            "indicators": indicators,
        }

    def analyze_many(self, hosts: list[str]) -> dict[str, Any]:
        """Aggregate graph evidence across all domains in an email scan."""
        unique_hosts = sorted({h.lower() for h in hosts if h})
        results = [self.analyze(host) for host in unique_hosts]
        ok_results = [r for r in results if r["status"] == "ok"]
        indicators = [
            dict(item, source="graph")
            for result in ok_results
            for item in result.get("indicators", [])
        ]
        if not ok_results:
            return {
                "name": "graph",
                "label": "Domain relationship graph",
                "status": "no_data",
                "score": None,
                "confidence": None,
                "explanation": (
                    "None of the domains in this scan appear in the local domain corpus; "
                    "no graph risk was added (absence of data is not evidence of safety)."
                ),
                "details": {"domains": unique_hosts, "matched": 0},
            }

        worst = max(ok_results, key=lambda r: r["score"] or 0.0)
        return {
            "name": "graph",
            "label": "Domain relationship graph",
            "status": "ok",
            "score": worst["score"],
            "confidence": None,
            "explanation": worst["explanation"],
            "details": {
                "domains": unique_hosts,
                "matched": len(ok_results),
                "per_domain": [
                    {
                        "domain": r["details"].get("queried_host"),
                        "score": r["score"],
                        "status": r["status"],
                    }
                    for r in results
                ],
            },
            "indicators": indicators,
        }


def _indicator(name: str, severity: str, description: str) -> dict:
    return {"name": name, "severity": severity, "description": description, "source": "graph"}
