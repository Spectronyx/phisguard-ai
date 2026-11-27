"""Build the NetworkX domain relationship graph artifact.

The graph is derived from the URL corpus used for model training:
- hostname nodes and registrable-domain nodes (real domains from the corpora)
- ``subdomain_of`` edges
- ``brand_impersonation`` edges to brand nodes where a hostname contains a
  protected brand token but is not on the brand's official domain

This is graph analytics, not a Graph Neural Network.

Usage:
    python backend/scripts/build_graph.py
"""

from __future__ import annotations

import json
import pickle
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import networkx as nx
import pandas as pd

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.ml.popularity import load_popular_domains  # noqa: E402
from app.ml.url_features import BRAND_DOMAINS, registrable_domain  # noqa: E402

PROCESSED_DIR = BACKEND_DIR / "datasets" / "processed"
ARTIFACTS_DIR = BACKEND_DIR / "artifacts"
POPULARITY_PATH = BACKEND_DIR / "datasets" / "raw" / "top-1m.csv.zip"
POPULAR_LIMIT = 10_000


def has_brand_token(host: str, brand: str) -> bool:
    if brand == "x":
        return "x" in host.split(".")
    return brand in host.lower()


def build_graph(urls: pd.DataFrame, popular_domains: set[str] | None = None) -> nx.Graph:
    graph = nx.Graph()
    brand_nodes = set(BRAND_DOMAINS)

    for brand in brand_nodes:
        graph.add_node(brand, kind="brand", label=brand, malicious=False)

    for _, row in urls.iterrows():
        url = str(row["url"])
        malicious = bool(row["label"] == 1)
        host = ""
        try:
            from urllib.parse import urlsplit

            candidate = url if "://" in url else "http://" + url
            host = (urlsplit(candidate).hostname or "").lower().strip(".")
        except ValueError:
            continue
        if not host:
            continue
        reg = registrable_domain(host)

        existing = graph.nodes.get(host)
        if existing is None:
            graph.add_node(host, kind="hostname", malicious=malicious, source=str(row.get("source", "")))
        else:
            existing["malicious"] = bool(existing.get("malicious") or malicious)
        graph.nodes[host].setdefault("sources", set())
        graph.nodes[host]["sources"].add(str(row.get("source", "")))

        domain_data = graph.nodes.get(reg)
        if domain_data is None:
            graph.add_node(reg, kind="domain", malicious=malicious)
        else:
            domain_data["malicious"] = bool(domain_data.get("malicious") or malicious)

        if host != reg:
            graph.add_edge(host, reg, relation="subdomain_of")

        if host != reg or reg == host:
            for brand in brand_nodes:
                official = registrable_domain(BRAND_DOMAINS[brand])
                if reg == official:
                    continue
                if has_brand_token(host, brand):
                    graph.add_edge(host, brand, relation="brand_impersonation")

    # Add popular registrable domains as benign-context domain nodes. This is a
    # public popularity ranking, not a safety guarantee and not a live lookup.
    popular_added = 0
    for domain in sorted(popular_domains or set()):
        data = graph.nodes.get(domain)
        if data is None:
            graph.add_node(
                domain, kind="domain", malicious=False, source="umbrella_top",
                popular=True,
            )
            popular_added += 1
        else:
            data.setdefault("popular", True)
            data.setdefault("popularity_source", "umbrella_top")

    # Convert mutable sets to JSON-friendly lists.
    for _, data in graph.nodes(data=True):
        if "sources" in data:
            data["sources"] = sorted(data["sources"])
    return graph, popular_added


def main() -> int:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    urls = pd.read_csv(PROCESSED_DIR / "url_dataset.csv")
    popular_domains: set[str] = set()
    if POPULARITY_PATH.exists():
        popular_domains = load_popular_domains(POPULARITY_PATH, limit=POPULAR_LIMIT)
        print(f"Loaded {len(popular_domains)} popular registrable domains from Cisco Umbrella")
    print(f"Building graph from {len(urls)} URL records...")
    graph, popular_added = build_graph(urls, popular_domains)

    metadata = {
        "description": (
            "Local domain relationship graph built from the URL training corpus "
            "and the Cisco Umbrella popularity ranking"
        ),
        "built_at": datetime.now(timezone.utc).isoformat(),
        "nodes": graph.number_of_nodes(),
        "edges": graph.number_of_edges(),
        "hostname_nodes": sum(1 for _, d in graph.nodes(data=True) if d.get("kind") == "hostname"),
        "domain_nodes": sum(1 for _, d in graph.nodes(data=True) if d.get("kind") == "domain"),
        "brand_nodes": sum(1 for _, d in graph.nodes(data=True) if d.get("kind") == "brand"),
        "popular_domain_nodes": sum(1 for _, d in graph.nodes(data=True) if d.get("popular")),
        "popular_domains_added": popular_added,
        "malicious_hostnames": sum(
            1 for _, d in graph.nodes(data=True) if d.get("kind") == "hostname" and d.get("malicious")
        ),
        "sources": [
            "Phishing-Database/Phishing.Database (CC0-1.0)",
            "Malicious URLs Dataset, Kaggle (CC0 1.0)",
            f"Cisco Umbrella top-1M popularity ranking (top {POPULAR_LIMIT:,} domains, public ranking)",
        ],
        "method": (
            "Hostnames and registrable domains are nodes. Edges encode subdomain relationships and "
            "lexical brand-lookalike relationships. Malicious labels come from the URL corpus; "
            "popular domains are added as benign-context nodes from the public Umbrella ranking. "
            "No WHOIS, DNS, IP or live reputation lookups were performed."
        ),
    }
    payload = {"graph": graph, "metadata": metadata}
    target = ARTIFACTS_DIR / "domain_graph.pkl"
    with target.open("wb") as handle:
        pickle.dump(payload, handle, protocol=pickle.HIGHEST_PROTOCOL)
    (ARTIFACTS_DIR / "graph_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print(json.dumps(metadata, indent=2))
    print(f"Wrote {target} ({target.stat().st_size / 1e6:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
