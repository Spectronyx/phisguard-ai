"""Popular-domain prior from Cisco Umbrella's public top-1M ranking.

This is a *popularity* signal, not a safety guarantee. It is used as one
feature (and as benign-context nodes in the domain graph), never as a
standalone whitelist.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

MULTI_SUFFIX = {
    ("co", "in"), ("co", "uk"), ("org", "uk"), ("ac", "uk"), ("gov", "uk"),
    ("com", "au"), ("com", "br"), ("co", "jp"), ("co", "za"), ("com", "sg"),
    ("co", "nz"), ("com", "mx"), ("com", "cn"),
}


def registrable(host: str) -> str:
    host = host.lower().strip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if len(labels) >= 3 and tuple(labels[-2:]) in MULTI_SUFFIX:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def load_popular_domains(path: Path, limit: int = 10_000) -> set[str]:
    domains: set[str] = set()
    with zipfile.ZipFile(path) as archive:
        with archive.open(archive.namelist()[0]) as handle:
            for raw_line in handle:
                parts = raw_line.decode("utf-8", errors="ignore").strip().split(",")
                if len(parts) != 2:
                    continue
                domain = parts[1].strip().lower()
                if not domain or "." not in domain:
                    continue
                reg = registrable(domain)
                domains.add(reg)
                if len(domains) >= limit:
                    break
    return domains
