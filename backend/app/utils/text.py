"""Small text helpers shared across services."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit


def truncate(value: str, limit: int) -> str:
    value = re.sub(r"\s+", " ", value or "").strip()
    return value if len(value) <= limit else value[: limit - 1].rstrip() + "…"


def sha256_text(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8", errors="ignore")).hexdigest()


def redact_url(url: str, limit: int = 180) -> str:
    """Keep scheme, host and path; drop query/fragment and embedded userinfo."""
    try:
        candidate = url if "://" in url else "http://" + url
        parts = urlsplit(candidate)
        host = parts.hostname or ""
        if not host:
            return truncate(url, limit)
        display = f"{parts.scheme}://{host}{parts.path or ''}"
        return truncate(display, limit)
    except ValueError:
        return truncate(url, limit)
