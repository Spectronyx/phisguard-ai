"""Lexical URL feature extraction and deterministic URL threat rules.

Security note: URLs are parsed as text only. Nothing in this module (or any
caller) performs DNS resolution or HTTP requests against submitted URLs.
"""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

SUSPICIOUS_TLDS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "work", "click", "link", "top",
    "xyz", "buzz", "rest", "cam", "sbs", "icu", "live", "fit", "mom", "monster",
    "quest", "cfd", "lol", "autos", "bond", "gdn", "best", "cyou", "support",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly", "s.id",
}

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "verify", "verification", "account", "update",
    "secure", "security", "banking", "confirm", "password", "credential",
    "recover", "unlock", "suspend", "suspended", "alert", "billing", "invoice",
    "payment", "wallet", "seed", "otp", "gift", "prize", "bonus", "free",
    "urgent", "webscr", "authenticate", "authorize", "reset", "token",
}

# Brands that are frequently impersonated. The map points at the brand's
# official registrable domain, used only for lexical comparison.
BRAND_DOMAINS: dict[str, str] = {
    "paypal": "paypal.com",
    "apple": "apple.com",
    "icloud": "icloud.com",
    "microsoft": "microsoft.com",
    "outlook": "outlook.com",
    "office365": "office.com",
    "google": "google.com",
    "gmail": "gmail.com",
    "amazon": "amazon.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "linkedin": "linkedin.com",
    "dropbox": "dropbox.com",
    "docusign": "docusign.com",
    "adobe": "adobe.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "hsbc": "hsbc.com",
    "icici": "icicibank.com",
    "hdfc": "hdfcbank.com",
    "sbi": "sbi.co.in",
    "axisbank": "axisbank.com",
    "flipkart": "flipkart.com",
    "steam": "steampowered.com",
    "spotify": "spotify.com",
    "github": "github.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
    "metamask": "metamask.io",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "ups": "ups.com",
    "usps": "usps.com",
    "irs": "irs.gov",
    "zoom": "zoom.us",
    "telegram": "telegram.org",
    "twitter": "twitter.com",
    "x": "x.com",
    "sbiyono": "onlinesbi.sbi",
    "aadhaar": "uidai.gov.in",
    "epfo": "epfindia.gov.in",
    "incometax": "incometax.gov.in",
}

FEATURE_NAMES: list[str] = [
    "url_length",
    "hostname_length",
    "path_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "num_special_chars",
    "subdomain_count",
    "has_ip",
    "has_at_symbol",
    "has_nonstandard_port",
    "uses_https",
    "has_punycode",
    "percent_encoding_count",
    "query_param_count",
    "suspicious_tld",
    "suspicious_keyword_count",
    "brand_impersonation",
    "path_depth",
    "has_embedded_protocol",
    "host_entropy",
    "host_digit_ratio",
    "host_hyphen_count",
    "uses_shortener",
]

# The ML model is deliberately restricted to host-centric features.
# Public benign URL corpora are dominated by homepages while phishing URLs
# often contain paths; training on path features creates a dataset artefact
# (a legitimate deep link such as github.com/microsoft/vscode would be scored
# as highly malicious). Path/query signals are still evaluated by the
# deterministic URL rule engine and shown in the feature summary.
MODEL_FEATURE_NAMES: list[str] = [
    "hostname_length",
    "domain_length",
    "host_label_count",
    "subdomain_count",
    "host_dots",
    "host_hyphens",
    "host_digits",
    "host_special_chars",
    "host_entropy",
    "host_digit_ratio",
    "host_hyphen_count",
    "tld_length",
    "suspicious_tld",
    "has_ip",
    "has_userinfo",
    "has_nonstandard_port",
    "has_punycode",
    "host_percent_encoding",
    "host_suspicious_keyword_count",
    "brand_impersonation",
    "uses_shortener",
    "single_char_labels",
    "numeric_labels",
    "path_suspicious_keyword_count",
    "path_percent_encoding",
    "path_suspicious_extension",
    "path_digit_ratio",
    "path_special_chars",
    "path_embedded_url",
    "path_brand_action",
    "query_param_count",
    "is_popular_domain",
]

_PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain using a compact multi-label suffix list.

    This is deliberately small and dependency-free; it is not a Public Suffix
    List implementation, and that limitation is documented.
    """
    host = host.lower().strip(".")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    multi_suffix = {
        ("co", "in"), ("co", "uk"), ("org", "uk"), ("ac", "uk"), ("gov", "uk"),
        ("com", "au"), ("com", "br"), ("co", "jp"), ("co", "za"), ("com", "sg"),
        ("co", "nz"), ("com", "mx"), ("co", "kr"), ("com", "cn"),
    }
    if len(labels) >= 3 and tuple(labels[-2:]) in multi_suffix:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


@dataclass
class ParsedUrl:
    raw: str
    normalized: str
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    fragment: str
    username: str | None
    password: str | None
    is_valid: bool
    error: str | None = None
    scheme_provided: bool = False


def normalize_url(raw: str) -> ParsedUrl:
    """Parse a URL without any network access, adding a scheme when missing."""
    raw = (raw or "").strip()
    scheme_provided = bool(_SCHEME_RE.match(raw))
    candidate = raw
    if candidate and not scheme_provided:
        candidate = "http://" + candidate

    try:
        parts = urlsplit(candidate)
    except ValueError as exc:  # malformed IPv6 brackets etc.
        return ParsedUrl(raw, raw, "", "", None, "", "", "", None, None, False, f"Malformed URL: {exc}")

    try:
        host = parts.hostname or ""
    except ValueError as exc:
        return ParsedUrl(raw, raw, parts.scheme, "", None, "", "", "", None, None, False, f"Invalid host: {exc}")

    scheme = parts.scheme.lower() or "http"
    host = host.lower().strip(".")
    try:
        port = parts.port
    except ValueError:
        port = -1  # signal an invalid port without crashing

    if host.startswith("www."):
        host = host[4:]

    if not host:
        return ParsedUrl(raw, raw, scheme, "", None, "", "", "", None, None, False, "URL has no hostname")
    if not _HOSTNAME_RE.match(host) and not _is_ip(host):
        return ParsedUrl(
            raw, raw, scheme, host, port, "", "", "", None, None, False,
            "Hostname contains invalid characters (internationalised hosts must be punycode-encoded)",
        )
    if port == -1:
        return ParsedUrl(raw, raw, scheme, host, None, "", "", "", None, None, False, "Invalid port number")

    normalized = f"{scheme}://{host}"
    if port and port not in (80, 443):
        normalized += f":{port}"
    path = parts.path or "/"
    normalized += path
    if parts.query:
        normalized += "?" + parts.query
    if parts.fragment:
        normalized += "#" + parts.fragment

    return ParsedUrl(
        raw=raw,
        normalized=normalized,
        scheme=scheme,
        host=host,
        port=port,
        path=parts.path or "/",
        query=parts.query,
        fragment=parts.fragment,
        username=parts.username,
        password=parts.password,
        is_valid=True,
        scheme_provided=scheme_provided,
    )


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def count_subdomains(host: str) -> int:
    if _is_ip(host):
        return 0
    domain = registrable_domain(host)
    host_labels = host.split(".")
    domain_labels = domain.split(".")
    return max(0, len(host_labels) - len(domain_labels))


def brand_impersonation(host: str) -> tuple[bool, str | None]:
    """Return whether a brand token appears in a hostname outside its official domain."""
    domain = registrable_domain(host)
    haystack = host.lower()
    domain_labels = set(domain.split("."))
    for brand, official in BRAND_DOMAINS.items():
        official_domain = registrable_domain(official)
        if domain == official_domain:
            continue
        # Avoid matching "x" inside arbitrary words.
        if brand == "x":
            if any(label == "x" for label in host.split(".")):
                return True, brand
            continue
        if len(brand) < 4:
            token_match = re.search(rf"(^|[^a-z]){re.escape(brand)}([^a-z]|$)", haystack)
        else:
            token_match = re.search(re.escape(brand), haystack)
        if token_match and brand not in domain_labels:
            return True, brand
    return False, None


def extract_features(url: str, popular_domains: set[str] | None = None) -> tuple[dict[str, float], ParsedUrl]:
    """Extract URL features. Values are numeric for scikit-learn.

    ``popular_domains`` (optional) enables the popularity-prior feature; it is
    a ranking signal, not a safety guarantee.
    """
    parsed = normalize_url(url)
    if not parsed.is_valid:
        return {name: 0.0 for name in (*FEATURE_NAMES, *MODEL_FEATURE_NAMES)}, parsed

    host = parsed.host
    full = parsed.normalized
    path = parsed.path
    query = parse_qs_count(parsed.query)
    quad = unquote(full)
    brand_flag, _brand = brand_impersonation(host)
    host_labels = host.split(".")
    tld = host.rsplit(".", 1)[-1]
    domain = registrable_domain(host)
    host_userinfo = bool(parsed.username or parsed.password)
    raw_host_part = parsed.raw.split("://", 1)[-1].split("/", 1)[0]
    if "@" in raw_host_part:
        host_userinfo = True

    features: dict[str, float] = {
        "url_length": float(len(full)),
        "hostname_length": float(len(host)),
        "path_length": float(len(path)),
        "num_dots": float(full.count(".")),
        "num_hyphens": float(full.count("-")),
        "num_digits": float(sum(ch.isdigit() for ch in full)),
        "num_special_chars": float(sum(not ch.isalnum() and ch not in ":/.-_?&=%" for ch in quad)),
        "subdomain_count": float(count_subdomains(host)),
        "has_ip": float(_is_ip(host)),
        "has_at_symbol": float("@" in parsed.raw),
        "has_nonstandard_port": float(bool(parsed.port and parsed.port not in (80, 443))),
        "uses_https": float(parsed.scheme == "https"),
        "has_punycode": float("xn--" in host),
        "percent_encoding_count": float(len(_PERCENT_RE.findall(parsed.raw))),
        "query_param_count": float(query),
        "suspicious_tld": float(tld in SUSPICIOUS_TLDS),
        "suspicious_keyword_count": float(
            sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in f"{host}{path}{parsed.query}".lower())
        ),
        "brand_impersonation": float(brand_flag),
        "path_depth": float(len([p for p in path.split("/") if p])),
        "has_embedded_protocol": float(path.count("http://") + path.count("https://") + path.startswith("//")),
        "host_entropy": float(_entropy(host)),
        "host_digit_ratio": float(sum(ch.isdigit() for ch in host) / max(1, len(host))),
        "host_hyphen_count": float(host.count("-")),
        "uses_shortener": float(registrable_domain(host) in SHORTENER_DOMAINS),
        # Host-centric model features (see MODEL_FEATURE_NAMES).
        "domain_length": float(len(domain)),
        "host_label_count": float(len(host_labels)),
        "host_dots": float(host.count(".")),
        "host_hyphens": float(host.count("-")),
        "host_digits": float(sum(ch.isdigit() for ch in host)),
        "host_special_chars": float(sum(not ch.isalnum() and ch not in ".-" for ch in host)),
        "tld_length": float(len(tld)),
        "has_userinfo": float(host_userinfo),
        "host_percent_encoding": float(len(_PERCENT_RE.findall(host))),
        "host_suspicious_keyword_count": float(
            sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in host)
        ),
        "single_char_labels": float(sum(1 for label in host_labels if len(label) == 1)),
        "numeric_labels": float(sum(1 for label in host_labels if label.isdigit())),
        "path_suspicious_keyword_count": float(
            sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in f"{path}{parsed.query}".lower())
        ),
        "path_percent_encoding": float(len(_PERCENT_RE.findall(path))),
        "path_suspicious_extension": float(
            bool(re.search(r"(?i)\.(exe|scr|apk|zip|rar|js|vbs|hta|iso|img)(?:$|[?/#])", path))
        ),
        "path_digit_ratio": float(sum(ch.isdigit() for ch in path) / max(1, len(path))),
        "path_special_chars": float(sum(not ch.isalnum() and ch not in "/-_." for ch in path)),
        "path_embedded_url": float("http://" in path.lower() or "https://" in path.lower()),
        "path_brand_action": float(
            any(brand in path.lower() for brand in BRAND_DOMAINS)
            and any(action in path.lower() for action in ("login", "verify", "account", "password", "update", "secure", "signin"))
        ),
        "is_popular_domain": float(bool(popular_domains and registrable_domain(host) in popular_domains)),
    }
    return features, parsed


def parse_qs_count(query: str) -> int:
    if not query:
        return 0
    return len([part for part in query.split("&") if part])


@dataclass
class UrlRuleResult:
    score: float
    indicators: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"score": round(self.score, 1), "indicators": self.indicators}


def _indicator(name: str, severity: str, description: str) -> dict:
    return {"name": name, "severity": severity, "description": description, "source": "url_rules"}


def evaluate_url_rules(url: str) -> UrlRuleResult:
    """Deterministic URL checks. This is independent of the ML model."""
    parsed = normalize_url(url)
    if not parsed.is_valid:
        return UrlRuleResult(
            score=50.0,
            indicators=[_indicator("Malformed URL", "high", parsed.error or "The URL could not be parsed safely.")],
        )

    features, _ = extract_features(url)
    host = parsed.host
    path = parsed.path
    lower_full = parsed.normalized.lower()
    indicators: list[dict] = []

    if "@" in parsed.raw:
        indicators.append(_indicator(
            "Embedded credentials", "critical",
            "The URL contains an '@' symbol, which can hide the real destination host.",
        ))
    if features["has_ip"]:
        indicators.append(_indicator(
            "IP address host", "high",
            "The link uses a raw IP address instead of a domain name, a common phishing tactic.",
        ))
    if parsed.password or parsed.username:
        indicators.append(_indicator(
            "Userinfo in URL", "high",
            "Credentials or user information appear before the host, obscuring the destination.",
        ))
    if features["brand_impersonation"]:
        flag, brand = brand_impersonation(host)
        indicators.append(_indicator(
            "Brand impersonation", "critical",
            f"The URL mentions the brand '{brand}' but is not hosted on its official domain.",
        ))
    if features["has_punycode"]:
        indicators.append(_indicator(
            "Punycode host", "medium",
            "The hostname is internationalised (xn--), which can enable homograph attacks.",
        ))
    if features["percent_encoding_count"] >= 2:
        indicators.append(_indicator(
            "Encoded characters", "high",
            "Multiple percent-encoded sequences may be used to obfuscate the destination.",
        ))
    if features["suspicious_tld"]:
        tld = host.rsplit(".", 1)[-1]
        indicators.append(_indicator(
            "High-abuse TLD", "medium",
            f"The '.{tld}' TLD is disproportionately used in phishing campaigns (weak signal on its own).",
        ))
    if features["has_nonstandard_port"]:
        indicators.append(_indicator(
            "Non-standard port", "medium",
            f"The URL uses port {parsed.port}, which is unusual for normal web traffic.",
        ))
    if features["has_embedded_protocol"]:
        indicators.append(_indicator(
            "Embedded URL", "high",
            "A second protocol or protocol-relative path appears inside the URL path.",
        ))
    if len(parsed.normalized) > 120:
        indicators.append(_indicator(
            "Very long URL", "medium",
            f"The URL is {len(parsed.normalized)} characters long; excessive length can hide the true domain.",
        ))
    elif len(parsed.normalized) > 75:
        indicators.append(_indicator(
            "Long URL", "low",
            f"The URL is {len(parsed.normalized)} characters long.",
        ))
    if features["subdomain_count"] >= 4:
        indicators.append(_indicator(
            "Deep subdomain chain", "medium",
            f"The host has {int(features['subdomain_count'])} subdomain levels, often used to imitate trusted hosts.",
        ))
    if features["suspicious_keyword_count"] >= 2:
        indicators.append(_indicator(
            "Credential-related keywords", "medium",
            "The URL contains multiple words associated with login, verification or payment flows.",
        ))
    if features["uses_shortener"]:
        indicators.append(_indicator(
            "URL shortener", "medium",
            "Link shorteners hide the final destination and are frequently used in phishing.",
        ))
    if parsed.scheme_provided and not features["uses_https"]:
        indicators.append(_indicator(
            "No HTTPS", "low",
            "The URL explicitly uses HTTP rather than HTTPS. This is weak evidence: many legitimate sites also lack it.",
        ))
    if features["host_digit_ratio"] > 0.15:
        indicators.append(_indicator(
            "Digit-heavy hostname", "medium",
            "The hostname contains an unusually high proportion of digits.",
        ))
    if features["host_hyphen_count"] >= 2:
        indicators.append(_indicator(
            "Hyphenated hostname", "low",
            "Multiple hyphens in the hostname are common in lookalike domains.",
        ))
    if features["host_entropy"] > 4.2 and len(host) > 20:
        indicators.append(_indicator(
            "High hostname randomness", "medium",
            "The hostname has high character entropy, suggesting an algorithmically generated name.",
        ))
    if f"{host}{path}".lower().count(".") >= 4:
        indicators.append(_indicator(
            "Many dots", "low",
            "The URL contains an unusually large number of dots, which can obscure the registrable domain.",
        ))

    points = {"low": 4.0, "medium": 10.0, "high": 18.0, "critical": 28.0}
    score = min(100.0, sum(points.get(item["severity"], 0.0) for item in indicators))
    return UrlRuleResult(score=score, indicators=indicators)
