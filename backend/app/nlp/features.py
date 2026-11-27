"""Email text normalisation, URL extraction and deterministic NLP indicators."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlsplit

from app.ml.url_features import BRAND_DOMAINS, registrable_domain

_URL_REGEX = re.compile(
    r"""(?xi)
    \b(
        (?:https?|ftp)://[^\s<>"')]+        # explicit scheme
        |
        www\.[^\s<>"')]+                    # www prefixed
        |
        [a-z0-9][a-z0-9.-]*\.(?:com|net|org|io|co|in|info|biz|xyz|top|zip|click|link|live|online|site|shop|app|dev|me|us|uk|ru|cn|tk|ml|ga|cf|gq)
        (?:/[^\s<>"')]*)?                   # bare domain with plausible TLD
    )
    """,
    re.IGNORECASE,
)
_EMAIL_REGEX = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_ANCHOR_RE = re.compile(r"<a\b[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._skip = False

    def handle_starttag(self, tag: str, attrs) -> None:  # noqa: ANN001
        if tag in {"script", "style", "noscript"}:
            self._skip = True
        if tag in {"p", "br", "div", "tr", "li", "h1", "h2", "h3"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:  # noqa: ANN001
        if tag in {"script", "style", "noscript"}:
            self._skip = False

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def html_to_text(value: str) -> str:
    """Convert simple HTML email bodies to readable plain text."""
    if not value:
        return ""
    if "<" not in value:
        return value
    parser = _TextExtractor()
    try:
        parser.feed(value)
        text = "".join(parser.parts)
    except Exception:
        text = _TAG_RE.sub(" ", value)
    return html.unescape(text)


def normalize_text(subject: str, body: str) -> str:
    """Normalise an email for TF-IDF inference (links become a token)."""
    text = f"{subject}\n{html_to_text(body)}"
    text = html.unescape(text)
    text = re.sub(r"(?i)\b(?:https?|ftp)://\S+", " urltoken ", text)
    text = re.sub(r"\bwww\.\S+", " urltoken ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()[:60_000]


def extract_urls(text: str, provided: list[str] | None = None, limit: int = 5) -> list[str]:
    """Extract URL-like strings and normalise them; duplicates removed."""
    found: list[str] = []
    if provided:
        found.extend(provided)
    found.extend(match.group(1) for match in _URL_REGEX.finditer(html_to_text(text)))
    cleaned: list[str] = []
    seen: set[str] = set()
    for url in found:
        url = url.strip().rstrip(".,;:!?)]}>'\"")
        if not url:
            continue
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
            url = "http://" + url
        if len(url) > 2_048 or any(ch.isspace() for ch in url):
            continue
        key = url.lower()
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(url)
        if len(cleaned) >= limit:
            break
    return cleaned


def extract_sender_domain(sender: str | None) -> str | None:
    if not sender:
        return None
    match = _EMAIL_REGEX.search(sender)
    if not match:
        return None
    domain = match.group(0).split("@", 1)[1].lower().strip(".")
    return domain or None


def anchor_mismatches(body: str) -> list[dict]:
    """Anchor text that looks like a URL but points to a different host."""
    mismatches: list[dict] = []
    for href, anchor_html in _ANCHOR_RE.findall(body or ""):
        anchor = html.unescape(_TAG_RE.sub("", anchor_html)).strip()
        if not re.search(r"\b[a-z0-9-]+\.[a-z]{2,}\b", anchor, re.IGNORECASE):
            continue
        anchor_host_match = re.search(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", anchor, re.IGNORECASE)
        if not anchor_host_match:
            continue
        anchor_host = anchor_host_match.group(1).lower()
        try:
            href_host = (urlsplit(href if "://" in href else "http://" + href).hostname or "").lower()
        except ValueError:
            continue
        if not href_host:
            continue
        if registrable_domain(anchor_host) != registrable_domain(href_host):
            mismatches.append({"displayed": anchor_host, "actual": href_host})
    return mismatches[:5]


@dataclass
class EmailRuleResult:
    score: float
    indicators: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"score": round(self.score, 1), "indicators": self.indicators}


def _indicator(name: str, severity: str, description: str) -> dict:
    return {"name": name, "severity": severity, "description": description, "source": "email_rules"}


_URGENCY_RE = re.compile(
    r"(?i)\b(urgent|immediately|act now|right away|within \d+ (?:hours?|minutes?)|"
    r"final (?:warning|notice)|last chance|expires? (?:today|soon)|as soon as possible|"
    r"time[- ]sensitive|don't delay|do not delay)\b"
)
_THREAT_RE = re.compile(
    r"(?i)(?:(?:account|profile|access|service|subscription)[^.\n]{0,40}"
    r"(?:suspend|terminat|deactivat|lock|restrict|clos|disabl))|"
    r"(?:(?:legal action|permanently deleted|unauthori[sz]ed access|failure to comply))"
)
_CREDENTIAL_RE = re.compile(
    r"(?i)(?:(?:verify|confirm|validate|update|provide|enter|submit|send|re-?enter)[^.\n]{0,50}"
    r"(?:password|passcode|otp|one[-\s]?time|pin\b|cvv|credential|login|aadhaar|pan card|"
    r"account details|identity|billing details))|"
    r"(?:(?:password|otp|one[-\s]?time password|login credentials|cvv)[^.\n]{0,40}"
    r"(?:required|expired|verify|confirm|update|below|here))"
)
_FINANCIAL_RE = re.compile(
    r"(?i)\b(wire transfer|bank transfer|send (?:money|funds|payment)|gift cards?|"
    r"bitcoin|cryptocurrency|crypto wallet|invoice attached|payment required|"
    r"outstanding (?:balance|payment)|refund (?:is )?(?:pending|available)|"
    r"processing fee|claim your (?:refund|prize|reward))\b"
)
_PRIZE_RE = re.compile(
    r"(?i)\b(you (?:have|'ve) won|winner|lottery|jackpot|claim your (?:prize|reward)|"
    r"free gift|exclusive reward|selected as a winner)\b"
)
_GENERIC_GREETING_RE = re.compile(
    r"(?i)^\s*(dear (?:customer|user|client|member|sir/madam|valued customer)|"
    r"attention (?:customer|user)|hello (?:customer|user))\b"
)
_ATTACHMENT_RE = re.compile(
    r"(?i)(?:attach(?:ed|ment)|see the attached|open the (?:attached|document))"
)
_DANGEROUS_EXT_RE = re.compile(r"(?i)\.(exe|scr|js|vbs|jar|bat|cmd|ps1|hta|iso|img|lnk|zip|rar|7z|html?)\b")
_SECRECY_RE = re.compile(
    r"(?i)\b(confidential|do not (?:tell|share|disclose)|keep this (?:private|secret)|"
    r"between you and (?:me|us)|don't tell anyone)\b"
)
_ACCOUNT_DATA_RE = re.compile(
    r"(?i)\b(credit card|debit card|card number|social security|ssn|aadhaar number|"
    r"bank account|date of birth|mother'?s maiden name)\b"
)

FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
    "aol.com", "protonmail.com", "mail.com", "yandex.com", "gmx.com",
    "rediffmail.com", "zoho.com",
}

OFFICIAL_BRAND_DOMAINS = {registrable_domain(domain) for domain in BRAND_DOMAINS.values()}


def evaluate_email_rules(
    subject: str,
    body: str,
    sender: str | None = None,
    urls: list[str] | None = None,
    url_indicators: list[dict] | None = None,
    anchor_mismatch_list: list[dict] | None = None,
) -> EmailRuleResult:
    """Rule-based social-engineering detector (independent of the ML model)."""
    raw_body = body or ""
    text = html_to_text(raw_body)
    combined = f"{subject or ''}\n{text}"
    lower = combined.lower()
    sender_domain = extract_sender_domain(sender)
    urls = urls or []
    anchor_mismatch_list = anchor_mismatch_list or []
    indicators: list[dict] = []

    if _URGENCY_RE.search(combined):
        match = _URGENCY_RE.search(combined)
        indicators.append(_indicator(
            "Urgency pressure", "medium",
            f"The message uses time pressure ('{match.group(0)}') to discourage careful verification.",
        ))
    if _THREAT_RE.search(combined):
        match = _THREAT_RE.search(combined)
        indicators.append(_indicator(
            "Account threat", "high",
            f"The message threatens account consequences ('{match.group(0)}').",
        ))
    if _CREDENTIAL_RE.search(combined):
        match = _CREDENTIAL_RE.search(combined)
        indicators.append(_indicator(
            "Credential harvesting language", "critical",
            f"The message asks the recipient to provide or verify credentials ('{match.group(0)[:80]}').",
        ))
    if _FINANCIAL_RE.search(combined):
        match = _FINANCIAL_RE.search(combined)
        indicators.append(_indicator(
            "Unexpected financial request", "high",
            f"The message contains a financial request or lure ('{match.group(0)}').",
        ))
    if _PRIZE_RE.search(combined):
        indicators.append(_indicator(
            "Prize or reward lure", "medium",
            "The message promises a prize or reward, a common social-engineering lure.",
        ))
    if _GENERIC_GREETING_RE.search(text):
        indicators.append(_indicator(
            "Generic greeting", "low",
            "The message uses a generic greeting rather than the recipient's name.",
        ))
    if _ATTACHMENT_RE.search(combined):
        severity = "critical" if _DANGEROUS_EXT_RE.search(combined) else "medium"
        indicators.append(_indicator(
            "Unexpected attachment", severity,
            "The message refers to an attachment; executable or archive attachments are high risk.",
        ))
    if _SECRECY_RE.search(combined):
        indicators.append(_indicator(
            "Secrecy request", "medium",
            "The message asks the recipient to keep the request confidential or hidden.",
        ))
    if _ACCOUNT_DATA_RE.search(combined):
        indicators.append(_indicator(
            "Sensitive data request", "high",
            "The message references sensitive personal or financial data.",
        ))

    # Brand impersonation from message text + sender/link mismatch.
    if sender_domain:
        sender_reg = registrable_domain(sender_domain)
        for brand in BRAND_DOMAINS:
            if brand == "x" or len(brand) < 4 or brand not in lower:
                continue
            official = registrable_domain(BRAND_DOMAINS[brand])
            if sender_reg != official:
                indicators.append(_indicator(
                    "Sender brand mismatch", "critical",
                    f"The message mentions '{brand}' but was sent from '{sender_domain}', "
                    f"not the official domain '{official}'.",
                ))
                break
        if sender_reg in FREE_MAIL_DOMAINS and re.search(r"(?i)\b(official|support team|security team|bank|department)\b", lower):
            indicators.append(_indicator(
                "Free mail domain for official claim", "medium",
                "The sender uses a free webmail domain while claiming to represent an organisation.",
            ))

    if anchor_mismatch_list:
        first = anchor_mismatch_list[0]
        indicators.append(_indicator(
            "Deceptive link text", "critical",
            f"Link text displays '{first['displayed']}' but the actual destination is '{first['actual']}'.",
        ))

    if url_indicators:
        critical = [item for item in url_indicators if item.get("severity") in {"high", "critical"}]
        if critical:
            indicators.append(_indicator(
                "Suspicious embedded link", "high",
                f"The message contains {len(critical)} high-risk link indicator(s), e.g. "
                f"'{critical[0]['name']}'.",
            ))
        elif len(urls) > 0 and not any(i.get("name") == "Suspicious embedded link" for i in indicators):
            indicators.append(_indicator(
                "Embedded link", "low",
                f"The message contains {len(urls)} link(s); verify the destination independently.",
            ))

    # De-duplicate by indicator name while keeping the highest severity.
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    unique: dict[str, dict] = {}
    for item in indicators:
        existing = unique.get(item["name"])
        if existing is None or rank[item["severity"]] > rank[existing["severity"]]:
            unique[item["name"]] = item

    points = {"low": 4.0, "medium": 10.0, "high": 18.0, "critical": 30.0}
    score = min(100.0, sum(points[item["severity"]] for item in unique.values()))
    return EmailRuleResult(score=score, indicators=list(unique.values()))
