"""Rule-based phishing risk scoring for inbound email.

Consumes normalized email metadata (sender, links, subject/body where
already permitted — see docs/PRIVACY_AND_CONSENT.md) and produces a 1-10
risk score with a human-readable rationale. This is the first-pass filter;
only flagged messages get escalated to app/detection/claude_analyzer.py for
a narrative. Pure/deterministic, no network calls — external lookups
(domain reputation, WHOIS age, etc.) belong in url_reputation.py instead.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


# Permissive charset check (covers domains, IPv4, and bracket-free IPv6) —
# just enough to reject garbage strings that urlparse doesn't error on.
_VALID_HOSTNAME_RE = re.compile(r"^[a-z0-9.\-:]+$")

FLAG_THRESHOLD = 5
MAX_SCORE = 10

_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}

_SUSPICIOUS_TLDS = {
    "zip", "top", "xyz", "country", "gq", "tk", "work", "click", "link",
    "review", "rest", "loan", "win", "bid", "stream", "download",
    "racing", "party", "science",
}

_FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "icloud.com", "mail.com", "protonmail.com",
}

# Brand -> its real domain. Used to catch domains that reference a brand
# name without actually being (or being a subdomain of) that brand.
_BRAND_LEGIT_DOMAINS = {
    "paypal": "paypal.com",
    "chase": "chase.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "citibank": "citibank.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "netflix": "netflix.com",
    "irs": "irs.gov",
    "socialsecurity": "ssa.gov",
    "usps": "usps.com",
    "fedex": "fedex.com",
    "ups": "ups.com",
    "americanexpress": "americanexpress.com",
    "capitalone": "capitalone.com",
    "discover": "discover.com",
    "venmo": "venmo.com",
    "zelle": "zellepay.com",
}

_URGENCY_PHRASES = (
    "verify your account", "account suspended", "unusual activity",
    "click here immediately", "confirm your identity",
    "account will be closed", "urgent action required",
    "password has expired", "password expired", "update your payment",
    "you have won", "claim your prize", "act now", "limited time offer",
    "wire transfer", "gift card", "confirm your password",
    "reactivate your account", "security alert",
)

_GENERIC_GREETINGS = (
    "dear customer", "dear user", "dear account holder", "dear valued customer",
)

_SENSITIVE_INFO_REQUESTS = (
    "social security number", "ssn", "credit card number", "routing number",
    "full account number", "one-time password", "otp", "verification code",
)


@dataclass
class RiskAssessment:
    """Result of scoring a single message."""

    score: int  # 1 (benign) - 10 (severe), always paired with a rationale
    flagged: bool
    signals: list[str] = field(default_factory=list)

    @property
    def rationale(self) -> str:
        if not self.signals:
            return "No phishing indicators detected."
        return "; ".join(self.signals)


def _normalize_domain(hostname: str) -> str:
    hostname = hostname.lower().strip()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname


def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _is_punycode(hostname: str) -> bool:
    return any(label.startswith("xn--") for label in hostname.split("."))


def _matches_known_brand_impersonation(hostname: str) -> str | None:
    """Return the impersonated brand name if hostname references a brand without being its real domain."""
    collapsed = hostname.replace("-", "").replace(".", "")
    for brand, legit_domain in _BRAND_LEGIT_DOMAINS.items():
        if brand not in collapsed:
            continue
        if hostname == legit_domain or hostname.endswith(f".{legit_domain}"):
            continue
        return brand
    return None

def _registrable_domain(hostname: str) -> str:
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def _score_link(url: str, signals: list[str]) -> int:
    try:
        parsed = urlparse(url if "://" in url else f"//{url}")
        hostname = parsed.hostname or ""
    except ValueError:
        signals.append(f"Malformed link could not be parsed: {url!r}")
        return 2

    if not hostname or not _VALID_HOSTNAME_RE.match(hostname):
        signals.append(f"Malformed link could not be parsed: {url!r}")
        return 2

    hostname = _normalize_domain(hostname)
    points = 0

    if _is_ip_literal(hostname):
        signals.append(f"Link points to a raw IP address ({hostname}) instead of a domain")
        points += 4

    if _is_punycode(hostname):
        signals.append(f"Link domain uses punycode encoding ({hostname}), often used to spoof lookalike domains")
        points += 4

    impersonated = _matches_known_brand_impersonation(hostname)
    if impersonated:
        signals.append(f"Link domain ({hostname}) references '{impersonated}' but is not {_BRAND_LEGIT_DOMAINS[impersonated]}")
        points += 4

    registrable = _registrable_domain(hostname)
    if registrable in _URL_SHORTENERS:
        signals.append(f"Link uses a URL shortener ({registrable}), which hides the real destination")
        points += 2

    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    if tld in _SUSPICIOUS_TLDS:
        signals.append(f"Link uses a TLD commonly abused for phishing (.{tld})")
        points += 2

    return points


def _score_urgency_language(text: str, signals: list[str]) -> int:
    lowered = text.lower()
    matched = [phrase for phrase in _URGENCY_PHRASES if phrase in lowered]
    if matched:
        signals.append(f"Urgency/credential-harvesting language detected: {', '.join(matched[:4])}")
    return min(len(matched), 4)


def _score_generic_greeting_with_sensitive_request(text: str, signals: list[str]) -> int:
    lowered = text.lower()
    has_greeting = any(phrase in lowered for phrase in _GENERIC_GREETINGS)
    has_request = any(phrase in lowered for phrase in _SENSITIVE_INFO_REQUESTS)
    if has_greeting and has_request:
        signals.append("Generic greeting combined with a request for sensitive personal/financial information")
        return 2
    return 0


def _score_sender_domain(sender_domain: str, subject: str, body: str, signals: list[str]) -> int:
    normalized = _normalize_domain(sender_domain)
    combined_text = f"{subject} {body}".lower()

    if normalized in _FREE_WEBMAIL_DOMAINS:
        mentioned_brands = [
            brand for brand, legit in _BRAND_LEGIT_DOMAINS.items()
            if brand in combined_text.replace(" ", "") and not legit.startswith("ssa.")
        ]
        if mentioned_brands:
            signals.append(
                f"Sender uses a free webmail domain ({normalized}) but message claims to be from "
                f"{', '.join(mentioned_brands)}"
            )
            return 3

    impersonated = _matches_known_brand_impersonation(normalized)
    if impersonated:
        signals.append(
            f"Sender domain ({normalized}) references '{impersonated}' but is not "
            f"{_BRAND_LEGIT_DOMAINS[impersonated]}"
        )
        return 4

    return 0


def score_email(
    sender_domain: str,
    subject: str,
    links: list[str],
    body: str = "",
    sender_display_name: str = "",
) -> RiskAssessment:
    """Score an inbound email for phishing risk on a 1-10 scale with rationale."""
    signals: list[str] = []
    points = 0

    points += _score_sender_domain(sender_domain, subject, body, signals)

    for link in links:
        points += _score_link(link, signals)

    full_text = f"{sender_display_name} {subject} {body}"
    points += _score_urgency_language(full_text, signals)
    points += _score_generic_greeting_with_sensitive_request(full_text, signals)

    score = max(1, min(MAX_SCORE, 1 + points))
    return RiskAssessment(score=score, flagged=score >= FLAG_THRESHOLD, signals=signals)
