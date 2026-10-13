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
    "racing", "party", "science", "icu", "cfd", "sbs", "cyou", "buzz",
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
    # Commonly impersonated in fake-renewal / tech-support callback scams
    "geeksquad": "geeksquad.com",
    "bestbuy": "bestbuy.com",
    "norton": "norton.com",
    "mcafee": "mcafee.com",
}

_SHORT_BRAND_MAX_LEN = 4

_URGENCY_PHRASES = (
    "verify your account", "account suspended", "unusual activity",
    "click here immediately", "confirm your identity",
    "account will be closed", "urgent action required",
    "password has expired", "password expired", "update your payment",
    "you have won", "claim your prize", "act now", "limited time offer",
    "wire transfer", "confirm your password",
    "reactivate your account", "security alert",
)

# Gift-card payment scams ("boss"/pastor/grandchild impersonation): the
# scammer asks the target to buy gift cards and send the codes. Real
# businesses and family members essentially never ask for this.
_GIFT_CARD_RE = re.compile(
    r"\b(gift ?cards?|itunes cards?|google play cards?|apple cards?|steam cards?|ebay cards?)\b"
)
# Handing over the codes is the defining step of the scam — retailers sell
# gift cards and relatives thank you for them, but neither asks for codes.
_GIFT_CARD_HANDOVER = (
    "send me the code", "send the code", "the codes", "card number", "card numbers",
    "pin number", "scratch", "take a picture", "photo of the back", "picture of the back",
    "send them to me", "email me the", "text me the",
)
_GIFT_CARD_PURCHASE = ("buy", "purchase", "pick up", "pick me up", "get me", "grab")
_FAVOR_PRETEXTS = (
    "quick favor", "do me a favor", "are you available", "are you free",
    "keep this between us", "keep it between us", "don't tell", "i'm in a meeting",
    "i am in a meeting", "can't talk", "cannot talk", "surprise for",
)

# Fake renewal / refund callback scams (Geek Squad, Norton, McAfee, PayPal
# "invoice"): a fake charge plus an instruction to call or reply to
# "cancel", which leads to a remote-access or refund scam.
_FAKE_CHARGE_PHRASES = (
    "has been renewed", "auto-renew", "automatically renewed", "renewal",
    "has been processed", "has been charged", "will be charged", "been debited",
    "invoice", "your subscription", "order confirmation", "payment of",
)
# The hook: "if you didn't authorize this, contact us". Legit receipts say
# "manage your order"; the scam needs you to dispute a charge you never made.
_DISAVOWAL_PHRASES = (
    "did not authorize", "didn't authorize", "not authorize this", "not authorized this",
    "did not make this purchase", "didn't make this purchase", "did not request",
    "if this wasn't you", "if this was not you", "dispute this charge",
)
_CONTACT_PHRASES = ("call", "phone", "cancel", "refund", "reply", "contact")
_PHONE_NUMBER_RE = re.compile(r"(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b")
_DOLLAR_AMOUNT_RE = re.compile(r"\$\s?\d{2,}(?:,\d{3})*(?:\.\d{2})?")

# Stable category keys for each signal, used for history/reporting. Keep in
# sync with dashboard/src/categories.ts.
CATEGORY_IMPERSONATION = "impersonation"
CATEGORY_DANGEROUS_LINK = "dangerous_link"
CATEGORY_PRESSURE = "pressure_language"
CATEGORY_SCAM_REQUEST = "scam_request"
CATEGORY_INFO_REQUEST = "info_request"
CATEGORY_SUSPICIOUS_SENDER = "suspicious_sender"

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
    categories: list[str] = field(default_factory=list)  # unique, in order first seen

    @property
    def rationale(self) -> str:
        if not self.signals:
            return "No phishing indicators detected."
        return "; ".join(self.signals)


class _Collector:
    """Accumulates signals and their categories while a message is scored."""

    def __init__(self) -> None:
        self.signals: list[str] = []
        self.categories: list[str] = []

    def add(self, category: str, signal: str) -> None:
        """Record one signal under its threat category."""
        self.signals.append(signal)
        if category not in self.categories:
            self.categories.append(category)


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
    tokens = set(re.split(r"[.\-]", hostname))
    for brand, legit_domain in _BRAND_LEGIT_DOMAINS.items():
        # Short brands ("irs", "ups", "usps") appear inside ordinary words
        # (firstbank, googlegroups), so they must be a whole hyphen/dot token.
        if len(brand) <= _SHORT_BRAND_MAX_LEN:
            if brand not in tokens:
                continue
        elif brand not in collapsed:
            continue
        if hostname == legit_domain or hostname.endswith(f".{legit_domain}"):
            continue
        return brand
    return None

def _registrable_domain(hostname: str) -> str:
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def _tld(hostname: str) -> str:
    return hostname.rsplit(".", 1)[-1] if "." in hostname else ""


def _score_link(url: str, found: _Collector) -> int:
    try:
        parsed = urlparse(url if "://" in url else f"//{url}")
        hostname = parsed.hostname or ""
    except ValueError:
        found.add(CATEGORY_DANGEROUS_LINK, f"Malformed link could not be parsed: {url!r}")
        return 2

    if not hostname or not _VALID_HOSTNAME_RE.match(hostname):
        found.add(CATEGORY_DANGEROUS_LINK, f"Malformed link could not be parsed: {url!r}")
        return 2

    hostname = _normalize_domain(hostname)
    points = 0

    if _is_ip_literal(hostname):
        found.add(CATEGORY_DANGEROUS_LINK, f"Link points to a raw IP address ({hostname}) instead of a domain")
        points += 4

    if _is_punycode(hostname):
        found.add(CATEGORY_DANGEROUS_LINK, f"Link domain uses punycode encoding ({hostname}), often used to spoof lookalike domains")
        points += 4

    impersonated = _matches_known_brand_impersonation(hostname)
    if impersonated:
        found.add(CATEGORY_IMPERSONATION, f"Link domain ({hostname}) references '{impersonated}' but is not {_BRAND_LEGIT_DOMAINS[impersonated]}")
        points += 4

    registrable = _registrable_domain(hostname)
    if registrable in _URL_SHORTENERS:
        found.add(CATEGORY_DANGEROUS_LINK, f"Link uses a URL shortener ({registrable}), which hides the real destination")
        points += 2

    tld = _tld(hostname)
    if tld in _SUSPICIOUS_TLDS:
        found.add(CATEGORY_DANGEROUS_LINK, f"Link uses a TLD commonly abused for phishing (.{tld})")
        points += 2

    return points


def _score_urgency_language(text: str, found: _Collector) -> int:
    lowered = text.lower()
    matched = [phrase for phrase in _URGENCY_PHRASES if phrase in lowered]
    if matched:
        found.add(CATEGORY_PRESSURE, f"Urgency/credential-harvesting language detected: {', '.join(matched[:4])}")
    return min(len(matched), 4)


def _score_generic_greeting_with_sensitive_request(text: str, found: _Collector) -> int:
    lowered = text.lower()
    has_greeting = any(phrase in lowered for phrase in _GENERIC_GREETINGS)
    has_request = any(phrase in lowered for phrase in _SENSITIVE_INFO_REQUESTS)
    if has_greeting and has_request:
        found.add(CATEGORY_INFO_REQUEST, "Generic greeting combined with a request for sensitive personal/financial information")
        return 2
    return 0


def _score_gift_card_request(text: str, found: _Collector) -> int:
    """Asking someone to buy gift cards and hand over the codes is a scam pattern, not a business practice."""
    lowered = text.lower()
    if not _GIFT_CARD_RE.search(lowered):
        return 0
    asks_for_codes = any(phrase in lowered for phrase in _GIFT_CARD_HANDOVER)
    asks_to_buy = any(phrase in lowered for phrase in _GIFT_CARD_PURCHASE)
    pretexts = [phrase for phrase in _FAVOR_PRETEXTS if phrase in lowered]
    if not (asks_for_codes or (asks_to_buy and pretexts)):
        return 0
    points = 5
    if pretexts:
        points += 2
        found.add(
            CATEGORY_SCAM_REQUEST,
            "Asks you to buy gift cards and share the codes, with a 'favor' pretext "
            f"({', '.join(pretexts[:2])}) — a common impersonation scam",
        )
    else:
        found.add(CATEGORY_SCAM_REQUEST, "Asks you to buy gift cards and share the codes — a common scam pattern")
    return points


def _is_known_brand_sender(sender_domain: str) -> bool:
    normalized = _normalize_domain(sender_domain)
    return any(
        normalized == legit or normalized.endswith(f".{legit}") for legit in _BRAND_LEGIT_DOMAINS.values()
    )


def _score_fake_charge_callback(sender_domain: str, text: str, found: _Collector) -> int:
    """A surprise charge plus 'didn't authorize this? contact us' is the fake-renewal / refund-scam template."""
    if _is_known_brand_sender(sender_domain):
        return 0
    lowered = text.lower()
    charge = next((phrase for phrase in _FAKE_CHARGE_PHRASES if phrase in lowered), None)
    callback = next((phrase for phrase in _DISAVOWAL_PHRASES if phrase in lowered), None)
    wants_contact = any(phrase in lowered for phrase in _CONTACT_PHRASES) or _PHONE_NUMBER_RE.search(text)
    if not (charge and callback and wants_contact):
        return 0
    points = 3
    details: list[str] = []
    if _PHONE_NUMBER_RE.search(text):
        points += 1
        details.append("a phone number to call")
    if _DOLLAR_AMOUNT_RE.search(text):
        points += 1
        details.append("a specific dollar amount")
    extra = f", with {' and '.join(details)}" if details else ""
    found.add(
        CATEGORY_SCAM_REQUEST,
        f"Claims you were charged ('{charge}') and asks you to get in touch if you '{callback}'{extra} "
        "— the fake renewal/refund scam pattern",
    )
    return points


def _score_sender_domain(sender_domain: str, subject: str, body: str, found: _Collector) -> int:
    normalized = _normalize_domain(sender_domain)
    combined_text = f"{subject} {body}".lower()

    if normalized in _FREE_WEBMAIL_DOMAINS:
        mentioned_brands = [
            brand for brand, legit in _BRAND_LEGIT_DOMAINS.items()
            if brand in combined_text.replace(" ", "") and not legit.startswith("ssa.")
        ]
        if mentioned_brands:
            found.add(
                CATEGORY_IMPERSONATION,
                f"Sender uses a free webmail domain ({normalized}) but message claims to be from "
                f"{', '.join(mentioned_brands)}"
            )
            return 3

    impersonated = _matches_known_brand_impersonation(normalized)
    if impersonated:
        found.add(
            CATEGORY_IMPERSONATION,
            f"Sender domain ({normalized}) references '{impersonated}' but is not "
            f"{_BRAND_LEGIT_DOMAINS[impersonated]}",
        )
        return 4

    tld = _tld(normalized)
    if tld in _SUSPICIOUS_TLDS:
        found.add(CATEGORY_SUSPICIOUS_SENDER, f"Sender domain uses a TLD commonly abused for phishing (.{tld})")
        return 2

    return 0


def score_email(
    sender_domain: str,
    subject: str,
    links: list[str],
    body: str = "",
    sender_display_name: str = "",
) -> RiskAssessment:
    """Score an inbound email for phishing risk on a 1-10 scale with rationale."""
    found = _Collector()
    points = 0

    points += _score_sender_domain(sender_domain, subject, body, found)

    for link in links:
        points += _score_link(link, found)

    full_text = f"{sender_display_name} {subject} {body}"
    points += _score_urgency_language(full_text, found)
    points += _score_generic_greeting_with_sensitive_request(full_text, found)
    points += _score_gift_card_request(full_text, found)
    points += _score_fake_charge_callback(sender_domain, full_text, found)

    score = max(1, min(MAX_SCORE, 1 + points))
    return RiskAssessment(
        score=score,
        flagged=score >= FLAG_THRESHOLD,
        signals=found.signals,
        categories=found.categories,
    )
