"""Rule-based phishing risk scoring for inbound email.

Consumes normalized email metadata (sender, headers, links, subject/body
where already permitted — see docs/PRIVACY_AND_CONSENT.md) and produces a
1-10 risk score with a human-readable rationale. This is the first-pass
filter; only flagged messages get escalated to app/detection/claude_analyzer.py
for a narrative.
"""

from dataclasses import dataclass


@dataclass
class RiskAssessment:
    """Result of scoring a single message."""

    score: int  # 1 (benign) - 10 (severe), always paired with a rationale
    rationale: str
    flagged: bool


# TODO: implement. Expected behavior: accept parsed email metadata (sender
# domain, display name, subject, link URLs, presence of urgency/credential
# language) and return a RiskAssessment. Should be pure/deterministic and
# unit-testable without any network calls — reserve external lookups
# (domain reputation, etc.) for app/detection/url_reputation.py, called
# separately and combined by the caller in app/services/email_ingestion.py.
def score_email(sender_domain: str, subject: str, links: list[str]) -> RiskAssessment:
    """Score an inbound email for phishing risk. Not yet implemented."""
    raise NotImplementedError("score_email is a stub — see TODO above")
