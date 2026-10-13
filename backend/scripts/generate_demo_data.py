"""Generate the public demo's sample data from the real detection engine.

    cd backend
    .venv/Scripts/python.exe -m scripts.generate_demo_data

Writes dashboard/src/demo/demoData.json. Every alert's score, rationale and
categories come from running a fictional email through score_email() — the
demo never hand-writes detection output. Re-run this whenever the engine
changes so the demo stays truthful.

The only illustrative numbers are the per-day "emails checked" counts (a
real inbox has clean mail we don't ship as samples); they are seeded so the
output is reproducible. The dashboard's demo banner says so.
"""

from __future__ import annotations

import json
import logging
import random
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from app.detection.heuristics import score_email
from app.services.scan_history import HIGH_RISK_MIN_SCORE

logger = logging.getLogger(__name__)

OUTPUT_PATH = Path(__file__).resolve().parents[2] / "dashboard" / "src" / "demo" / "demoData.json"
HISTORY_DAYS = 30
CHECKED_PER_DAY = (12, 31)  # illustrative clean-mail volume range
SEED = 20261013

MINUTE = 1
HOUR = 60 * MINUTE
DAY = 24 * HOUR


@dataclass(frozen=True)
class Sample:
    """A fictional email. Domains/IPs/phone numbers are reserved or made up."""

    minutes_ago: int
    sender_domain: str
    subject: str
    body: str
    links: tuple[str, ...] = ()


SAMPLES: tuple[Sample, ...] = (
    Sample(4 * MINUTE, "gmail.com", "Chase account alert: unusual activity detected",
           "Dear customer, we detected unusual activity. Verify your account immediately or it will be suspended.",
           ("http://chase-secure-login.top/verify",)),
    Sample(95 * MINUTE, "usps-redelivery.info", "Your package could not be delivered - action required",
           "Your package is on hold. Pay the redelivery fee within 24 hours or it will be returned.",
           ("https://bit.ly/3usps-fee", "http://192.0.2.44/redeliver")),
    Sample(5 * HOUR, "geeksquad-billing.com", "Your Geek Squad renewal of $399.99 has been processed",
           "Thank you for renewing. If you did not authorize this charge, call us at (888) 555-0147 "
           "to cancel and receive a refund."),
    Sample(1 * DAY + 2 * HOUR, "gmail.com", "Are you free?",
           "I'm in a meeting and can't talk. I need you to pick up four Google Play cards for the "
           "church raffle and send me the codes. Keep this between us for now."),
    Sample(1 * DAY + 7 * HOUR, "outlook.com", "Microsoft 365: your password expires today",
           "Dear user, your Microsoft password expires today. Confirm your password to keep using your account.",
           ("https://xn--microsft-login-7ib.com/keep-password",)),
    Sample(2 * DAY + 3 * HOUR, "amazon-orders-support.com", "Your order #112-4471 has been cancelled",
           "We could not process your payment. Update your billing details to restore your order.",
           ("https://amazon-orders-support.com/refund",)),
    Sample(4 * DAY + 1 * HOUR, "gmail.com", "Norton 360 auto-renewal invoice #88213",
           "Your subscription has been renewed for $349.99. If you did not authorize this, "
           "call our billing desk at 1-888-555-0142 to cancel."),
    Sample(5 * DAY + 6 * HOUR, "support-ticket-center.com", "Your account needs attention",
           "Please log in to review a recent change to your account.",
           ("http://203.0.113.9/login",)),
    Sample(7 * DAY + 4 * HOUR, "netflix-billing.click", "Payment declined",
           "We were unable to process your last payment. Please update your payment method to avoid interruption.",
           ("https://netflix-billing.click/update",)),
    Sample(9 * DAY + 2 * HOUR, "irs-refund-portal.com", "You are eligible for a tax refund",
           "Dear taxpayer, confirm your identity to receive your refund of $1,284.00.",
           ("https://irs-refund-portal.com/claim",)),
    Sample(12 * DAY + 5 * HOUR, "gmail.com", "Grandma it's me, please don't tell mom",
           "I got in trouble on my trip and need help. Can you buy two Apple gift cards and send me "
           "the codes? Please don't tell mom."),
    Sample(15 * DAY + 3 * HOUR, "rewards-center.top", "You've been selected for a $500 grocery reward",
           "Claim your reward before it expires.",
           ("https://bit.ly/claim-500-reward",)),
    Sample(19 * DAY + 8 * HOUR, "gmail.com", "PayPal invoice: $499.00 payment to Coinbase",
           "An invoice of $499.00 has been processed. If you did not authorize this payment, "
           "call PayPal support at 1-808-555-0199 immediately."),
    Sample(24 * DAY + 1 * HOUR, "wellsfargo-secure.cfd", "Security alert: sign-in from a new device",
           "Security alert. If this wasn't you, reactivate your account here.",
           ("https://wellsfargo-secure.cfd/signin",)),
    Sample(28 * DAY + 6 * HOUR, "photo-share-cloud.xyz", "Someone shared a photo album with you",
           "Click below to view the album.",
           ("https://tinyurl.com/family-album-2026",)),
)


def _score_samples() -> list[dict]:
    """Run every sample through the real engine; keep only what it flags."""
    alerts: list[dict] = []
    for sample in sorted(SAMPLES, key=lambda s: s.minutes_ago):
        result = score_email(
            sender_domain=sample.sender_domain,
            subject=sample.subject,
            links=list(sample.links),
            body=sample.body,
        )
        if not result.flagged:
            logger.warning("Sample not flagged by the engine, dropping it: %r (score %d)", sample.subject, result.score)
            continue
        alerts.append(
            {
                "minutes_ago": sample.minutes_ago,
                "sender_domain": sample.sender_domain,
                "subject": sample.subject,
                "links": list(sample.links),
                "score": result.score,
                "rationale": result.rationale,
                "categories": result.categories,
            }
        )
    for index, alert in enumerate(reversed(alerts), start=1):
        alert["id"] = index
    return alerts


def _build_history(alerts: list[dict]) -> dict:
    """Derive history from the scored alerts, plus seeded clean-mail volume per day."""
    rng = random.Random(SEED)
    caught_by_day = Counter(alert["minutes_ago"] // DAY for alert in alerts)
    daily = []
    for days_ago in range(HISTORY_DAYS - 1, -1, -1):
        caught = caught_by_day.get(days_ago, 0)
        daily.append({"days_ago": days_ago, "checked": rng.randint(*CHECKED_PER_DAY) + caught, "caught": caught})

    categories = Counter(category for alert in alerts for category in alert["categories"])
    return {
        "days": HISTORY_DAYS,
        "first_scan_days_ago": 41,
        "emails_checked": sum(day["checked"] for day in daily),
        "threats_caught": len(alerts),
        "high_risk": sum(1 for alert in alerts if alert["score"] >= HIGH_RISK_MIN_SCORE),
        "links_flagged": sum(len(alert["links"]) for alert in alerts),
        "daily": daily,
        "categories": [{"category": name, "count": count} for name, count in categories.most_common()],
    }


def main() -> None:
    """Score the samples and write the demo data file."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    alerts = _score_samples()
    payload = {
        "_note": "Generated by backend/scripts/generate_demo_data.py from the real detection engine. Do not hand-edit.",
        "alerts": alerts,
        "history": _build_history(alerts),
    }
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    logger.info("Wrote %d alerts to %s", len(alerts), OUTPUT_PATH)


if __name__ == "__main__":
    main()
