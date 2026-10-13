"""Pulls recent messages for a connected Gmail account and runs them
through the existing heuristic detection engine, persisting an Alert for
anything flagged.

Manual-trigger only for now (see docs/ROADMAP.md) — Gmail push
notifications via Cloud Pub/Sub would remove the need to poll on demand,
but that's a separate build, not required to prove this path works.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.security import decrypt_token, encrypt_token
from app.detection.heuristics import score_email
from app.integrations import gmail_client
from app.models.alert import Alert
from app.models.gmail_account import GmailAccount
from app.services.scan_history import record_scan

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IngestResult:
    messages_checked: int
    alerts: list[Alert]


def _as_utc(dt: datetime) -> datetime:
    """SQLite drops tzinfo on round-trip, so a value reloaded from the DB after a
    commit comes back naive even though it was written as UTC-aware. Normalize
    before comparing rather than relying on the driver to preserve tzinfo."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _valid_access_token(db: Session, settings: Settings, account: GmailAccount) -> str:
    """Return a usable access token, refreshing it first if expired or about to be."""
    now = datetime.now(timezone.utc)
    if _as_utc(account.token_expires_at) > now + timedelta(minutes=1):
        return decrypt_token(account.encrypted_access_token)

    refresh_token = decrypt_token(account.encrypted_refresh_token)
    tokens = gmail_client.refresh_access_token(settings, refresh_token)
    account.encrypted_access_token = encrypt_token(tokens.access_token)
    account.token_expires_at = now + timedelta(seconds=tokens.expires_in)
    db.add(account)
    db.commit()
    return tokens.access_token


def ingest_recent_messages(
    db: Session,
    settings: Settings,
    account: GmailAccount,
    max_results: int = 10,
) -> IngestResult:
    """Fetch recent messages for one connected account, score each, persist
    Alerts for the ones the heuristic engine flags."""
    access_token = _valid_access_token(db, settings, account)
    message_ids = gmail_client.fetch_recent_message_ids(access_token, max_results=max_results)

    new_alerts: list[Alert] = []
    for message_id in message_ids:
        try:
            message = gmail_client.fetch_message(access_token, message_id)
        except gmail_client.GmailApiError:
            logger.warning("Skipping message_id=%s for account_id=%s: fetch failed", message_id, account.id)
            continue

        result = score_email(
            sender_domain=message.sender_domain,
            subject=message.subject,
            links=message.links,
            body=message.body_text,
            sender_display_name=message.sender_display_name,
        )
        record_scan(db, account.owner_id, result, link_count=len(message.links))
        if not result.flagged:
            continue

        alert = Alert(
            owner_id=account.owner_id,
            sender_domain=message.sender_domain,
            subject=message.subject,
            links=message.links,
            score=result.score,
            rationale=result.rationale,
        )
        db.add(alert)
        new_alerts.append(alert)

    account.last_ingested_at = datetime.now(timezone.utc)
    db.add(account)
    db.commit()
    for alert in new_alerts:
        db.refresh(alert)

    logger.info(
        "Ingestion complete for account_id=%s: %d messages checked, %d flagged",
        account.id,
        len(message_ids),
        len(new_alerts),
    )
    return IngestResult(messages_checked=len(message_ids), alerts=new_alerts)
