"""Tests for app/services/email_ingestion.py. Gmail API calls are mocked;
this exercises the wiring into the real heuristic engine and Alert model.
"""

from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.core.db import Base
from app.core.security import encrypt_token
from app.integrations.gmail_client import GmailMessage, TokenResponse
from app.models.gmail_account import GmailAccount
from app.services import email_ingestion


@pytest.fixture()
def db(tmp_path, monkeypatch) -> Generator[Session, None, None]:
    monkeypatch.setenv("SECRET_KEY", Fernet.generate_key().decode())
    get_settings.cache_clear()

    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        get_settings.cache_clear()


def _connected_account(expires_in_minutes: int = 55) -> GmailAccount:
    return GmailAccount(
        email="grandma@gmail.com",
        encrypted_access_token=encrypt_token("valid-access-token"),
        encrypted_refresh_token=encrypt_token("valid-refresh-token"),
        token_expires_at=datetime.now(timezone.utc) + timedelta(minutes=expires_in_minutes),
    )


def _clean_message(message_id="m1") -> GmailMessage:
    return GmailMessage(
        message_id=message_id,
        sender_domain="newsletter.example.com",
        sender_display_name="Example Newsletter",
        subject="Your weekly digest",
        links=["https://example.com/digest"],
        body_text="Here's what happened this week.",
    )


def _phishing_message(message_id="m2") -> GmailMessage:
    return GmailMessage(
        message_id=message_id,
        sender_domain="gmail.com",
        sender_display_name="Chase Bank",
        subject="Chase account alert: unusual activity detected",
        links=["https://chase-alerts.com/verify"],
        body_text="Dear customer, confirm your identity immediately or your account will be closed.",
    )


def test_ingest_creates_alerts_only_for_flagged_messages(db: Session, mocker):
    account = _connected_account()
    db.add(account)
    db.commit()

    mocker.patch(
        "app.services.email_ingestion.gmail_client.fetch_recent_message_ids",
        return_value=["m1", "m2"],
    )
    mocker.patch(
        "app.services.email_ingestion.gmail_client.fetch_message",
        side_effect=lambda token, message_id: {
            "m1": _clean_message("m1"),
            "m2": _phishing_message("m2"),
        }[message_id],
    )

    result = email_ingestion.ingest_recent_messages(db, get_settings(), account)

    assert result.messages_checked == 2
    assert len(result.alerts) == 1
    assert result.alerts[0].sender_domain == "gmail.com"
    assert result.alerts[0].score >= 5
    assert account.last_ingested_at is not None


def test_ingest_refreshes_expired_token_before_fetching(db: Session, mocker):
    account = _connected_account(expires_in_minutes=-5)  # already expired
    db.add(account)
    db.commit()
    stale_encrypted_token = account.encrypted_access_token

    mock_refresh = mocker.patch(
        "app.services.email_ingestion.gmail_client.refresh_access_token",
        return_value=TokenResponse(access_token="new-access-token", refresh_token="valid-refresh-token", expires_in=3600),
    )
    mocker.patch("app.services.email_ingestion.gmail_client.fetch_recent_message_ids", return_value=[])

    email_ingestion.ingest_recent_messages(db, get_settings(), account)

    mock_refresh.assert_called_once()
    assert account.encrypted_access_token != stale_encrypted_token


def test_ingest_skips_messages_that_fail_to_fetch(db: Session, mocker):
    account = _connected_account()
    db.add(account)
    db.commit()

    mocker.patch(
        "app.services.email_ingestion.gmail_client.fetch_recent_message_ids",
        return_value=["m1", "m2"],
    )

    from app.integrations.gmail_client import GmailApiError

    def flaky_fetch(token, message_id):
        if message_id == "m1":
            raise GmailApiError("simulated fetch failure")
        return _phishing_message("m2")

    mocker.patch("app.services.email_ingestion.gmail_client.fetch_message", side_effect=flaky_fetch)

    result = email_ingestion.ingest_recent_messages(db, get_settings(), account)

    assert result.messages_checked == 2
    assert len(result.alerts) == 1
