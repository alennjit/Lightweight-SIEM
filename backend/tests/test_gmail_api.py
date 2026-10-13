"""Integration tests for the Gmail OAuth connect + ingest endpoints.

Same in-memory-per-test DB pattern as test_alerts_api.py. All Gmail/OAuth
network calls are mocked at the gmail_client boundary — no real network
access.
"""

from __future__ import annotations

from collections.abc import Generator

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings
from app.core.db import Base, get_db
from app.integrations.gmail_client import GmailApiError, TokenResponse
from app.main import app


@pytest.fixture()
def client(tmp_path, monkeypatch) -> Generator[TestClient, None, None]:
    monkeypatch.setenv("SECRET_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "test-client-secret")
    get_settings.cache_clear()

    db_path = tmp_path / "test.db"
    test_engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    def override_get_db() -> Generator:
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()
        get_settings.cache_clear()


def test_authorize_redirects_to_google_with_state_cookie(client: TestClient):
    response = client.get("/api/v1/auth/gmail/authorize", follow_redirects=False)
    assert response.status_code in (302, 307)
    assert response.headers["location"].startswith("https://accounts.google.com/o/oauth2/v2/auth")
    assert "oauth_state" in response.cookies


def test_callback_rejects_mismatched_state(client: TestClient):
    response = client.get(
        "/api/v1/auth/gmail/callback",
        params={"code": "auth-code", "state": "does-not-match-cookie"},
    )
    assert response.status_code == 400


def test_callback_creates_gmail_account(client: TestClient, mocker):
    authorize = client.get("/api/v1/auth/gmail/authorize", follow_redirects=False)
    state = authorize.cookies["oauth_state"]

    mocker.patch(
        "app.api.gmail.gmail_client.exchange_code_for_tokens",
        return_value=TokenResponse(access_token="at-1", refresh_token="rt-1", expires_in=3600),
    )
    mocker.patch(
        "app.api.gmail.gmail_client.fetch_account_email",
        return_value="grandma@gmail.com",
    )

    response = client.get(
        "/api/v1/auth/gmail/callback",
        params={"code": "auth-code", "state": state},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "grandma@gmail.com"
    assert "encrypted_access_token" not in body
    assert "access_token" not in body

    accounts = client.get("/api/v1/gmail/accounts").json()
    assert len(accounts) == 1
    assert accounts[0]["email"] == "grandma@gmail.com"


def test_callback_surfaces_gmail_api_errors_as_502(client: TestClient, mocker):
    authorize = client.get("/api/v1/auth/gmail/authorize", follow_redirects=False)
    state = authorize.cookies["oauth_state"]

    mocker.patch(
        "app.api.gmail.gmail_client.exchange_code_for_tokens",
        side_effect=GmailApiError("token exchange failed"),
    )

    response = client.get(
        "/api/v1/auth/gmail/callback",
        params={"code": "bad-code", "state": state},
    )
    assert response.status_code == 502


def test_ingest_endpoint_returns_404_for_unknown_account(client: TestClient):
    response = client.post("/api/v1/gmail/accounts/999/ingest")
    assert response.status_code == 404


def test_ingest_endpoint_creates_alerts_end_to_end(client: TestClient, mocker):
    authorize = client.get("/api/v1/auth/gmail/authorize", follow_redirects=False)
    state = authorize.cookies["oauth_state"]
    mocker.patch(
        "app.api.gmail.gmail_client.exchange_code_for_tokens",
        return_value=TokenResponse(access_token="at-1", refresh_token="rt-1", expires_in=3600),
    )
    mocker.patch("app.api.gmail.gmail_client.fetch_account_email", return_value="grandma@gmail.com")
    callback = client.get(
        "/api/v1/auth/gmail/callback",
        params={"code": "auth-code", "state": state},
    )
    account_id = callback.json()["id"]

    from app.integrations.gmail_client import GmailMessage

    mocker.patch(
        "app.services.email_ingestion.gmail_client.fetch_recent_message_ids",
        return_value=["m1"],
    )
    mocker.patch(
        "app.services.email_ingestion.gmail_client.fetch_message",
        return_value=GmailMessage(
            message_id="m1",
            sender_domain="gmail.com",
            sender_display_name="Chase Bank",
            subject="Chase account alert: unusual activity detected",
            links=["https://chase-alerts.com/verify"],
            body_text="Dear customer, confirm your identity immediately or your account will be closed.",
        ),
    )

    response = client.post(f"/api/v1/gmail/accounts/{account_id}/ingest")
    assert response.status_code == 200
    body = response.json()
    assert body["messages_checked"] == 1
    assert len(body["alerts_created"]) == 1

    assert len(client.get("/api/v1/alerts").json()) == 1
