"""Integration tests for the email-scoring and alerts API endpoints.

Uses a temp-file SQLite DB per test via dependency override, and avoids
running the app's lifespan (which would touch the real dev.db) by not
using TestClient as a context manager.
"""

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.db import Base, get_db
from app.main import app


@pytest.fixture()
def client(tmp_path) -> Generator[TestClient, None, None]:
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


def test_scoring_a_clean_email_does_not_create_an_alert(client: TestClient) -> None:
    response = client.post(
        "/api/v1/emails/score",
        json={
            "sender_domain": "newsletter.example.com",
            "subject": "Your weekly digest",
            "links": ["https://example.com/digest/42"],
            "body": "Here's what happened this week.",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["flagged"] is False
    assert body["alert_id"] is None
    assert client.get("/api/v1/alerts").json() == []


def test_scoring_a_phishing_email_creates_an_alert(client: TestClient) -> None:
    response = client.post(
        "/api/v1/emails/score",
        json={
            "sender_domain": "gmail.com",
            "subject": "Chase account alert: unusual activity detected",
            "links": ["https://chase-alerts.com/verify"],
            "body": "Dear customer, please confirm your identity immediately or your account will be closed.",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["flagged"] is True
    assert body["alert_id"] is not None

    alerts = client.get("/api/v1/alerts").json()
    assert len(alerts) == 1
    assert alerts[0]["id"] == body["alert_id"]
    assert alerts[0]["sender_domain"] == "gmail.com"


def test_alerts_are_returned_most_recent_first(client: TestClient) -> None:
    for subject in ["Chase account suspended, verify now", "PayPal unusual activity, act now"]:
        client.post(
            "/api/v1/emails/score",
            json={
                "sender_domain": "gmail.com",
                "subject": subject,
                "links": ["https://paypal-secure-login.com/verify"],
                "body": "Dear customer, confirm your identity immediately, account will be closed.",
            },
        )

    alerts = client.get("/api/v1/alerts").json()
    assert len(alerts) == 2
    assert alerts[0]["subject"] == "PayPal unusual activity, act now"
