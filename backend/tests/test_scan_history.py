"""Tests for app/services/scan_history.py and the /api/v1/stats/history endpoint."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect
from sqlalchemy.orm import Session

from app.models.scan_event import ScanEvent
from app.models.user import ROLE_PROTECTED, User
from app.services.scan_history import build_history

NOW = datetime(2026, 10, 13, 15, 0, tzinfo=timezone.utc)


@pytest.fixture()
def owner(db: Session) -> User:
    user = User(email="owner@example.test", display_name="Owner", role=ROLE_PROTECTED, password_hash="x")
    db.add(user)
    db.commit()
    return user


def _event(owner: User, days_ago: int, score: int, categories: list[str] | None = None, links: int = 0) -> ScanEvent:
    return ScanEvent(
        owner_id=owner.id,
        scanned_at=(NOW - timedelta(days=days_ago)).replace(tzinfo=None),
        score=score,
        flagged=score >= 5,
        categories=categories or [],
        flagged_link_count=links,
    )


def test_scan_events_store_no_message_content() -> None:
    columns = {column.name for column in inspect(ScanEvent).columns}
    # owner_id is a user reference, not message content.
    assert columns == {"id", "owner_id", "scanned_at", "score", "flagged", "categories", "flagged_link_count"}


def test_history_aggregates_counts_by_day_and_category(db: Session, owner: User) -> None:
    someone_else = User(email="other@example.test", display_name="Other", role=ROLE_PROTECTED, password_hash="x")
    db.add(someone_else)
    db.commit()
    db.add_all(
        [
            _event(owner, 0, 1),
            _event(owner, 0, 9, ["impersonation", "dangerous_link"], links=2),
            _event(owner, 1, 1),
            _event(owner, 1, 6, ["scam_request"]),
            _event(owner, 6, 8, ["impersonation"], links=1),
            _event(owner, 10, 10, ["impersonation"]),  # outside a 7-day window
            _event(someone_else, 0, 10, ["scam_request"]),  # not this person's
        ]
    )
    db.commit()

    history = build_history(db, owner.id, days=7, now=NOW)

    assert history.emails_checked == 5
    assert history.threats_caught == 3
    assert history.high_risk == 2
    assert history.links_flagged == 3
    assert len(history.daily) == 7
    assert history.daily[0].day == (NOW - timedelta(days=6)).date()
    assert history.daily[-1].day == NOW.date()
    assert (history.daily[-1].checked, history.daily[-1].caught) == (2, 1)
    assert (history.daily[-2].checked, history.daily[-2].caught) == (2, 1)
    assert history.categories[0] == ("impersonation", 2)
    assert dict(history.categories) == {"impersonation": 2, "dangerous_link": 1, "scam_request": 1}
    assert history.first_scan_at == NOW - timedelta(days=10)


def test_history_with_no_scans_is_all_zeroes(db: Session, owner: User) -> None:
    history = build_history(db, owner.id, days=30, now=NOW)

    assert history.emails_checked == 0
    assert history.threats_caught == 0
    assert history.first_scan_at is None
    assert len(history.daily) == 30
    assert all(day.checked == 0 for day in history.daily)


def test_scoring_endpoint_feeds_history_endpoint(client: TestClient) -> None:
    client.post(
        "/api/v1/emails/score",
        json={"sender_domain": "example.com", "subject": "Hello", "links": [], "body": "See you Sunday."},
    )
    scored = client.post(
        "/api/v1/emails/score",
        json={
            "sender_domain": "gmail.com",
            "subject": "Are you free?",
            "links": [],
            "body": "I'm in a meeting. Buy 4 Google Play cards and send me the codes.",
        },
    ).json()
    assert scored["flagged"]
    assert scored["categories"] == ["scam_request"]

    response = client.get("/api/v1/stats/history", params={"days": 7})

    assert response.status_code == 200
    body = response.json()
    assert body["emails_checked"] == 2
    assert body["threats_caught"] == 1
    assert body["categories"] == [{"category": "scam_request", "count": 1}]
    assert len(body["daily"]) == 7
    assert body["daily"][-1]["checked"] == 2


@pytest.mark.parametrize("days", [0, 366])
def test_history_rejects_out_of_range_windows(client: TestClient, days: int) -> None:
    assert client.get("/api/v1/stats/history", params={"days": days}).status_code == 422
