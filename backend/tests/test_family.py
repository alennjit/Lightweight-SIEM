"""Consent-based family linking and per-person data isolation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import FamilyInvite
from tests.conftest import register

PHISH = {
    "sender_domain": "gmail.com",
    "subject": "Chase account alert: unusual activity detected",
    "links": ["https://chase-alerts.com/verify"],
    "body": "Dear customer, confirm your identity immediately or your account will be closed.",
}


def _link(protected: TestClient, monitor: TestClient) -> dict:
    code = protected.post("/api/v1/family/invites").json()["code"]
    response = monitor.post("/api/v1/family/invites/redeem", json={"code": code})
    assert response.status_code == 200, response.text
    return response.json()


def test_invite_code_is_readable_and_stored_hashed(client: TestClient, db: Session) -> None:
    body = client.post("/api/v1/family/invites").json()
    code = body["code"]
    assert len(code) == 9 and code[4] == "-"
    assert not set(code.replace("-", "")) & set("01OIL")  # no look-alike characters
    stored = db.scalar(select(FamilyInvite))
    assert code.replace("-", "") not in stored.code_hash


def test_linked_monitor_sees_the_protected_persons_alerts(client: TestClient, monitor_client: TestClient) -> None:
    client.post("/api/v1/emails/score", json=PHISH)
    assert monitor_client.get("/api/v1/alerts").json() == []  # nobody linked yet

    link = _link(client, monitor_client)
    assert link["display_name"] == "Margaret"

    me = monitor_client.get("/api/v1/auth/me").json()
    assert [p["display_name"] for p in me["people"]] == ["Margaret"]
    alerts = monitor_client.get("/api/v1/alerts").json()
    assert len(alerts) == 1 and alerts[0]["subject"] == PHISH["subject"]
    assert monitor_client.get("/api/v1/stats/history").json()["threats_caught"] == 1

    # Both sides see the link.
    assert [l["display_name"] for l in client.get("/api/v1/family/links").json()] == ["Daniel"]


def test_people_cannot_see_each_others_data(client: TestClient, make_client) -> None:
    client.post("/api/v1/emails/score", json=PHISH)
    stranger = make_client()
    stranger_me = register(stranger, "robert@example.test", "protected", "Robert")
    margaret_id = client.get("/api/v1/auth/me").json()["id"]

    assert stranger.get("/api/v1/alerts").json() == []
    assert stranger.get("/api/v1/alerts", params={"person_id": margaret_id}).status_code == 404
    assert client.get("/api/v1/alerts", params={"person_id": stranger_me["id"]}).status_code == 404


def test_unlinked_monitor_cannot_request_someone_by_id(client: TestClient, monitor_client: TestClient) -> None:
    margaret_id = client.get("/api/v1/auth/me").json()["id"]
    for path in ("/api/v1/alerts", "/api/v1/stats/history"):
        assert monitor_client.get(path, params={"person_id": margaret_id}).status_code == 404


def test_monitor_with_several_people_chooses_who_to_view(client: TestClient, monitor_client: TestClient, make_client) -> None:
    robert = make_client()
    register(robert, "robert@example.test", "protected", "Robert")
    client.post("/api/v1/emails/score", json=PHISH)
    _link(client, monitor_client)
    _link(robert, monitor_client)

    people = monitor_client.get("/api/v1/auth/me").json()["people"]
    assert [p["display_name"] for p in people] == ["Margaret", "Robert"]
    by_name = {p["display_name"]: p["id"] for p in people}
    assert len(monitor_client.get("/api/v1/alerts", params={"person_id": by_name["Margaret"]}).json()) == 1
    assert monitor_client.get("/api/v1/alerts", params={"person_id": by_name["Robert"]}).json() == []


def test_invite_codes_work_once(client: TestClient, monitor_client: TestClient, make_client) -> None:
    code = client.post("/api/v1/family/invites").json()["code"]
    assert monitor_client.post("/api/v1/family/invites/redeem", json={"code": code.lower()}).status_code == 200

    second_monitor = make_client()
    register(second_monitor, "sam@example.test", "monitor", "Sam")
    assert second_monitor.post("/api/v1/family/invites/redeem", json={"code": code}).status_code == 400


def test_expired_invite_is_rejected(client: TestClient, monitor_client: TestClient, db: Session) -> None:
    code = client.post("/api/v1/family/invites").json()["code"]
    invite = db.scalar(select(FamilyInvite))
    invite.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()
    assert monitor_client.post("/api/v1/family/invites/redeem", json={"code": code}).status_code == 400


def test_invite_guessing_is_throttled(monitor_client: TestClient) -> None:
    statuses = [
        monitor_client.post("/api/v1/family/invites/redeem", json={"code": f"AAAA-AAA{n}"}).status_code
        for n in range(2, 9)
    ]
    assert statuses[:5] == [400] * 5
    assert statuses[-1] == 429


def test_roles_are_enforced(client: TestClient, monitor_client: TestClient) -> None:
    assert monitor_client.post("/api/v1/family/invites").status_code == 403
    code = client.post("/api/v1/family/invites").json()["code"]
    assert client.post("/api/v1/family/invites/redeem", json={"code": code}).status_code == 400
    # Monitors can't touch anyone's Gmail connection.
    assert monitor_client.get("/api/v1/gmail/accounts").status_code == 403
    assert monitor_client.get("/api/v1/auth/gmail/authorize", follow_redirects=False).status_code == 403


def test_protected_person_can_remove_a_monitor_immediately(client: TestClient, monitor_client: TestClient) -> None:
    client.post("/api/v1/emails/score", json=PHISH)
    link = _link(client, monitor_client)

    assert client.delete(f"/api/v1/family/links/{link['id']}").status_code == 204
    assert monitor_client.get("/api/v1/alerts").json() == []
    assert monitor_client.get("/api/v1/auth/me").json()["people"] == []


def test_monitor_can_leave_but_strangers_cannot_remove_links(
    client: TestClient, monitor_client: TestClient, make_client
) -> None:
    link = _link(client, monitor_client)
    stranger = make_client()
    register(stranger, "sam@example.test", "monitor", "Sam")
    assert stranger.delete(f"/api/v1/family/links/{link['id']}").status_code == 404
    assert monitor_client.delete(f"/api/v1/family/links/{link['id']}").status_code == 204


def test_monitor_without_links_cannot_score_test_emails(monitor_client: TestClient) -> None:
    assert monitor_client.post("/api/v1/emails/score", json=PHISH).status_code == 400
