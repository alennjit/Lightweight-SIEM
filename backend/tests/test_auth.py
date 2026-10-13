"""Sign-up, sign-in, sessions, and the CSRF/brute-force defences around them."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.passwords import hash_password, verify_password
from app.models.user import User, UserSession
from tests.conftest import TEST_PASSWORD, register


def _login(client: TestClient, email: str, password: str = TEST_PASSWORD):
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


# --- passwords -------------------------------------------------------------


def test_password_hash_round_trip_and_is_salted() -> None:
    first, second = hash_password("a long passphrase here"), hash_password("a long passphrase here")
    assert first != second  # unique salt per hash
    assert first.startswith("scrypt$")
    assert verify_password("a long passphrase here", first)
    assert not verify_password("a long passphrase herE", first)


@pytest.mark.parametrize("stored", ["", "not-a-hash", "md5$abc", "scrypt$1$2$3$!!$!!"])
def test_verify_password_rejects_malformed_hashes(stored: str) -> None:
    assert verify_password("anything at all", stored) is False


@pytest.mark.parametrize(
    ("password", "message"),
    [
        ("short", "at least 12"),
        ("password1234", "too easy"),
        ("aaaaaaaaaaaaaaaa", "too easy"),
        ("margaret-is-great-2026", "email address"),
    ],
)
def test_weak_passwords_are_rejected(make_client, password: str, message: str) -> None:
    response = make_client().post(
        "/api/v1/auth/register",
        json={"email": "margaret@example.test", "password": password, "display_name": "M", "role": "protected"},
    )
    assert response.status_code == 400
    assert message in response.json()["detail"]


# --- registration ----------------------------------------------------------


def test_register_sets_a_locked_down_session_cookie(make_client) -> None:
    c = make_client()
    response = c.post(
        "/api/v1/auth/register",
        json={"email": "Margaret@Example.test ", "password": TEST_PASSWORD, "display_name": "Margaret", "role": "protected"},
    )
    assert response.status_code == 201
    cookie = response.headers["set-cookie"].lower()
    assert "lwsiem_session=" in cookie
    assert "httponly" in cookie
    assert "secure" in cookie
    assert "samesite=lax" in cookie

    body = response.json()
    assert body["email"] == "margaret@example.test"  # normalized
    assert body["people"] == [{"id": body["id"], "display_name": "Margaret"}]
    assert "password" not in response.text and "scrypt" not in response.text


def test_password_and_session_token_are_never_stored_in_plaintext(make_client, db: Session) -> None:
    c = make_client()
    register(c, "margaret@example.test", "protected")
    user = db.scalar(select(User))
    assert TEST_PASSWORD not in user.password_hash
    token = c.cookies.get("lwsiem_session")
    stored = db.scalar(select(UserSession))
    assert stored.token_hash != token and len(stored.token_hash) == 64


def test_duplicate_email_is_rejected_case_insensitively(make_client) -> None:
    register(make_client(), "margaret@example.test", "protected")
    response = make_client().post(
        "/api/v1/auth/register",
        json={"email": "MARGARET@example.test", "password": TEST_PASSWORD, "display_name": "M", "role": "protected"},
    )
    assert response.status_code == 400


@pytest.mark.parametrize("payload_change", [{"role": "admin"}, {"email": "not-an-email"}, {"display_name": "   "}])
def test_register_validates_input(make_client, payload_change: dict) -> None:
    payload = {"email": "m@example.test", "password": TEST_PASSWORD, "display_name": "M", "role": "protected"}
    response = make_client().post("/api/v1/auth/register", json=payload | payload_change)
    assert response.status_code in (400, 422)


# --- login / logout --------------------------------------------------------


def test_login_and_me(make_client) -> None:
    register(make_client(), "margaret@example.test", "protected", "Margaret")
    c = make_client()
    assert c.get("/api/v1/auth/me").status_code == 401

    assert _login(c, "MARGARET@example.test").status_code == 200
    assert c.get("/api/v1/auth/me").json()["display_name"] == "Margaret"


def test_wrong_password_and_unknown_email_get_the_same_error(make_client) -> None:
    register(make_client(), "margaret@example.test", "protected")
    wrong = _login(make_client(), "margaret@example.test", "not the password!!")
    unknown = _login(make_client(), "nobody@example.test", "not the password!!")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_repeated_failures_lock_the_account_even_for_the_right_password(make_client) -> None:
    register(make_client(), "margaret@example.test", "protected")
    attacker = make_client()
    for _ in range(5):
        assert _login(attacker, "margaret@example.test", "guess guess guess").status_code == 401
    assert _login(attacker, "margaret@example.test").status_code == 429


def test_logout_kills_the_session_server_side(make_client) -> None:
    c = make_client()
    register(c, "margaret@example.test", "protected")
    stolen_token = c.cookies.get("lwsiem_session")

    assert c.post("/api/v1/auth/logout").status_code == 204
    assert c.get("/api/v1/auth/me").status_code == 401

    replay = make_client()
    replay.cookies.set("lwsiem_session", stolen_token)
    assert replay.get("/api/v1/auth/me").status_code == 401


def test_expired_session_is_rejected(make_client, db: Session) -> None:
    c = make_client()
    register(c, "margaret@example.test", "protected")
    session = db.scalar(select(UserSession))
    session.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()
    assert c.get("/api/v1/auth/me").status_code == 401


def test_forged_session_cookie_is_rejected(make_client) -> None:
    c = make_client()
    c.cookies.set("lwsiem_session", "made-up-token")
    assert c.get("/api/v1/auth/me").status_code == 401


# --- endpoints require a session ------------------------------------------


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/api/v1/alerts"),
        ("get", "/api/v1/stats/history"),
        ("post", "/api/v1/emails/score"),
        ("get", "/api/v1/gmail/accounts"),
        ("get", "/api/v1/auth/gmail/authorize"),
        ("get", "/api/v1/family/links"),
        ("post", "/api/v1/family/invites"),
    ],
)
def test_data_endpoints_require_sign_in(make_client, method: str, path: str) -> None:
    kwargs = {"json": {"sender_domain": "x.com", "subject": "s"}} if method == "post" else {}
    response = getattr(make_client(), method)(path, follow_redirects=False, **kwargs)
    assert response.status_code == 401


# --- CSRF origin check -----------------------------------------------------


def test_cross_site_post_is_blocked(client: TestClient) -> None:
    response = client.post("/api/v1/family/invites", headers={"Origin": "https://evil.example"})
    assert response.status_code == 403


def test_dashboard_origin_post_is_allowed(client: TestClient) -> None:
    response = client.post("/api/v1/family/invites", headers={"Origin": "http://localhost:5173"})
    assert response.status_code == 201
