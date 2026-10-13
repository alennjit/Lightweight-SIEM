"""Unit tests for app/integrations/gmail_client.py. All Google API calls are
mocked — no real network access, per project convention.
"""

from __future__ import annotations

import base64
from unittest.mock import MagicMock

import httpx
import pytest

from app.core.config import Settings
from app.integrations import gmail_client


def _settings(**overrides) -> Settings:
    defaults = dict(
        google_oauth_client_id="test-client-id",
        google_oauth_client_secret="test-client-secret",
        google_oauth_redirect_uri="http://localhost:8000/api/v1/auth/gmail/callback",
    )
    return Settings(**{**defaults, **overrides})


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def test_build_authorization_url_includes_required_params():
    url = gmail_client.build_authorization_url(_settings(), state="abc123")
    assert url.startswith(gmail_client.AUTH_URL)
    assert "client_id=test-client-id" in url
    assert "state=abc123" in url
    assert "access_type=offline" in url
    assert "gmail.readonly" in url


def test_build_authorization_url_raises_without_client_id():
    with pytest.raises(gmail_client.GmailApiError):
        gmail_client.build_authorization_url(_settings(google_oauth_client_id=None), state="x")


def test_exchange_code_for_tokens_parses_response(mocker):
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {
        "access_token": "at-123",
        "refresh_token": "rt-456",
        "expires_in": 3599,
    }
    mocker.patch("app.integrations.gmail_client.httpx.post", return_value=mock_response)

    tokens = gmail_client.exchange_code_for_tokens(_settings(), code="auth-code")
    assert tokens.access_token == "at-123"
    assert tokens.refresh_token == "rt-456"
    assert tokens.expires_in == 3599


def test_exchange_code_for_tokens_raises_when_no_refresh_token(mocker):
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"access_token": "at-123", "expires_in": 3599}
    mocker.patch("app.integrations.gmail_client.httpx.post", return_value=mock_response)

    with pytest.raises(gmail_client.GmailApiError, match="refresh_token"):
        gmail_client.exchange_code_for_tokens(_settings(), code="auth-code")


def test_exchange_code_for_tokens_wraps_http_errors(mocker):
    mocker.patch(
        "app.integrations.gmail_client.httpx.post",
        side_effect=httpx.ConnectError("boom"),
    )
    with pytest.raises(gmail_client.GmailApiError):
        gmail_client.exchange_code_for_tokens(_settings(), code="auth-code")


def test_fetch_account_email(mocker):
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"emailAddress": "grandma@gmail.com"}
    mocker.patch("app.integrations.gmail_client.httpx.get", return_value=mock_response)

    assert gmail_client.fetch_account_email("at-123") == "grandma@gmail.com"


def test_fetch_recent_message_ids(mocker):
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {"messages": [{"id": "m1"}, {"id": "m2"}]}
    mocker.patch("app.integrations.gmail_client.httpx.get", return_value=mock_response)

    assert gmail_client.fetch_recent_message_ids("at-123") == ["m1", "m2"]


def test_fetch_recent_message_ids_empty_inbox(mocker):
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {}
    mocker.patch("app.integrations.gmail_client.httpx.get", return_value=mock_response)

    assert gmail_client.fetch_recent_message_ids("at-123") == []


def test_parse_message_extracts_sender_subject_and_links():
    body_html = '<p>Verify now: <a href="https://chase-alerts.com/verify">click here</a></p>'
    payload = {
        "id": "m1",
        "payload": {
            "headers": [
                {"name": "From", "value": '"Chase Bank" <alerts@secure-chase-alerts.com>'},
                {"name": "Subject", "value": "Unusual activity detected"},
            ],
            "mimeType": "text/html",
            "body": {"data": _b64(body_html)},
        },
    }
    message = gmail_client.parse_message(payload)
    assert message.sender_display_name == "Chase Bank"
    assert message.sender_domain == "secure-chase-alerts.com"
    assert message.subject == "Unusual activity detected"
    assert "https://chase-alerts.com/verify" in message.links


def test_parse_message_handles_multipart_body():
    text_part = {"mimeType": "text/plain", "body": {"data": _b64("Plain text, no links here.")}}
    html_part = {
        "mimeType": "text/html",
        "body": {"data": _b64('<a href="https://example.com/a">a</a>')},
    }
    payload = {
        "id": "m2",
        "payload": {
            "headers": [
                {"name": "From", "value": "noreply@newsletter.example.com"},
                {"name": "Subject", "value": "Weekly digest"},
            ],
            "mimeType": "multipart/alternative",
            "parts": [text_part, html_part],
        },
    }
    message = gmail_client.parse_message(payload)
    assert message.sender_domain == "newsletter.example.com"
    assert "https://example.com/a" in message.links


def test_parse_message_handles_missing_headers_gracefully():
    message = gmail_client.parse_message({"id": "m3", "payload": {}})
    assert message.sender_domain == ""
    assert message.subject == ""
    assert message.links == []
