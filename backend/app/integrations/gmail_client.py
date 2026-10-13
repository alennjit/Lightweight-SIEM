"""Gmail OAuth + message fetching.

Uses direct httpx calls to Google's OAuth2 and Gmail REST APIs rather than
the google-api-python-client SDK — keeps the dependency footprint small and
every HTTP call explicit and mockable in tests.

Every external call is wrapped in try/except with a non-leaky error message
— never include a token value in a raised exception or log line.
"""

from __future__ import annotations

import base64
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlencode

import httpx

from app.core.config import Settings

logger = logging.getLogger(__name__)

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"
SCOPE = "https://www.googleapis.com/auth/gmail.readonly"

_LINK_PATTERN = re.compile(r"""href=['"]?([^'" >]+)|(\bhttps?://[^\s<>"']+)""", re.IGNORECASE)
_FROM_HEADER_PATTERN = re.compile(r'^\s*"?([^"<]*)"?\s*<([^@>]+)@([^>]+)>\s*$')


class GmailApiError(RuntimeError):
    """Raised for any Gmail/OAuth API failure. Message never includes token values."""


@dataclass(frozen=True)
class TokenResponse:
    access_token: str
    refresh_token: str | None
    expires_in: int  # seconds


@dataclass(frozen=True)
class GmailMessage:
    message_id: str
    sender_domain: str
    sender_display_name: str
    subject: str
    links: list[str] = field(default_factory=list)
    body_text: str = ""


def build_authorization_url(settings: Settings, state: str) -> str:
    """Build the Google OAuth consent-screen URL the user is redirected to."""
    if not settings.google_oauth_client_id:
        raise GmailApiError("GOOGLE_OAUTH_CLIENT_ID is not configured.")
    params = {
        "client_id": settings.google_oauth_client_id,
        "redirect_uri": settings.google_oauth_redirect_uri,
        "response_type": "code",
        "scope": SCOPE,
        "access_type": "offline",  # required to receive a refresh_token
        "prompt": "consent",  # forces a refresh_token even on repeat authorizations
        "state": state,
    }
    return f"{AUTH_URL}?{urlencode(params)}"


def exchange_code_for_tokens(settings: Settings, code: str) -> TokenResponse:
    """Exchange an OAuth authorization code for access + refresh tokens."""
    try:
        response = httpx.post(
            TOKEN_URL,
            data={
                "code": code,
                "client_id": settings.google_oauth_client_id,
                "client_secret": settings.google_oauth_client_secret,
                "redirect_uri": settings.google_oauth_redirect_uri,
                "grant_type": "authorization_code",
            },
            timeout=10.0,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        logger.error("Gmail OAuth token exchange failed: %s", exc)
        raise GmailApiError("Failed to exchange authorization code for tokens.") from exc

    payload = response.json()
    refresh_token = payload.get("refresh_token")
    if not refresh_token:
        raise GmailApiError(
            "Google did not return a refresh_token for this authorization. This usually "
            "means the account was already connected once before — revoke access at "
            "https://myaccount.google.com/permissions and re-authorize."
        )
    return TokenResponse(
        access_token=payload["access_token"],
        refresh_token=refresh_token,
        expires_in=payload["expires_in"],
    )


def refresh_access_token(settings: Settings, refresh_token: str) -> TokenResponse:
    """Exchange a stored refresh token for a new access token."""
    try:
        response = httpx.post(
            TOKEN_URL,
            data={
                "refresh_token": refresh_token,
                "client_id": settings.google_oauth_client_id,
                "client_secret": settings.google_oauth_client_secret,
                "grant_type": "refresh_token",
            },
            timeout=10.0,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        logger.error("Gmail access token refresh failed: %s", exc)
        raise GmailApiError("Failed to refresh Gmail access token.") from exc

    payload = response.json()
    return TokenResponse(
        access_token=payload["access_token"],
        refresh_token=refresh_token,  # Google doesn't rotate refresh tokens on refresh
        expires_in=payload["expires_in"],
    )


def fetch_account_email(access_token: str) -> str:
    """Return the connected inbox's email address, to key the GmailAccount row on."""
    try:
        response = httpx.get(
            f"{GMAIL_API_BASE}/profile",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10.0,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        logger.error("Gmail profile fetch failed: %s", exc)
        raise GmailApiError("Failed to fetch the connected Gmail account's profile.") from exc
    return response.json()["emailAddress"]


def fetch_recent_message_ids(access_token: str, max_results: int = 10) -> list[str]:
    """List the most recent inbox message IDs."""
    try:
        response = httpx.get(
            f"{GMAIL_API_BASE}/messages",
            headers={"Authorization": f"Bearer {access_token}"},
            params={"maxResults": max_results, "labelIds": "INBOX"},
            timeout=10.0,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        logger.error("Gmail message list fetch failed: %s", exc)
        raise GmailApiError("Failed to list recent Gmail messages.") from exc
    return [m["id"] for m in response.json().get("messages", [])]


def fetch_message(access_token: str, message_id: str) -> GmailMessage:
    """Fetch one message and extract exactly what the detection engine needs:
    sender domain/display name, subject, and links found in the body.

    Body text is decoded locally to extract links and is never forwarded
    anywhere external by this function — only the Claude narrative step
    (Stage 2, after a heuristic flag) is allowed to send body content
    onward. See docs/PRIVACY_AND_CONSENT.md.
    """
    try:
        response = httpx.get(
            f"{GMAIL_API_BASE}/messages/{message_id}",
            headers={"Authorization": f"Bearer {access_token}"},
            params={"format": "full"},
            timeout=10.0,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        logger.error("Gmail message fetch failed for message_id=%s: %s", message_id, exc)
        raise GmailApiError(f"Failed to fetch Gmail message {message_id}.") from exc

    return parse_message(response.json())


def parse_message(payload: dict) -> GmailMessage:
    """Pure parsing step, split out from fetch_message so it's testable without HTTP."""
    headers = {h["name"].lower(): h["value"] for h in payload.get("payload", {}).get("headers", [])}
    sender_display_name, sender_domain = _split_from_header(headers.get("from", ""))
    subject = headers.get("subject", "")

    body_text = _extract_body_text(payload.get("payload", {}))
    links = _extract_links(body_text)

    return GmailMessage(
        message_id=payload.get("id", ""),
        sender_domain=sender_domain,
        sender_display_name=sender_display_name,
        subject=subject,
        links=links,
        body_text=body_text,
    )


def _split_from_header(from_header: str) -> tuple[str, str]:
    """'"Chase Bank" <alerts@secure-chase-alerts.com>' -> ('Chase Bank', 'secure-chase-alerts.com')."""
    match = _FROM_HEADER_PATTERN.match(from_header)
    if match:
        display_name, _local, domain = match.groups()
        return display_name.strip(), domain.strip().lower()
    if "@" in from_header:
        return "", from_header.split("@")[-1].strip().lower()
    return "", ""


def _extract_body_text(part: dict) -> str:
    """Walk a (possibly multipart) Gmail message payload and decode all text parts."""
    mime_type = part.get("mimeType", "")
    body_data = part.get("body", {}).get("data")

    if body_data and mime_type in ("text/plain", "text/html"):
        try:
            padded = body_data + "=" * (-len(body_data) % 4)
            return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
        except (ValueError, UnicodeDecodeError):
            return ""

    texts = [_extract_body_text(sub) for sub in part.get("parts", [])]
    return "\n".join(t for t in texts if t)


def _extract_links(body_text: str) -> list[str]:
    """Best-effort link extraction from decoded email body text/HTML.

    Deliberately simple (regex, not a full HTML parser) — good enough to
    feed the heuristic engine's link checks. Revisit with a proper HTML
    parser if false negatives on obfuscated links become a real problem.
    """
    seen: list[str] = []
    for match in _LINK_PATTERN.finditer(body_text):
        link = match.group(1) or match.group(2)
        if link and link not in seen:
            seen.append(link)
    return seen
