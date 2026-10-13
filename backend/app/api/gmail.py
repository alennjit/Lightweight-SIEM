"""Gmail OAuth connect flow, plus manually-triggered ingestion.

Only the protected person can connect their own inbox. CSRF protection on
the OAuth round-trip uses a short-lived httponly cookie holding the `state`
value; the session cookie (SameSite=Lax) identifies who is connecting.
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_protected
from app.api.schemas import GmailAccountOut, IngestResponse
from app.core.config import Settings, get_settings
from app.core.db import get_db
from app.core.security import encrypt_token
from app.integrations import gmail_client
from app.models.gmail_account import GmailAccount
from app.models.user import User
from app.services.email_ingestion import ingest_recent_messages

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["gmail"])

_STATE_COOKIE = "oauth_state"


@router.get("/auth/gmail/authorize")
def gmail_authorize(
    response: Response,
    _: User = Depends(require_protected),
    settings: Settings = Depends(get_settings),
) -> RedirectResponse:
    """Redirect the user to Google's consent screen."""
    state = secrets.token_urlsafe(32)
    try:
        url = gmail_client.build_authorization_url(settings, state)
    except gmail_client.GmailApiError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    redirect = RedirectResponse(url)
    redirect.set_cookie(_STATE_COOKIE, state, httponly=True, samesite="lax", max_age=600)
    return redirect


@router.get("/auth/gmail/callback", response_model=GmailAccountOut)
def gmail_callback(
    request: Request,
    code: str,
    state: str,
    user: User = Depends(require_protected),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> GmailAccountOut:
    """Exchange the authorization code for tokens and store the connected account."""
    cookie_state = request.cookies.get(_STATE_COOKIE)
    if not cookie_state or not secrets.compare_digest(cookie_state, state):
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state.")

    try:
        tokens = gmail_client.exchange_code_for_tokens(settings, code)
        email = gmail_client.fetch_account_email(tokens.access_token)
    except gmail_client.GmailApiError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    expires_at = datetime.now(timezone.utc) + timedelta(seconds=tokens.expires_in)
    account = db.scalar(select(GmailAccount).where(GmailAccount.email == email))
    if account is None:
        account = GmailAccount(email=email, owner_id=user.id)
    elif account.owner_id != user.id:
        raise HTTPException(status_code=409, detail="That inbox is already connected to a different account.")

    account.encrypted_access_token = encrypt_token(tokens.access_token)
    account.encrypted_refresh_token = encrypt_token(tokens.refresh_token)
    account.token_expires_at = expires_at
    db.add(account)
    db.commit()
    db.refresh(account)

    logger.info("Gmail account connected: id=%s", account.id)
    return account


@router.get("/gmail/accounts", response_model=list[GmailAccountOut])
def list_gmail_accounts(user: User = Depends(require_protected), db: Session = Depends(get_db)) -> list[GmailAccount]:
    """List the signed-in person's connected inboxes. Never includes token fields."""
    return list(
        db.scalars(
            select(GmailAccount).where(GmailAccount.owner_id == user.id).order_by(GmailAccount.created_at.desc())
        )
    )


@router.post("/gmail/accounts/{account_id}/ingest", response_model=IngestResponse)
def trigger_ingest(
    account_id: int,
    user: User = Depends(require_protected),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> IngestResponse:
    """Manually trigger a pull of recent messages for one of the signed-in person's inboxes."""
    account = db.get(GmailAccount, account_id)
    if account is None or account.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Gmail account not found.")

    try:
        result = ingest_recent_messages(db, settings, account)
    except gmail_client.GmailApiError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return IngestResponse(
        account_email=account.email,
        messages_checked=result.messages_checked,
        alerts_created=result.alerts,
    )
