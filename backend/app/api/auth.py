"""Sign up, sign in, sign out, and "who am I"."""

from __future__ import annotations

import logging
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.api.deps import SESSION_COOKIE, get_current_user
from app.api.schemas import LoginRequest, MeOut, PersonOut, RegisterRequest
from app.core.config import Settings, get_settings
from app.core.db import get_db
from app.models.user import User
from app.services import accounts
from app.services.login_throttle import login_throttle

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _start_session(response: Response, db: Session, user: User, settings: Settings) -> None:
    ttl = timedelta(hours=settings.session_ttl_hours)
    token = accounts.create_session(db, user, ttl)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=int(ttl.total_seconds()),
        httponly=True,  # unreadable by JavaScript, so XSS can't steal it
        secure=settings.session_cookie_secure,
        samesite="lax",  # Lax, not Strict: Google's OAuth redirect back to us must carry it
        path="/",
    )


def _me(db: Session, user: User) -> MeOut:
    return MeOut(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=user.role,
        people=[PersonOut(id=p.id, display_name=p.display_name) for p in accounts.people_visible_to(db, user)],
    )


@router.post("/register", response_model=MeOut, status_code=201)
def register(
    body: RegisterRequest,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> MeOut:
    """Create an account and sign it in."""
    try:
        user = accounts.create_user(db, body.email, body.password, body.display_name, body.role)
    except accounts.AccountError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    logger.info("Account created: user_id=%s role=%s", user.id, user.role)
    _start_session(response, db, user, settings)
    return _me(db, user)


@router.post("/login", response_model=MeOut)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> MeOut:
    """Check credentials and set the session cookie. One generic error for every failure."""
    account_key = accounts.normalize_email(body.email)
    ip_key = _client_ip(request)
    if login_throttle.is_blocked(account_key, ip_key):
        logger.warning("Login throttled for ip=%s", ip_key)  # never log the submitted email/password
        raise HTTPException(status_code=429, detail="Too many attempts. Please wait 15 minutes and try again.")

    user = accounts.authenticate(db, body.email, body.password)
    if user is None:
        login_throttle.record_failure(account_key, ip_key)
        logger.info("Failed login from ip=%s", ip_key)
        raise HTTPException(status_code=401, detail="That email and password don't match.")

    login_throttle.record_success(account_key)
    _start_session(response, db, user, settings)
    logger.info("Login: user_id=%s", user.id)
    return _me(db, user)


@router.post("/logout", status_code=204)
def logout(request: Request, db: Session = Depends(get_db), settings: Settings = Depends(get_settings)) -> Response:
    """End the session server-side and clear the cookie."""
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        accounts.end_session(db, token)
    response = Response(status_code=204)
    response.delete_cookie(SESSION_COOKIE, path="/", secure=settings.session_cookie_secure, httponly=True, samesite="lax")
    return response


@router.get("/me", response_model=MeOut)
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> MeOut:
    """The signed-in user and the protected people they can see."""
    return _me(db, user)
