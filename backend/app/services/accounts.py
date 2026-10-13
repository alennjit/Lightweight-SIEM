"""Account, session and family-link operations. API routes stay thin; the
rules (who can see whom, how invites work) live here so they're testable
without HTTP."""

from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.passwords import DUMMY_HASH, PasswordPolicyError, check_policy, hash_password, verify_password
from app.models.user import ROLE_MONITOR, ROLE_PROTECTED, ROLES, FamilyInvite, FamilyLink, User, UserSession

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
INVITE_TTL = timedelta(days=7)
# No 0/O/1/I/L — codes are read aloud over the phone between relatives.
_INVITE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_INVITE_LENGTH = 8


class AccountError(ValueError):
    """A user-facing reason an account operation was refused."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime) -> datetime:
    """SQLite returns naive datetimes; everything is stored as UTC."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def normalize_email(email: str) -> str:
    """Lowercase and trim so 'Mom@Example.com ' and 'mom@example.com' are one account."""
    return email.strip().lower()


# --- Users -----------------------------------------------------------------


def create_user(db: Session, email: str, password: str, display_name: str, role: str) -> User:
    """Register a user after enforcing password policy. Raises AccountError."""
    email = normalize_email(email)
    if not _EMAIL_RE.match(email):
        raise AccountError("Enter a valid email address.")
    if role not in ROLES:
        raise AccountError("Choose who this account is for.")
    if not display_name.strip():
        raise AccountError("Enter a name.")
    try:
        check_policy(password, email)
    except PasswordPolicyError as exc:
        raise AccountError(str(exc)) from exc
    user = User(email=email, display_name=display_name.strip(), role=role, password_hash=hash_password(password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise AccountError("An account with that email already exists.") from exc
    db.refresh(user)
    return user


def authenticate(db: Session, email: str, password: str) -> User | None:
    """Return the user if the password matches. Same work is done for unknown emails."""
    user = db.scalar(select(User).where(User.email == normalize_email(email)))
    if user is None:
        verify_password(password, DUMMY_HASH)
        return None
    return user if verify_password(password, user.password_hash) else None


# --- Sessions --------------------------------------------------------------


def create_session(db: Session, user: User, ttl: timedelta) -> str:
    """Start a session and return the raw token for the cookie. Only its hash is stored."""
    token = secrets.token_urlsafe(32)
    db.add(UserSession(token_hash=_sha256(token), user_id=user.id, expires_at=_utcnow() + ttl))
    db.commit()
    return token


def user_for_session(db: Session, token: str) -> User | None:
    """Resolve a cookie token to its user, deleting the session if it has expired."""
    session = db.scalar(select(UserSession).where(UserSession.token_hash == _sha256(token)))
    if session is None:
        return None
    if _as_utc(session.expires_at) <= _utcnow():
        db.delete(session)
        db.commit()
        return None
    return db.get(User, session.user_id)


def end_session(db: Session, token: str) -> None:
    """Delete the session for this token, if any."""
    db.execute(delete(UserSession).where(UserSession.token_hash == _sha256(token)))
    db.commit()


# --- Family links ----------------------------------------------------------


def people_visible_to(db: Session, user: User) -> list[User]:
    """Protected people whose data this user may see: themselves, or everyone linked to a monitor."""
    if user.role == ROLE_PROTECTED:
        return [user]
    return list(
        db.scalars(
            select(User)
            .join(FamilyLink, FamilyLink.protected_user_id == User.id)
            .where(FamilyLink.monitor_user_id == user.id)
            .order_by(FamilyLink.created_at)
        )
    )


def create_invite(db: Session, protected_user: User) -> tuple[str, datetime]:
    """Issue a single-use invite code. Returns (code shown once, expiry)."""
    if protected_user.role != ROLE_PROTECTED:
        raise AccountError("Only the person being protected can invite a family member.")
    raw = "".join(secrets.choice(_INVITE_ALPHABET) for _ in range(_INVITE_LENGTH))
    code = f"{raw[:4]}-{raw[4:]}"
    expires_at = _utcnow() + INVITE_TTL
    db.add(FamilyInvite(code_hash=_sha256(raw), protected_user_id=protected_user.id, expires_at=expires_at))
    db.commit()
    return code, expires_at


def redeem_invite(db: Session, monitor: User, code: str) -> FamilyLink:
    """Link a monitor to the protected person who issued the code. Raises AccountError."""
    if monitor.role != ROLE_MONITOR:
        raise AccountError("Only a family-member account can use an invite code.")
    raw = "".join(ch for ch in code.upper() if ch.isalnum())
    invite = db.scalar(select(FamilyInvite).where(FamilyInvite.code_hash == _sha256(raw)))
    if invite is None or invite.used_at is not None or _as_utc(invite.expires_at) <= _utcnow():
        raise AccountError("That code isn't valid. Codes work once and expire after 7 days.")

    existing = db.scalar(
        select(FamilyLink).where(
            FamilyLink.monitor_user_id == monitor.id,
            FamilyLink.protected_user_id == invite.protected_user_id,
        )
    )
    invite.used_at = _utcnow()
    if existing is not None:
        db.commit()
        return existing
    link = FamilyLink(monitor_user_id=monitor.id, protected_user_id=invite.protected_user_id)
    db.add(link)
    db.commit()
    db.refresh(link)
    return link


def links_for(db: Session, user: User) -> list[tuple[FamilyLink, User]]:
    """Each link involving this user, paired with the *other* person on it."""
    if user.role == ROLE_PROTECTED:
        rows = db.execute(
            select(FamilyLink, User)
            .join(User, User.id == FamilyLink.monitor_user_id)
            .where(FamilyLink.protected_user_id == user.id)
            .order_by(FamilyLink.created_at)
        )
    else:
        rows = db.execute(
            select(FamilyLink, User)
            .join(User, User.id == FamilyLink.protected_user_id)
            .where(FamilyLink.monitor_user_id == user.id)
            .order_by(FamilyLink.created_at)
        )
    return [(link, other) for link, other in rows]


def revoke_link(db: Session, user: User, link_id: int) -> None:
    """Either person on a link can end it, immediately. Raises AccountError if not theirs."""
    link = db.get(FamilyLink, link_id)
    if link is None or user.id not in (link.monitor_user_id, link.protected_user_id):
        raise AccountError("Link not found.")
    db.delete(link)
    db.commit()
