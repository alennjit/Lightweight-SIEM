"""Accounts, sessions, and the consent-based family link between them.

Two roles (docs/PRIVACY_AND_CONSENT.md):
- protected: the person whose inbox is checked. Owns alerts, scan events
  and connected Gmail accounts.
- monitor: a family member who receives alerts for the protected people
  linked to them.

A link only exists because the protected person created an invite code and
shared it — that is the consent step — and either side can revoke it.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base

ROLE_PROTECTED = "protected"
ROLE_MONITOR = "monitor"
ROLES = (ROLE_PROTECTED, ROLE_MONITOR)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)  # stored lowercased
    display_name: Mapped[str] = mapped_column(String(80))
    role: Mapped[str] = mapped_column(String(16))
    password_hash: Mapped[str] = mapped_column(String(255))  # never returned by any API
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)


class UserSession(Base):
    """A login session. Only a SHA-256 of the cookie token is stored, so a
    database leak doesn't hand out live sessions."""

    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class FamilyInvite(Base):
    """A single-use code a protected person shares with a family member."""

    __tablename__ = "family_invites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    protected_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class FamilyLink(Base):
    """An active monitor -> protected person relationship. Deleted on revoke."""

    __tablename__ = "family_links"
    __table_args__ = (UniqueConstraint("monitor_user_id", "protected_user_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    monitor_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    protected_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)
