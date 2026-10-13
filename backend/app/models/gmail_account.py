"""GmailAccount — one OAuth-connected Gmail inbox.

Owned by the protected person who connected it (app/models/user.py).
Monitors never see tokens — only alerts derived from the inbox.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class GmailAccount(Base):
    __tablename__ = "gmail_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)  # protected person
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)

    # Fernet-encrypted at rest — see app/core/security.py. Never log these values.
    encrypted_access_token: Mapped[str] = mapped_column(Text)
    encrypted_refresh_token: Mapped[str] = mapped_column(Text)
    token_expires_at: Mapped[datetime] = mapped_column(DateTime)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_ingested_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
