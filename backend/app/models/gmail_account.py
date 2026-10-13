"""GmailAccount — one OAuth-connected Gmail inbox.

Deliberately not a full `User`/auth model — that comes with the family
linking + consent flow (see CONTRIBUTING.md "Architecture"), which isn't
built yet. This is scoped to just proving the OAuth + ingestion path works
end to end. `FamilyLink` will reference this by id once it exists.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class GmailAccount(Base):
    __tablename__ = "gmail_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)

    # Fernet-encrypted at rest — see app/core/security.py. Never log these values.
    encrypted_access_token: Mapped[str] = mapped_column(Text)
    encrypted_refresh_token: Mapped[str] = mapped_column(Text)
    token_expires_at: Mapped[datetime] = mapped_column(DateTime)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_ingested_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
