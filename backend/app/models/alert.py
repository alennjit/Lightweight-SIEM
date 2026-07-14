"""Alert — a phishing-flagged email, created when the detection engine's score crosses the flag threshold."""

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sender_domain: Mapped[str] = mapped_column(String(255))
    subject: Mapped[str] = mapped_column(String(998))  # RFC 5322 max subject length
    links: Mapped[list[str]] = mapped_column(JSON, default=list)
    score: Mapped[int] = mapped_column(Integer)
    rationale: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
