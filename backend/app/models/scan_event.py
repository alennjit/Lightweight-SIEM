"""ScanEvent — one row per email the detection engine checked, flagged or not.

Powers the "protection history" view (emails checked vs. threats caught over
time). Deliberately content-free per docs/PRIVACY_AND_CONSENT.md's data
minimization rule: no sender, subject, body or links — only when it was
checked, the score, and which threat categories fired. Flagged messages'
details live on Alert, not here.
"""

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base


class ScanEvent(Base):
    __tablename__ = "scan_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), index=True
    )
    score: Mapped[int] = mapped_column(Integer)
    flagged: Mapped[bool] = mapped_column(Boolean)
    categories: Mapped[list[str]] = mapped_column(JSON, default=list)
    # Links in a flagged message — counted, never stored here.
    flagged_link_count: Mapped[int] = mapped_column(Integer, default=0)
