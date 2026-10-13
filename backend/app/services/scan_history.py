"""Records content-free scan events and aggregates them into protection history."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.heuristics import RiskAssessment
from app.models.scan_event import ScanEvent

HIGH_RISK_MIN_SCORE = 8  # matches the dashboard's "Act now" tier


@dataclass
class DayCount:
    day: date
    checked: int = 0
    caught: int = 0


@dataclass
class ProtectionHistory:
    days: int
    first_scan_at: datetime | None
    emails_checked: int
    threats_caught: int
    high_risk: int
    links_flagged: int
    daily: list[DayCount] = field(default_factory=list)
    categories: list[tuple[str, int]] = field(default_factory=list)  # most common first


def record_scan(db: Session, owner_id: int, result: RiskAssessment, link_count: int) -> ScanEvent:
    """Add a ScanEvent for one scored email. The caller owns the commit."""
    event = ScanEvent(
        owner_id=owner_id,
        score=result.score,
        flagged=result.flagged,
        categories=list(result.categories),
        flagged_link_count=link_count if result.flagged else 0,
    )
    db.add(event)
    return event


def _as_utc(dt: datetime) -> datetime:
    """SQLite returns naive datetimes; everything here is stored as UTC."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def build_history(db: Session, owner_id: int | None, days: int, now: datetime | None = None) -> ProtectionHistory:
    """Aggregate one protected person's last `days` UTC calendar days (including today).

    owner_id None (a monitor with nobody linked yet) yields an all-zero history."""
    now = now or datetime.now(timezone.utc)
    today = now.date()
    start_day = today - timedelta(days=days - 1)
    window_start = datetime.combine(start_day, datetime.min.time(), tzinfo=timezone.utc)

    events = list(
        db.scalars(
            select(ScanEvent)
            .where(ScanEvent.owner_id == owner_id)
            .where(ScanEvent.scanned_at >= window_start.replace(tzinfo=None))
            .order_by(ScanEvent.scanned_at)
        )
    )
    first_scan = db.scalars(
        select(ScanEvent.scanned_at).where(ScanEvent.owner_id == owner_id).order_by(ScanEvent.scanned_at).limit(1)
    ).first()

    daily = {start_day + timedelta(days=offset): DayCount(start_day + timedelta(days=offset)) for offset in range(days)}
    categories: Counter[str] = Counter()
    caught = high_risk = links_flagged = 0

    for event in events:
        bucket = daily.get(_as_utc(event.scanned_at).date())
        if bucket is None:  # clock skew / future-dated row — ignore rather than crash
            continue
        bucket.checked += 1
        if event.flagged:
            bucket.caught += 1
            caught += 1
            links_flagged += event.flagged_link_count
            categories.update(event.categories)
            if event.score >= HIGH_RISK_MIN_SCORE:
                high_risk += 1

    return ProtectionHistory(
        days=days,
        first_scan_at=_as_utc(first_scan) if first_scan else None,
        emails_checked=sum(day.checked for day in daily.values()),
        threats_caught=caught,
        high_risk=high_risk,
        links_flagged=links_flagged,
        daily=list(daily.values()),
        categories=categories.most_common(),
    )
