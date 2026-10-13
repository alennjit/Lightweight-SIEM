"""Protection history endpoint — how much has been checked and caught over time."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.schemas import CategoryCountOut, DailyCountOut, ProtectionHistoryOut
from app.core.db import get_db
from app.services.scan_history import build_history

router = APIRouter(prefix="/api/v1", tags=["stats"])


@router.get("/stats/history", response_model=ProtectionHistoryOut)
def protection_history(
    days: int = Query(default=30, ge=1, le=365),
    db: Session = Depends(get_db),
) -> ProtectionHistoryOut:
    """Daily emails-checked vs. threats-caught counts plus a breakdown by threat category."""
    history = build_history(db, days)
    return ProtectionHistoryOut(
        days=history.days,
        first_scan_at=history.first_scan_at,
        emails_checked=history.emails_checked,
        threats_caught=history.threats_caught,
        high_risk=history.high_risk,
        links_flagged=history.links_flagged,
        daily=[DailyCountOut(date=d.day, checked=d.checked, caught=d.caught) for d in history.daily],
        categories=[CategoryCountOut(category=name, count=count) for name, count in history.categories],
    )
