"""Endpoint for listing stored alerts — consumed by the monitor dashboard."""

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_viewed_person
from app.api.schemas import AlertOut
from app.core.db import get_db
from app.models.alert import Alert
from app.models.user import User

router = APIRouter(prefix="/api/v1", tags=["alerts"])


@router.get("/alerts", response_model=list[AlertOut])
def list_alerts(person: User | None = Depends(get_viewed_person), db: Session = Depends(get_db)) -> list[Alert]:
    """Alerts for one protected person the caller may see, most recent first."""
    if person is None:
        return []
    return list(db.scalars(select(Alert).where(Alert.owner_id == person.id).order_by(Alert.created_at.desc())))
