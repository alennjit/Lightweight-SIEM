"""Endpoint for listing stored alerts — consumed by the monitor dashboard."""

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schemas import AlertOut
from app.core.db import get_db
from app.models.alert import Alert

router = APIRouter(prefix="/api/v1", tags=["alerts"])


@router.get("/alerts", response_model=list[AlertOut])
def list_alerts(db: Session = Depends(get_db)) -> list[Alert]:
    """Return all stored alerts, most recent first."""
    return list(db.scalars(select(Alert).order_by(Alert.created_at.desc())))
