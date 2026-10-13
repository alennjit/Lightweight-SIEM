"""Endpoint for scoring a submitted email against the heuristic detection engine."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_viewed_person
from app.api.schemas import EmailScoreRequest, EmailScoreResponse
from app.core.db import get_db
from app.detection.heuristics import score_email
from app.models.alert import Alert
from app.models.user import User
from app.services.scan_history import record_scan

router = APIRouter(prefix="/api/v1", tags=["emails"])


@router.post("/emails/score", response_model=EmailScoreResponse)
def score_email_endpoint(
    request: EmailScoreRequest,
    person: User | None = Depends(get_viewed_person),
    db: Session = Depends(get_db),
) -> EmailScoreResponse:
    """Score a test email for one protected person, recording a scan event and an Alert if flagged."""
    if person is None:
        raise HTTPException(status_code=400, detail="Link to someone first — there's no inbox to test against.")
    result = score_email(
        sender_domain=request.sender_domain,
        subject=request.subject,
        links=request.links,
        body=request.body,
        sender_display_name=request.sender_display_name,
    )

    record_scan(db, person.id, result, link_count=len(request.links))

    alert_id = None
    if result.flagged:
        alert = Alert(
            owner_id=person.id,
            sender_domain=request.sender_domain,
            subject=request.subject,
            links=request.links,
            score=result.score,
            rationale=result.rationale,
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        alert_id = alert.id
    else:
        db.commit()

    return EmailScoreResponse(
        score=result.score,
        flagged=result.flagged,
        rationale=result.rationale,
        signals=result.signals,
        categories=result.categories,
        alert_id=alert_id,
    )
