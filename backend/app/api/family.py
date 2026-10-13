"""Consent-based linking between a protected person and their family monitors."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_protected
from app.api.schemas import FamilyLinkOut, InviteOut, RedeemInviteRequest
from app.core.db import get_db
from app.models.user import User
from app.services import accounts
from app.services.login_throttle import login_throttle

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/family", tags=["family"])


@router.post("/invites", response_model=InviteOut, status_code=201)
def create_invite(user: User = Depends(require_protected), db: Session = Depends(get_db)) -> InviteOut:
    """Protected person creates a one-time code to share. Sharing it is the consent step."""
    code, expires_at = accounts.create_invite(db, user)
    logger.info("Invite created by user_id=%s", user.id)  # the code itself is never logged
    return InviteOut(code=code, expires_at=expires_at)


@router.post("/invites/redeem", response_model=FamilyLinkOut)
def redeem_invite(
    body: RedeemInviteRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FamilyLinkOut:
    """Monitor enters a code to link to the person who shared it. Guessing is throttled."""
    ip_key = request.client.host if request.client else "unknown"
    account_key = f"invite:{user.id}"
    if login_throttle.is_blocked(account_key, ip_key):
        raise HTTPException(status_code=429, detail="Too many attempts. Please wait 15 minutes and try again.")
    try:
        link = accounts.redeem_invite(db, user, body.code)
    except accounts.AccountError as exc:
        login_throttle.record_failure(account_key, ip_key)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    protected = db.get(User, link.protected_user_id)
    logger.info("Family link created: monitor=%s protected=%s", user.id, link.protected_user_id)
    return FamilyLinkOut(id=link.id, person_id=protected.id, display_name=protected.display_name, role=protected.role, created_at=link.created_at)


@router.get("/links", response_model=list[FamilyLinkOut])
def list_links(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[FamilyLinkOut]:
    """Everyone linked to the signed-in user: their monitors, or the people they watch over."""
    return [
        FamilyLinkOut(id=link.id, person_id=other.id, display_name=other.display_name, role=other.role, created_at=link.created_at)
        for link, other in accounts.links_for(db, user)
    ]


@router.delete("/links/{link_id}", status_code=204)
def revoke_link(link_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Response:
    """Either person ends the link immediately."""
    try:
        accounts.revoke_link(db, user, link_id)
    except accounts.AccountError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    logger.info("Family link %s revoked by user_id=%s", link_id, user.id)
    return Response(status_code=204)
