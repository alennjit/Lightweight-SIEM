"""Shared request dependencies: who is calling, and whose data they may see."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.models.user import ROLE_PROTECTED, User
from app.services.accounts import people_visible_to, user_for_session

SESSION_COOKIE = "lwsiem_session"


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """The signed-in user, or 401. The session token only ever travels in an httpOnly cookie."""
    token = request.cookies.get(SESSION_COOKIE)
    user = user_for_session(db, token) if token else None
    if user is None:
        raise HTTPException(status_code=401, detail="Please sign in.")
    return user


def require_protected(user: User = Depends(get_current_user)) -> User:
    """Only the protected person themselves (e.g. connecting their own inbox)."""
    if user.role != ROLE_PROTECTED:
        raise HTTPException(status_code=403, detail="Only the person being protected can do this.")
    return user


def get_viewed_person(
    person_id: int | None = Query(default=None, description="Protected person to view; defaults to the first one you can see."),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User | None:
    """Resolve which protected person's data to return, enforcing family-link access.

    Returns None when a monitor has no linked people yet (callers return
    empty results). Asking for someone you aren't linked to is a 404, not a
    403, so the API doesn't confirm which user ids exist.
    """
    visible = people_visible_to(db, user)
    if person_id is None:
        return visible[0] if visible else None
    for person in visible:
        if person.id == person_id:
            return person
    raise HTTPException(status_code=404, detail="Person not found.")
