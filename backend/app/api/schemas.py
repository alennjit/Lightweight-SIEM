"""Pydantic request/response schemas for the API layer."""

from datetime import date, datetime

from pydantic import BaseModel, Field

from app.core.passwords import MAX_LENGTH as PASSWORD_MAX


class EmailScoreRequest(BaseModel):
    sender_domain: str
    subject: str
    links: list[str] = Field(default_factory=list)
    body: str = ""
    sender_display_name: str = ""


class EmailScoreResponse(BaseModel):
    score: int
    flagged: bool
    rationale: str
    signals: list[str]
    categories: list[str] = Field(default_factory=list)
    alert_id: int | None = None


class AlertOut(BaseModel):
    id: int
    sender_domain: str
    subject: str
    links: list[str]
    score: int
    rationale: str
    created_at: datetime

    model_config = {"from_attributes": True}


class DailyCountOut(BaseModel):
    date: date
    checked: int
    caught: int


class CategoryCountOut(BaseModel):
    category: str
    count: int


class ProtectionHistoryOut(BaseModel):
    """Aggregates only — no message content ever appears in this response."""

    days: int
    first_scan_at: datetime | None
    emails_checked: int
    threats_caught: int
    high_risk: int
    links_flagged: int
    daily: list[DailyCountOut]
    categories: list[CategoryCountOut]


class RegisterRequest(BaseModel):
    email: str = Field(max_length=255)  # format checked in services.accounts
    password: str = Field(max_length=PASSWORD_MAX)
    display_name: str = Field(min_length=1, max_length=80)
    role: str  # "protected" | "monitor" — validated in services.accounts


class LoginRequest(BaseModel):
    email: str = Field(max_length=255)
    password: str = Field(max_length=PASSWORD_MAX)


class PersonOut(BaseModel):
    id: int
    display_name: str


class MeOut(BaseModel):
    """Never includes the password hash or session data."""

    id: int
    email: str
    display_name: str
    role: str
    people: list[PersonOut]  # protected people this user can view


class InviteOut(BaseModel):
    code: str  # shown once; only a hash is stored
    expires_at: datetime


class RedeemInviteRequest(BaseModel):
    code: str = Field(min_length=4, max_length=20)


class FamilyLinkOut(BaseModel):
    id: int
    person_id: int  # the other person on the link
    display_name: str
    role: str
    created_at: datetime


class GmailAccountOut(BaseModel):
    """Never includes token fields — those never leave the backend."""

    id: int
    email: str
    created_at: datetime
    last_ingested_at: datetime | None

    model_config = {"from_attributes": True}


class IngestResponse(BaseModel):
    account_email: str
    messages_checked: int
    alerts_created: list[AlertOut]
