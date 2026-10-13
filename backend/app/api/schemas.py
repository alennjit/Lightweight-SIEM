"""Pydantic request/response schemas for the API layer."""

from datetime import date, datetime

from pydantic import BaseModel, Field


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
