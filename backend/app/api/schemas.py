"""Pydantic request/response schemas for the API layer."""

from datetime import datetime

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
