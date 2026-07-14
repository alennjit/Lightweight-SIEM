"""FastAPI application entry point."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.alerts import router as alerts_router
from app.api.emails import router as emails_router
from app.api.health import router as health_router
from app.core.db import Base, engine
from app.core.logging_config import configure_logging
from app.models import alert as _alert  # noqa: F401  (registers table with Base.metadata)

configure_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create DB tables (dev convenience — replace with Alembic migrations before production) and log startup."""
    Base.metadata.create_all(bind=engine)
    logger.info("Lightweight SIEM backend starting up")
    yield


app = FastAPI(title="Lightweight SIEM", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(emails_router)
app.include_router(alerts_router)
