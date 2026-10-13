"""FastAPI application entry point."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.alerts import router as alerts_router
from app.api.auth import router as auth_router
from app.api.emails import router as emails_router
from app.api.family import router as family_router
from app.api.gmail import router as gmail_router
from app.api.health import router as health_router
from app.api.stats import router as stats_router
from app.core.config import get_settings
from app.core.db import Base, engine
from app.core.logging_config import configure_logging
from app.core.origin_check import OriginCheckMiddleware
from app.models import alert as _alert  # noqa: F401  (registers table with Base.metadata)
from app.models import gmail_account as _gmail_account  # noqa: F401  (registers table with Base.metadata)
from app.models import scan_event as _scan_event  # noqa: F401  (registers table with Base.metadata)
from app.models import user as _user  # noqa: F401  (registers tables with Base.metadata)

configure_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Create DB tables (dev convenience — replace with Alembic migrations before production) and log startup."""
    Base.metadata.create_all(bind=engine)
    logger.info("Lightweight SIEM backend starting up")
    yield


app = FastAPI(title="Lightweight SIEM", version="0.1.0", lifespan=lifespan)

_allowed_origins = get_settings().allowed_origin_list

# Added before CORS so CORS ends up outermost (preflights are answered first).
app.add_middleware(OriginCheckMiddleware, allowed_origins=_allowed_origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,  # the session cookie; requires explicit origins, never "*"
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
)

app.include_router(health_router)
app.include_router(auth_router)
app.include_router(family_router)
app.include_router(emails_router)
app.include_router(alerts_router)
app.include_router(gmail_router)
app.include_router(stats_router)
