"""FastAPI application entry point."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.health import router as health_router
from app.core.logging_config import configure_logging

configure_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Log service startup for visibility in deployment logs."""
    logger.info("Lightweight SIEM backend starting up")
    yield


app = FastAPI(title="Lightweight SIEM", version="0.1.0", lifespan=lifespan)
app.include_router(health_router)
