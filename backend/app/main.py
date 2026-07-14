"""FastAPI application entry point."""

import logging

from fastapi import FastAPI

from app.api.health import router as health_router
from app.core.logging_config import configure_logging

configure_logging()
logger = logging.getLogger(__name__)

app = FastAPI(title="Lightweight SIEM", version="0.1.0")
app.include_router(health_router)


@app.on_event("startup")
def on_startup() -> None:
    """Log service startup for visibility in deployment logs."""
    logger.info("Lightweight SIEM backend starting up")
