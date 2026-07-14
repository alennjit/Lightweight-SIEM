"""Logging setup. Use logging (not print) for anything that runs in production."""

import logging

from app.core.config import get_settings


def configure_logging() -> None:
    """Configure root logging once at app startup, level driven by LOG_LEVEL env var."""
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
