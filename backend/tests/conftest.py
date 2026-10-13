"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from app.core.config import Settings, get_settings


@pytest.fixture(autouse=True)
def _isolate_settings_from_dotenv(monkeypatch):
    """Stop Settings from reading the developer's real backend/.env during tests.

    Without this, real secrets (SECRET_KEY, OAuth client credentials) leak into
    the test run and make "unconfigured" code paths untestable. Tests that need
    a value must set it explicitly with monkeypatch.setenv.
    """
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
