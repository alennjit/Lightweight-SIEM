"""Shared pytest fixtures."""

from __future__ import annotations

from collections.abc import Callable, Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.core.db import Base, get_db
from app.main import app
from app.models.user import ROLE_MONITOR, ROLE_PROTECTED
from app.services.login_throttle import login_throttle

TEST_PASSWORD = "correct horse battery staple"


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


@pytest.fixture(autouse=True)
def _reset_login_throttle():
    """The throttle is process-global; don't let one test's failures lock out another."""
    login_throttle.reset()
    yield
    login_throttle.reset()


@pytest.fixture()
def session_factory(tmp_path) -> Generator[sessionmaker, None, None]:
    """A fresh SQLite file per test, wired into the app in place of dev.db.

    The app's lifespan (which would touch dev.db) never runs because TestClient
    isn't used as a context manager.
    """
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_get_db() -> Generator[Session, None, None]:
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield factory
    finally:
        app.dependency_overrides.clear()


@pytest.fixture()
def db(session_factory) -> Generator[Session, None, None]:
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def make_client(session_factory) -> Callable[[], TestClient]:
    """Each call returns an independent browser-like client (own cookie jar).

    HTTPS base URL because the session cookie is Secure.
    """
    return lambda: TestClient(app, base_url="https://testserver")


def register(client: TestClient, email: str, role: str, name: str = "Test User") -> dict:
    """Sign up through the real API (which also signs the client in)."""
    response = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": TEST_PASSWORD, "display_name": name, "role": role},
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.fixture()
def client(make_client) -> TestClient:
    """A client signed in as a protected person — the owner of the data most tests touch."""
    c = make_client()
    register(c, "margaret@example.test", ROLE_PROTECTED, "Margaret")
    return c


@pytest.fixture()
def monitor_client(make_client) -> TestClient:
    """A client signed in as a family monitor with nobody linked yet."""
    c = make_client()
    register(c, "daniel@example.test", ROLE_MONITOR, "Daniel")
    return c
