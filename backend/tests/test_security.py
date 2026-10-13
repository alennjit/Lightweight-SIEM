"""Tests for app/core/security.py token encryption helpers."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from app.core import security
from app.core.config import get_settings


@pytest.fixture(autouse=True)
def _fresh_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_encrypt_decrypt_round_trip(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", Fernet.generate_key().decode())

    ciphertext = security.encrypt_token("super-secret-refresh-token")
    assert ciphertext != "super-secret-refresh-token"
    assert security.decrypt_token(ciphertext) == "super-secret-refresh-token"


def test_encrypt_raises_without_secret_key(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(security.TokenEncryptionError):
        security.encrypt_token("anything")


def test_decrypt_raises_on_tampered_value(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", Fernet.generate_key().decode())
    ciphertext = security.encrypt_token("value")
    with pytest.raises(security.TokenEncryptionError):
        security.decrypt_token(ciphertext[:-2] + "xx")


def test_decrypt_raises_with_wrong_key(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", Fernet.generate_key().decode())
    ciphertext = security.encrypt_token("value")

    monkeypatch.setenv("SECRET_KEY", Fernet.generate_key().decode())
    get_settings.cache_clear()
    with pytest.raises(security.TokenEncryptionError):
        security.decrypt_token(ciphertext)
