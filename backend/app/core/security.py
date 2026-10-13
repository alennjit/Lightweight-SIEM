"""Encryption helpers for data that must never be stored in plaintext —
OAuth access/refresh tokens, per CONTRIBUTING.md's "encrypted at rest,
never logged" rule.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings


class TokenEncryptionError(RuntimeError):
    """Raised when SECRET_KEY is missing/invalid or a token fails to decrypt."""


def _fernet() -> Fernet:
    settings = get_settings()
    if not settings.secret_key:
        raise TokenEncryptionError(
            "SECRET_KEY is not configured — cannot encrypt/decrypt OAuth tokens. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; "
            'print(Fernet.generate_key().decode())"'
        )
    try:
        return Fernet(settings.secret_key.encode())
    except ValueError as exc:
        raise TokenEncryptionError("SECRET_KEY is not a valid Fernet key.") from exc


def encrypt_token(plaintext: str) -> str:
    """Encrypt a token for storage. Never log or return the plaintext alongside this."""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_token(ciphertext: str) -> str:
    """Decrypt a stored token. Raises TokenEncryptionError on a bad key or tampered value."""
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise TokenEncryptionError("Stored token could not be decrypted — key mismatch or corruption.") from exc
