"""Password hashing and policy.

Uses scrypt from the standard library (memory-hard, so GPU cracking of a
leaked hash table is expensive) — no third-party dependency. Hashes are
self-describing (`scrypt$n$r$p$salt$hash`) so parameters can be raised
later without invalidating existing passwords.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

_N = 2**15  # CPU/memory cost — ~32 MB per hash
_R = 8
_P = 1
_KEY_LEN = 32
_SALT_LEN = 16
_MAXMEM = 64 * 1024 * 1024

MIN_LENGTH = 12
MAX_LENGTH = 128  # bounds hashing cost per request

# A short blocklist of the most common long-enough passwords. Not a substitute
# for a breached-password check (e.g. HIBP k-anonymity), which needs a network
# call — see docs/ROADMAP.md.
_COMMON_PASSWORDS = frozenset(
    {
        "password1234", "123456789012", "qwertyuiop12", "iloveyou1234", "passwordpassword",
        "letmein12345", "welcome12345", "administrator", "1q2w3e4r5t6y", "qwerty123456",
        "password12345", "123456123456", "abc123456789", "football1234", "baseball1234",
    }
)


class PasswordPolicyError(ValueError):
    """Raised with a user-facing message when a new password is not acceptable."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, maxmem=_MAXMEM, dklen=_KEY_LEN)


def check_policy(password: str, email: str) -> None:
    """Raise PasswordPolicyError if the password is too weak to accept."""
    if len(password) < MIN_LENGTH:
        raise PasswordPolicyError(f"Use at least {MIN_LENGTH} characters.")
    if len(password) > MAX_LENGTH:
        raise PasswordPolicyError(f"Use at most {MAX_LENGTH} characters.")
    lowered = password.lower()
    if lowered in _COMMON_PASSWORDS or len(set(lowered)) < 4:
        raise PasswordPolicyError("That password is too easy to guess. Try a short phrase of a few words.")
    local_part = email.split("@", 1)[0].lower()
    if len(local_part) >= 4 and local_part in lowered:
        raise PasswordPolicyError("Your password shouldn't contain your email address.")


def hash_password(password: str) -> str:
    """Hash a password with a fresh random salt."""
    salt = secrets.token_bytes(_SALT_LEN)
    digest = _derive(password, salt, _N, _R, _P)
    return f"scrypt${_N}${_R}${_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of a password against a stored hash. False on any malformed hash."""
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        candidate = _derive(password[:MAX_LENGTH], _unb64(salt), int(n), int(r), int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, _unb64(digest))


# Verified against when an email isn't registered, so a login for an unknown
# address takes as long as one for a real account (no timing-based enumeration).
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))
