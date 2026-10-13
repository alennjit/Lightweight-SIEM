"""Brute-force / password-spray throttling for login and invite redemption.

In-memory and per-process: fine for the single-process dev server and a
small pilot. Move to Redis (or the DB) before running multiple workers —
see docs/ROADMAP.md.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

WINDOW_SECONDS = 15 * 60
MAX_FAILURES_PER_ACCOUNT = 5   # targeted guessing against one email
MAX_FAILURES_PER_IP = 20       # spraying many emails from one address


class LoginThrottle:
    """Counts recent failures per key and blocks once a key exceeds its limit."""

    def __init__(self) -> None:
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _recent(self, key: str, now: float) -> deque[float]:
        attempts = self._failures[key]
        while attempts and now - attempts[0] > WINDOW_SECONDS:
            attempts.popleft()
        return attempts

    def is_blocked(self, account_key: str, ip_key: str) -> bool:
        """True if either the account or the client IP has too many recent failures."""
        now = time.monotonic()
        with self._lock:
            return (
                len(self._recent(f"acct:{account_key}", now)) >= MAX_FAILURES_PER_ACCOUNT
                or len(self._recent(f"ip:{ip_key}", now)) >= MAX_FAILURES_PER_IP
            )

    def record_failure(self, account_key: str, ip_key: str) -> None:
        """Count one failed attempt against both the account and the IP."""
        now = time.monotonic()
        with self._lock:
            self._recent(f"acct:{account_key}", now).append(now)
            self._recent(f"ip:{ip_key}", now).append(now)

    def record_success(self, account_key: str) -> None:
        """Clear the account's failures after a successful login (IP count is kept)."""
        with self._lock:
            self._failures.pop(f"acct:{account_key}", None)

    def reset(self) -> None:
        """Forget everything — for tests."""
        with self._lock:
            self._failures.clear()


login_throttle = LoginThrottle()
