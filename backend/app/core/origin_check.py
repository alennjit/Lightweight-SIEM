"""CSRF defence for cookie-authenticated, state-changing requests.

Browsers attach an Origin header to every cross-origin request and to
same-origin fetch() POSTs. If a state-changing request carries an Origin
that isn't our dashboard, a hostile page is trying to ride the user's
session cookie — reject it. Requests with no Origin come from non-browser
clients (curl, tests), which can't carry a victim's cookies anyway.
This complements the SameSite=Lax session cookie.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class OriginCheckMiddleware(BaseHTTPMiddleware):
    """Reject unsafe-method requests whose Origin isn't in the allow-list."""

    def __init__(self, app, allowed_origins: list[str]) -> None:
        super().__init__(app)
        self._allowed = frozenset(allowed_origins)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Pass safe methods and allowed origins through; 403 everything else."""
        origin = request.headers.get("origin")
        if request.method not in _SAFE_METHODS and origin is not None and origin not in self._allowed:
            return JSONResponse(status_code=403, content={"detail": "Cross-site request blocked."})
        return await call_next(request)
