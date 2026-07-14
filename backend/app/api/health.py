"""Health check endpoint — the only route that requires no auth."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def health_check() -> dict[str, str]:
    """Return service status for uptime checks and load balancers."""
    return {"status": "ok"}
