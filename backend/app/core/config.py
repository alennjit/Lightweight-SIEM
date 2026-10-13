"""Application configuration loaded from environment variables."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration. All values come from the environment or .env — never hardcoded."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    log_level: str = "INFO"
    database_url: str = "sqlite:///./dev.db"

    anthropic_api_key: str | None = None

    google_oauth_client_id: str | None = None
    google_oauth_client_secret: str | None = None
    google_oauth_redirect_uri: str = "http://localhost:8000/api/v1/auth/gmail/callback"

    # Fernet key (44-char urlsafe base64) used to encrypt OAuth tokens at rest.
    # Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    secret_key: str | None = None

    microsoft_oauth_client_id: str | None = None
    microsoft_oauth_client_secret: str | None = None

    twilio_account_sid: str | None = None
    twilio_auth_token: str | None = None
    twilio_from_number: str | None = None

    stripe_api_key: str | None = None
    stripe_webhook_secret: str | None = None

    url_reputation_api_key: str | None = None

    # Accounts & sessions (non-secret). Browsers treat http://localhost as a
    # secure context, so Secure cookies work in local dev too — leave this on.
    session_cookie_secure: bool = True
    session_ttl_hours: int = 24 * 7
    # Dashboard origins allowed to call the API with credentials (CORS) and to
    # make state-changing requests (CSRF origin check). Comma-separated.
    allowed_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    @property
    def allowed_origin_list(self) -> list[str]:
        """allowed_origins split into a clean list."""
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance so env vars are only parsed once per process."""
    return Settings()
