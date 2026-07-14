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

    microsoft_oauth_client_id: str | None = None
    microsoft_oauth_client_secret: str | None = None

    twilio_account_sid: str | None = None
    twilio_auth_token: str | None = None
    twilio_from_number: str | None = None

    stripe_api_key: str | None = None
    stripe_webhook_secret: str | None = None

    url_reputation_api_key: str | None = None


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance so env vars are only parsed once per process."""
    return Settings()
