"""
BHRAM API — Application Configuration
All settings are loaded from environment variables with safe defaults.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── API ───────────────────────────────────────────────────────────────────
    app_name: str = "BHRAM API"
    app_version: str = "1.0.0"
    bhram_api_debug: bool = False
    bhram_api_secret_key: str = "insecure_default_change_me"

    # ── Database ──────────────────────────────────────────────────────────────
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "bhram_db"
    postgres_user: str = "bhram_user"
    postgres_password: str = "devpassword_not_for_production"

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def sync_database_url(self) -> str:
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )


settings = Settings()
