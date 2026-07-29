"""Application settings from environment variables (MVP 15.3 — secrets from env)."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="INTEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- database ---
    database_url: str = Field(
        default="postgresql+psycopg://intel:intel@localhost:5432/intel",
        description="SQLAlchemy URL. Uses psycopg 3 driver.",
    )

    # --- sources config ---
    sources_file: str = Field(default="sources/sources.yaml")
    parsers_dir: str = Field(default="sources/parsers")

    # --- blob store (plan 修正 5) ---
    blob_dir: str = Field(default="data/blobs")

    # --- egress / proxy pools (plan 修正 3) — never logged ---
    proxy_pool_cn: str | None = Field(default=None, description="Proxy URL for CN-routed fetches")
    proxy_pool_global: str | None = Field(
        default=None, description="Proxy URL for global-routed fetches"
    )

    # --- fetch defaults (overridable per endpoint) ---
    fetch_timeout_seconds: float = Field(default=20.0)
    fetch_max_response_bytes: int = Field(default=5 * 1024 * 1024)
    fetch_max_redirects: int = Field(default=3)
    fetch_user_agent: str = Field(default="ai-security-hot-intel/0.1 (+contact-admin)")

    # --- scheduler ---
    tick_interval_seconds: int = Field(default=60)
    self_check_interval_seconds: int = Field(default=600)
    lease_seconds: int = Field(default=300, description="Endpoint fetch lease duration")

    # --- LLM / delivery (placeholders for M0) ---
    llm_provider: str | None = Field(default=None)
    llm_api_key: str | None = Field(default=None)
    feishu_webhook_url: str | None = Field(default=None)
    smtp_url: str | None = Field(default=None)
    admin_alert_target: str | None = Field(default=None)


@lru_cache
def get_settings() -> Settings:
    return Settings()
