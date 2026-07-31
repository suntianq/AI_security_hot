"""Application settings from environment variables (MVP 15.3 — secrets from env)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

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
    lease_seconds: int = Field(
        default=900, ge=60, description="Endpoint fetch crash-recovery lease duration"
    )
    normalize_interval_seconds: int = Field(default=10, ge=1)
    fulltext_interval_seconds: int = Field(default=30, ge=5)
    normalize_batch_size: int = Field(default=2000, ge=1, le=5000)
    fulltext_batch_size: int = Field(default=20, ge=1, le=500)

    # --- M1.3 classification / LLM ---
    classification_mode: Literal["rule", "hybrid"] = Field(default="rule")
    classification_interval_seconds: int = Field(default=30, ge=5)
    event_interval_seconds: int = Field(default=60, ge=5)
    event_backlog_threshold: int = Field(
        default=1000,
        ge=0,
        description=(
            "Defer scheduled event updates while M1 processing backlog "
            "exceeds this count; 0 disables the guard"
        ),
    )
    m2_signature_batch_size: int = Field(default=5000, ge=100, le=20000)
    m2_dedupe_batch_size: int = Field(default=1000, ge=1, le=5000)
    m2_cluster_batch_size: int = Field(default=1000, ge=1, le=5000)
    m2_max_local_documents: int = Field(
        default=20000,
        ge=1000,
        le=100000,
        description="Safety bound for one local candidate/component closure",
    )
    classification_batch_size: int = Field(
        default=25, ge=1, le=500, description="Cost-bounded hybrid model batch"
    )
    rule_classification_batch_size: int = Field(default=2000, ge=1, le=5000)
    classification_lease_seconds: int = Field(default=300, ge=30)
    llm_provider: str = Field(default="openai-compatible")
    llm_base_url: str = Field(default="https://api.openai.com/v1")
    llm_api_key: str | None = Field(default=None)
    llm_model: str | None = Field(default=None)
    llm_timeout_seconds: float = Field(default=30.0, ge=1, le=120)
    llm_max_input_chars: int = Field(default=12000, ge=1000, le=100000)
    llm_max_output_tokens: int = Field(default=500, ge=100, le=4000)

    # --- M2.2 shadow semantic enrichment ---
    semantic_enrichment_enabled: bool = Field(
        default=False,
        description="Explicit cost gate; disabled means no semantic model calls",
    )
    semantic_enrichment_mode: Literal["shadow"] = Field(default="shadow")
    semantic_enrichment_interval_seconds: int = Field(default=120, ge=10)
    semantic_enrichment_batch_size: int = Field(default=5, ge=1, le=100)
    semantic_enrichment_lease_seconds: int = Field(default=600, ge=60)
    semantic_llm_max_output_tokens: int = Field(default=2500, ge=500, le=8000)

    # --- delivery ---
    feishu_webhook_url: str | None = Field(default=None)
    smtp_url: str | None = Field(default=None)
    admin_alert_target: str | None = Field(default=None)


@lru_cache
def get_settings() -> Settings:
    return Settings()
