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
    worker_heartbeat_file: str = Field(default="data/.worker-heartbeat")
    lease_seconds: int = Field(
        default=900, ge=60, description="Endpoint fetch crash-recovery lease duration"
    )
    normalize_interval_seconds: int = Field(default=10, ge=1)
    fulltext_interval_seconds: int = Field(default=30, ge=5)
    normalize_batch_size: int = Field(default=2000, ge=1, le=5000)
    fulltext_batch_size: int = Field(default=20, ge=1, le=500)

    # --- circuit breaker (applies to all endpoints uniformly) ---
    circuit_breaker_threshold: int = Field(
        default=5, ge=1, description="Consecutive failures before the circuit opens"
    )
    circuit_breaker_cooldown_minutes: int = Field(
        default=120, ge=10, description="Cooldown when the circuit is open (default 2h)"
    )

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
    llm_config_file: str = Field(default="config/models.yaml")
    llm_profile: str | None = Field(default=None)
    llm_provider: str = Field(default="openai-compatible")
    llm_base_url: str = Field(default="https://api.openai.com/v1")
    llm_api_key: str | None = Field(default=None)
    llm_model: str | None = Field(default=None)
    llm_response_format: Literal["json_schema", "json_object", "prompt_only"] = Field(
        default="json_schema",
        description="Structured-output strategy supported by the selected compatible endpoint",
    )
    llm_thinking_mode: Literal["default", "enabled", "disabled"] = Field(
        default="default",
        description="Optional reasoning toggle for compatible endpoints such as DeepSeek",
    )
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
    # reproducible experiment batch tag (M2.2.1 1d)
    semantic_enrichment_batch_id: str | None = Field(default=None)

    # --- M2.3 relation queue and frozen daily snapshots ---
    relation_scan_enabled: bool = Field(default=True)
    relation_scan_interval_seconds: int = Field(default=120, ge=10)
    relation_scan_batch_size: int = Field(default=100, ge=1, le=1000)
    daily_snapshot_enabled: bool = Field(default=True)
    daily_snapshot_interval_seconds: int = Field(default=900, ge=60)
    daily_snapshot_timezone: str = Field(default="Asia/Shanghai")
    daily_snapshot_limit: int = Field(default=100, ge=1, le=500)

    # --- M2.3.1 embedding candidate recall (disabled by default) ---
    embedding_enabled: bool = Field(default=False)
    embedding_config_file: str = Field(default="config/embeddings.yaml")
    embedding_profile: str | None = Field(default=None)
    embedding_provider: str = Field(default="openai-compatible")
    embedding_base_url: str = Field(default="https://api.openai.com/v1")
    embedding_api_key: str | None = Field(default=None)
    embedding_model: str | None = Field(default=None)
    embedding_dimensions: int | None = Field(default=None, ge=1, le=65536)
    embedding_timeout_seconds: float = Field(default=30.0, ge=1, le=120)
    embedding_max_input_chars: int = Field(default=4000, ge=256, le=50000)
    embedding_interval_seconds: int = Field(default=180, ge=30)
    embedding_batch_size: int = Field(default=16, ge=1, le=100)
    embedding_lease_seconds: int = Field(default=300, ge=60)
    embedding_recall_window_days: int = Field(default=30, ge=1, le=365)
    embedding_recall_threshold: float = Field(default=0.82, ge=0, le=1)
    embedding_recall_top_k: int = Field(default=10, ge=1, le=100)
    embedding_recall_pool_limit: int = Field(default=2000, ge=10, le=20000)

    # --- API security / build identity ---
    # Read and administrative operations use separate environment-only tokens.
    api_token: str | None = Field(default=None, min_length=8)
    admin_api_token: str | None = Field(default=None, min_length=8)
    build_sha: str = Field(default="dev")

    # --- delivery ---
    feishu_webhook_url: str | None = Field(default=None)
    smtp_url: str | None = Field(default=None)
    admin_alert_target: str | None = Field(default=None)


@lru_cache
def get_settings() -> Settings:
    return Settings()
