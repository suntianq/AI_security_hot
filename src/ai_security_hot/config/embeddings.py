"""Validated profile configuration for embedding-capable model endpoints."""

from __future__ import annotations

from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from ai_security_hot.config.settings import Settings


class EmbeddingProfile(BaseModel):
    """One non-secret embedding model profile."""

    model_config = ConfigDict(extra="forbid")

    provider: str = Field(default="openai-compatible", min_length=1, max_length=64)
    base_url: str
    model: str = Field(min_length=1, max_length=200)
    dimensions: int | None = Field(default=None, ge=1, le=65536)
    timeout_seconds: float = Field(default=30.0, ge=1, le=120)
    max_input_chars: int = Field(default=4000, ge=256, le=50000)

    @field_validator("provider", "model")
    @classmethod
    def _strip_model(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be empty")
        return value

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base_url must be an absolute http(s) URL")
        if parsed.query or parsed.fragment:
            raise ValueError("base_url must not contain a query string or fragment")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("base_url must not contain credentials")
        return value


class EmbeddingProfiles(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    active_profile: str | None = None
    profiles: dict[str, EmbeddingProfile] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_profile_names(self) -> EmbeddingProfiles:
        for name in self.profiles:
            if not name.strip() or len(name) > 64:
                raise ValueError("profile names must contain 1..64 characters")
        if self.active_profile is not None and self.active_profile not in self.profiles:
            raise ValueError(f"active_profile {self.active_profile!r} is not defined")
        return self


class ResolvedEmbeddingConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    profile: str | None
    config_file: str
    provider: str
    base_url: str
    model: str | None
    dimensions: int | None
    timeout_seconds: float
    max_input_chars: int
    api_key: SecretStr | None = Field(default=None, exclude=True, repr=False)
    field_sources: dict[str, str]

    @property
    def api_key_configured(self) -> bool:
        return self.api_key is not None and bool(self.api_key.get_secret_value())

    def public_summary(self) -> dict:
        return {
            "config_file": self.config_file,
            "profile": self.profile,
            "provider": self.provider,
            "base_url": self.base_url,
            "model": self.model,
            "dimensions": self.dimensions,
            "timeout_seconds": self.timeout_seconds,
            "max_input_chars": self.max_input_chars,
            "api_key_configured": self.api_key_configured,
            "ready": self.api_key_configured and bool(self.model),
            "field_sources": dict(self.field_sources),
        }


def load_embedding_profiles(path: str | Path) -> EmbeddingProfiles:
    config_path = Path(path)
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read embedding config {str(config_path)!r}: {exc}") from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError(f"embedding config {str(config_path)!r} must contain a YAML object")
    try:
        return EmbeddingProfiles.model_validate(raw)
    except ValueError as exc:
        raise ValueError(f"invalid embedding config {str(config_path)!r}: {exc}") from exc


def resolve_embedding_config(settings: Settings) -> ResolvedEmbeddingConfig:
    """Resolve YAML first, then explicit ``INTEL_EMBEDDING_*`` overrides."""

    config_path = Path(settings.embedding_config_file)
    profiles = load_embedding_profiles(config_path) if config_path.exists() else None
    selected = settings.embedding_profile
    if selected is None and profiles is not None:
        selected = profiles.active_profile
    profile = None
    if selected is not None:
        if profiles is None:
            raise ValueError(
                f"embedding profile {selected!r} requested but {str(config_path)!r} does not exist"
            )
        try:
            profile = profiles.profiles[selected]
        except KeyError as exc:
            raise ValueError(
                f"unknown embedding profile {selected!r}; "
                f"available={tuple(sorted(profiles.profiles))}"
            ) from exc

    values = {
        "provider": settings.embedding_provider,
        "base_url": settings.embedding_base_url,
        "model": settings.embedding_model,
        "dimensions": settings.embedding_dimensions,
        "timeout_seconds": settings.embedding_timeout_seconds,
        "max_input_chars": settings.embedding_max_input_chars,
    }
    sources = {key: "settings-default" for key in values}
    if profile is not None:
        values.update(profile.model_dump())
        sources = {key: f"profile:{selected}" for key in values}

    mapping = {
        "embedding_provider": "provider",
        "embedding_base_url": "base_url",
        "embedding_model": "model",
        "embedding_dimensions": "dimensions",
        "embedding_timeout_seconds": "timeout_seconds",
        "embedding_max_input_chars": "max_input_chars",
    }
    for setting_name, value_name in mapping.items():
        if setting_name in settings.model_fields_set:
            values[value_name] = getattr(settings, setting_name)
            sources[value_name] = f"INTEL_{setting_name.upper()}"

    model_unset = values["model"] is None
    validated = EmbeddingProfile.model_validate(
        {**values, "model": values["model"] or "unconfigured"}
    ).model_dump()
    if model_unset:
        validated["model"] = None
    return ResolvedEmbeddingConfig(
        profile=selected,
        config_file=str(config_path),
        api_key=SecretStr(settings.embedding_api_key) if settings.embedding_api_key else None,
        field_sources=sources,
        **validated,
    )
