"""Validated, profile-based model configuration with environment overrides.

Non-secret provider settings may live in YAML. Credentials are deliberately
accepted only from ``INTEL_LLM_API_KEY`` so they cannot leak into source
control through a model profile.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from ai_security_hot.config.settings import Settings

ResponseFormat = Literal["json_schema", "json_object", "prompt_only"]
ThinkingMode = Literal["default", "enabled", "disabled"]


class ModelProfile(BaseModel):
    """One named OpenAI-compatible (or future adapter) model profile."""

    model_config = ConfigDict(extra="forbid")

    provider: str = Field(min_length=1, max_length=64)
    base_url: str
    model: str = Field(min_length=1, max_length=200)
    response_format: ResponseFormat = "json_schema"
    thinking_mode: ThinkingMode = "default"
    timeout_seconds: float = Field(default=30.0, ge=1, le=120)
    max_input_chars: int = Field(default=12000, ge=1000, le=100000)
    classification_max_output_tokens: int = Field(default=500, ge=100, le=4000)
    semantic_max_output_tokens: int = Field(default=2500, ge=500, le=8000)

    @field_validator("provider", "model")
    @classmethod
    def _strip_non_empty(cls, value: str) -> str:
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


class ModelProfiles(BaseModel):
    """Schema for ``config/models.yaml``."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1] = 1
    active_profile: str | None = None
    profiles: dict[str, ModelProfile] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_profile_names(self) -> ModelProfiles:
        for name in self.profiles:
            if not name.strip() or len(name) > 64:
                raise ValueError("profile names must contain 1..64 characters")
        if self.active_profile is not None and self.active_profile not in self.profiles:
            raise ValueError(f"active_profile {self.active_profile!r} is not defined")
        return self


class ResolvedModelConfig(BaseModel):
    """Effective configuration after profile and environment precedence."""

    model_config = ConfigDict(frozen=True)

    profile: str | None
    config_file: str
    provider: str
    base_url: str
    model: str | None
    response_format: ResponseFormat
    thinking_mode: ThinkingMode
    timeout_seconds: float
    max_input_chars: int
    classification_max_output_tokens: int
    semantic_max_output_tokens: int
    api_key: SecretStr | None = Field(default=None, exclude=True, repr=False)
    field_sources: dict[str, str]

    @property
    def api_key_configured(self) -> bool:
        return self.api_key is not None and bool(self.api_key.get_secret_value())

    def public_summary(self) -> dict:
        """Return an operational diagnostic that can safely be logged."""

        return {
            "config_file": self.config_file,
            "profile": self.profile,
            "provider": self.provider,
            "base_url": self.base_url,
            "model": self.model,
            "response_format": self.response_format,
            "thinking_mode": self.thinking_mode,
            "timeout_seconds": self.timeout_seconds,
            "max_input_chars": self.max_input_chars,
            "classification_max_output_tokens": self.classification_max_output_tokens,
            "semantic_max_output_tokens": self.semantic_max_output_tokens,
            "api_key_configured": self.api_key_configured,
            "ready": self.api_key_configured and bool(self.model),
            "field_sources": dict(self.field_sources),
        }


def load_model_profiles(path: str | Path) -> ModelProfiles:
    """Read and validate a model profile file."""

    config_path = Path(path)
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read model config {str(config_path)!r}: {exc}") from exc
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError(f"model config {str(config_path)!r} must contain a YAML object")
    try:
        return ModelProfiles.model_validate(raw)
    except ValueError as exc:
        raise ValueError(f"invalid model config {str(config_path)!r}: {exc}") from exc


def resolve_model_config(settings: Settings) -> ResolvedModelConfig:
    """Resolve YAML profile first, then apply explicit ``INTEL_LLM_*`` values.

    ``BaseSettings.model_fields_set`` contains constructor, process-environment,
    and dotenv values, allowing defaults to remain fallback values rather than
    accidentally overriding a selected YAML profile.
    """

    config_path = Path(settings.llm_config_file)
    profiles: ModelProfiles | None = None
    if config_path.exists():
        profiles = load_model_profiles(config_path)

    selected_profile = settings.llm_profile
    if selected_profile is None and profiles is not None:
        selected_profile = profiles.active_profile

    profile: ModelProfile | None = None
    if selected_profile is not None:
        if profiles is None:
            raise ValueError(
                f"model profile {selected_profile!r} requested but config file "
                f"{str(config_path)!r} does not exist"
            )
        try:
            profile = profiles.profiles[selected_profile]
        except KeyError as exc:
            raise ValueError(
                f"unknown model profile {selected_profile!r}; "
                f"available={tuple(sorted(profiles.profiles))}"
            ) from exc

    values = {
        "provider": settings.llm_provider,
        "base_url": settings.llm_base_url,
        "model": settings.llm_model,
        "response_format": settings.llm_response_format,
        "thinking_mode": settings.llm_thinking_mode,
        "timeout_seconds": settings.llm_timeout_seconds,
        "max_input_chars": settings.llm_max_input_chars,
        "classification_max_output_tokens": settings.llm_max_output_tokens,
        "semantic_max_output_tokens": settings.semantic_llm_max_output_tokens,
    }
    sources = {key: "settings-default" for key in values}

    if profile is not None:
        values.update(
            provider=profile.provider,
            base_url=profile.base_url,
            model=profile.model,
            response_format=profile.response_format,
            thinking_mode=profile.thinking_mode,
            timeout_seconds=profile.timeout_seconds,
            max_input_chars=profile.max_input_chars,
            classification_max_output_tokens=profile.classification_max_output_tokens,
            semantic_max_output_tokens=profile.semantic_max_output_tokens,
        )
        sources = {key: f"profile:{selected_profile}" for key in values}

    setting_to_value = {
        "llm_provider": "provider",
        "llm_base_url": "base_url",
        "llm_model": "model",
        "llm_response_format": "response_format",
        "llm_thinking_mode": "thinking_mode",
        "llm_timeout_seconds": "timeout_seconds",
        "llm_max_input_chars": "max_input_chars",
        "llm_max_output_tokens": "classification_max_output_tokens",
        "semantic_llm_max_output_tokens": "semantic_max_output_tokens",
    }
    for setting_name, value_name in setting_to_value.items():
        if setting_name in settings.model_fields_set:
            values[value_name] = getattr(settings, setting_name)
            sources[value_name] = f"INTEL_{setting_name.upper()}"

    # Reuse ModelProfile validation after merging, including URL and limits.
    # Legacy environment-only configuration may intentionally leave model unset
    # while rule mode is active; build_provider reports that only when needed.
    model_is_unset = values["model"] is None
    validation_values = {**values, "model": values["model"] or "unconfigured"}
    validated_values = ModelProfile.model_validate(validation_values).model_dump()
    if model_is_unset:
        validated_values["model"] = None
    return ResolvedModelConfig(
        profile=selected_profile,
        config_file=str(config_path),
        api_key=SecretStr(settings.llm_api_key) if settings.llm_api_key else None,
        field_sources=sources,
        **validated_values,
    )
