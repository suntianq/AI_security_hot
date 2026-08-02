"""Small provider registry so adding an adapter never changes the pipeline."""

from __future__ import annotations

from collections.abc import Callable

from ai_security_hot.config.models import ResolvedModelConfig, resolve_model_config
from ai_security_hot.config.settings import Settings
from ai_security_hot.llm.provider import ModelProvider, OpenAICompatibleProvider

ProviderFactory = Callable[[ResolvedModelConfig], ModelProvider]


def _openai_compatible(config: ResolvedModelConfig) -> ModelProvider:
    if not config.api_key_configured or not config.model:
        raise ValueError(
            "INTEL_LLM_API_KEY and a model from config/models.yaml or "
            "INTEL_LLM_MODEL are required"
        )
    assert config.api_key is not None
    return OpenAICompatibleProvider(
        base_url=config.base_url,
        api_key=config.api_key.get_secret_value(),
        model=config.model,
        timeout_seconds=config.timeout_seconds,
        response_format=config.response_format,
        thinking_mode=config.thinking_mode,
    )


_FACTORIES: dict[str, ProviderFactory] = {"openai-compatible": _openai_compatible}


def register_provider(name: str, factory: ProviderFactory) -> None:
    if not name or name in _FACTORIES:
        raise ValueError(f"provider already registered or invalid: {name!r}")
    _FACTORIES[name] = factory


def provider_names() -> tuple[str, ...]:
    return tuple(sorted(_FACTORIES))


def build_provider(
    settings: Settings,
    *,
    config: ResolvedModelConfig | None = None,
) -> ModelProvider:
    resolved = config or resolve_model_config(settings)
    try:
        factory = _FACTORIES[resolved.provider]
    except KeyError as exc:
        raise ValueError(
            f"unknown LLM provider {resolved.provider!r}; available={provider_names()}"
        ) from exc
    return factory(resolved)
