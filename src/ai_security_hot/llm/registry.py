"""Small provider registry so adding an adapter never changes the pipeline."""

from __future__ import annotations

from collections.abc import Callable

from ai_security_hot.config.settings import Settings
from ai_security_hot.llm.provider import ModelProvider, OpenAICompatibleProvider

ProviderFactory = Callable[[Settings], ModelProvider]


def _openai_compatible(settings: Settings) -> ModelProvider:
    if not settings.llm_api_key or not settings.llm_model:
        raise ValueError("INTEL_LLM_API_KEY and INTEL_LLM_MODEL are required")
    return OpenAICompatibleProvider(
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key,
        model=settings.llm_model,
        timeout_seconds=settings.llm_timeout_seconds,
    )


_FACTORIES: dict[str, ProviderFactory] = {"openai-compatible": _openai_compatible}


def register_provider(name: str, factory: ProviderFactory) -> None:
    if not name or name in _FACTORIES:
        raise ValueError(f"provider already registered or invalid: {name!r}")
    _FACTORIES[name] = factory


def provider_names() -> tuple[str, ...]:
    return tuple(sorted(_FACTORIES))


def build_provider(settings: Settings) -> ModelProvider:
    try:
        factory = _FACTORIES[settings.llm_provider]
    except KeyError as exc:
        raise ValueError(
            f"unknown LLM provider {settings.llm_provider!r}; available={provider_names()}"
        ) from exc
    return factory(settings)
