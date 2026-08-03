"""Replaceable embedding-provider boundary and OpenAI-compatible adapter."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Protocol

import httpx

from ai_security_hot.config.embeddings import ResolvedEmbeddingConfig, resolve_embedding_config
from ai_security_hot.config.settings import Settings

EMBEDDING_ADAPTER_VERSION = "openai-compatible-embedding-v1"


@dataclass(frozen=True)
class EmbeddingResponse:
    vectors: list[list[float]]
    usage: dict = field(default_factory=dict)
    raw_response: str | None = None


class EmbeddingProviderError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        raw_response: str | None = None,
        status_code: int | None = None,
        usage: dict | None = None,
    ) -> None:
        super().__init__(message)
        self.raw_response = raw_response
        self.status_code = status_code
        self.usage = usage or {}


class EmbeddingProvider(Protocol):
    name: str
    model: str
    cache_namespace: str

    def embed(self, inputs: Sequence[str]) -> EmbeddingResponse: ...


class OpenAICompatibleEmbeddingProvider:
    name = "openai-compatible"

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        dimensions: int | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.dimensions = dimensions
        self.timeout_seconds = timeout_seconds
        identity = (
            f"{EMBEDDING_ADAPTER_VERSION}\0{self.base_url}\0{model}\0{dimensions or 'native'}"
        ).encode()
        self.cache_namespace = f"{self.name}:{hashlib.sha256(identity).hexdigest()[:12]}"

    @property
    def embeddings_url(self) -> str:
        if self.base_url.endswith("/embeddings"):
            return self.base_url
        return f"{self.base_url}/embeddings"

    def embed(self, inputs: Sequence[str]) -> EmbeddingResponse:
        if not inputs:
            return EmbeddingResponse(vectors=[])
        payload: dict = {"model": self.model, "input": list(inputs)}
        if self.dimensions is not None:
            payload["dimensions"] = self.dimensions
        try:
            with httpx.Client(
                timeout=self.timeout_seconds,
                headers={"Authorization": f"Bearer {self.api_key}"},
            ) as client:
                response = client.post(self.embeddings_url, json=payload)
        except httpx.RequestError as exc:
            raise EmbeddingProviderError(f"transport error: {exc}") from exc
        raw = response.text
        try:
            data = response.json()
        except ValueError as exc:
            raise EmbeddingProviderError(
                "provider returned invalid JSON",
                raw_response=raw,
                status_code=response.status_code,
            ) from exc
        usage_value = data.get("usage") if isinstance(data, dict) else None
        usage = dict(usage_value) if isinstance(usage_value, dict) else {}
        if response.is_error:
            raise EmbeddingProviderError(
                f"provider HTTP {response.status_code}",
                raw_response=raw,
                status_code=response.status_code,
                usage=usage,
            )
        rows = data.get("data") if isinstance(data, dict) else None
        if not isinstance(rows, list) or len(rows) != len(inputs):
            raise EmbeddingProviderError(
                "provider returned an unexpected embedding count",
                raw_response=raw,
                status_code=response.status_code,
                usage=usage,
            )
        ordered: list[tuple[int, list[float]]] = []
        for ordinal, row in enumerate(rows):
            if not isinstance(row, dict) or not isinstance(row.get("embedding"), list):
                raise EmbeddingProviderError(
                    "provider response missing embedding vector",
                    raw_response=raw,
                    status_code=response.status_code,
                    usage=usage,
                )
            try:
                vector = [float(value) for value in row["embedding"]]
            except (TypeError, ValueError) as exc:
                raise EmbeddingProviderError(
                    "provider returned a non-numeric embedding",
                    raw_response=raw,
                    status_code=response.status_code,
                    usage=usage,
                ) from exc
            if not vector or any(not math.isfinite(value) for value in vector):
                raise EmbeddingProviderError(
                    "provider returned an empty or non-finite embedding",
                    raw_response=raw,
                    status_code=response.status_code,
                    usage=usage,
                )
            if self.dimensions is not None and len(vector) != self.dimensions:
                raise EmbeddingProviderError(
                    f"provider returned {len(vector)} dimensions; expected {self.dimensions}",
                    raw_response=raw,
                    status_code=response.status_code,
                    usage=usage,
                )
            index = row.get("index", ordinal)
            if not isinstance(index, int):
                raise EmbeddingProviderError("provider returned a non-integer embedding index")
            ordered.append((index, vector))
        ordered.sort(key=lambda item: item[0])
        if [index for index, _vector in ordered] != list(range(len(inputs))):
            raise EmbeddingProviderError("provider returned invalid embedding indexes")
        dimensions = {len(vector) for _index, vector in ordered}
        if len(dimensions) != 1:
            raise EmbeddingProviderError("provider returned inconsistent embedding dimensions")
        return EmbeddingResponse(
            vectors=[vector for _index, vector in ordered],
            usage=usage,
            raw_response=raw,
        )


ProviderFactory = Callable[[ResolvedEmbeddingConfig], EmbeddingProvider]


def _openai_compatible(config: ResolvedEmbeddingConfig) -> EmbeddingProvider:
    if not config.api_key_configured or not config.model:
        raise ValueError(
            "INTEL_EMBEDDING_API_KEY and a model from config/embeddings.yaml or "
            "INTEL_EMBEDDING_MODEL are required"
        )
    assert config.api_key is not None
    return OpenAICompatibleEmbeddingProvider(
        base_url=config.base_url,
        api_key=config.api_key.get_secret_value(),
        model=config.model,
        dimensions=config.dimensions,
        timeout_seconds=config.timeout_seconds,
    )


_FACTORIES: dict[str, ProviderFactory] = {"openai-compatible": _openai_compatible}


def build_embedding_provider(
    settings: Settings,
    *,
    config: ResolvedEmbeddingConfig | None = None,
) -> EmbeddingProvider:
    resolved = config or resolve_embedding_config(settings)
    try:
        factory = _FACTORIES[resolved.provider]
    except KeyError as exc:
        raise ValueError(
            f"unknown embedding provider {resolved.provider!r}; "
            f"available={embedding_provider_names()}"
        ) from exc
    return factory(resolved)


def register_embedding_provider(name: str, factory: ProviderFactory) -> None:
    if not name or name in _FACTORIES:
        raise ValueError(f"embedding provider already registered or invalid: {name!r}")
    _FACTORIES[name] = factory


def embedding_provider_names() -> tuple[str, ...]:
    return tuple(sorted(_FACTORIES))
