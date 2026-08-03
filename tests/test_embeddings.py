"""DB-free contracts for configurable embedding generation."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from ai_security_hot.config.embeddings import resolve_embedding_config
from ai_security_hot.config.settings import Settings
from ai_security_hot.embeddings.pipeline import embedding_execution_version, run_embedding_stage
from ai_security_hot.embeddings.provider import (
    EmbeddingProviderError,
    OpenAICompatibleEmbeddingProvider,
)


def _settings(**values: object) -> Settings:
    return Settings.model_validate(values)


def _config_file(path: Path) -> Path:
    path.write_text(
        """
version: 1
active_profile: local
profiles:
  local:
    provider: openai-compatible
    base_url: https://embedding.example/v1
    model: embed-v1
    dimensions: 3
    timeout_seconds: 12
    max_input_chars: 2048
""".strip(),
        encoding="utf-8",
    )
    return path


def test_embedding_profile_and_environment_override(tmp_path: Path) -> None:
    path = _config_file(tmp_path / "embeddings.yaml")
    settings = _settings(
        embedding_config_file=str(path),
        embedding_api_key="secret-key",
        embedding_model="embed-v2",
        embedding_dimensions=4,
    )

    config = resolve_embedding_config(settings)

    assert config.profile == "local"
    assert config.base_url == "https://embedding.example/v1"
    assert config.model == "embed-v2"
    assert config.dimensions == 4
    assert config.api_key_configured
    assert config.public_summary()["field_sources"]["model"] == "INTEL_EMBEDDING_MODEL"
    assert "secret-key" not in json.dumps(config.public_summary())


@respx.mock
def test_openai_compatible_embedding_provider_validates_and_orders_vectors() -> None:
    route = respx.post("https://embedding.example/v1/embeddings").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {"index": 1, "embedding": [0, 1, 0]},
                    {"index": 0, "embedding": [1, 0, 0]},
                ],
                "usage": {"prompt_tokens": 7, "total_tokens": 7},
            },
        )
    )
    provider = OpenAICompatibleEmbeddingProvider(
        base_url="https://embedding.example/v1",
        api_key="secret-key",
        model="embed-v1",
        dimensions=3,
    )

    response = provider.embed(["first", "second"])

    assert response.vectors == [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0]]
    assert response.usage == {"prompt_tokens": 7, "total_tokens": 7}
    request = route.calls[0].request
    assert request.headers["Authorization"] == "Bearer secret-key"
    assert json.loads(request.content) == {
        "model": "embed-v1",
        "input": ["first", "second"],
        "dimensions": 3,
    }


@respx.mock
def test_embedding_provider_retains_safe_failure_response() -> None:
    respx.post("https://embedding.example/embeddings").mock(
        return_value=httpx.Response(429, json={"error": {"message": "rate limited"}})
    )
    provider = OpenAICompatibleEmbeddingProvider(
        base_url="https://embedding.example",
        api_key="secret-key",
        model="embed-v1",
    )

    with pytest.raises(EmbeddingProviderError) as caught:
        provider.embed(["input"])

    assert caught.value.status_code == 429
    assert "rate limited" in (caught.value.raw_response or "")
    assert "secret-key" not in (caught.value.raw_response or "")


def test_embedding_execution_version_changes_with_endpoint_contract(tmp_path: Path) -> None:
    path = _config_file(tmp_path / "embeddings.yaml")
    first_settings = _settings(
        embedding_config_file=str(path),
        embedding_api_key="secret-key",
    )
    first_config = resolve_embedding_config(first_settings)
    first_provider = OpenAICompatibleEmbeddingProvider(
        base_url=first_config.base_url,
        api_key="secret-key",
        model=first_config.model or "",
        dimensions=first_config.dimensions,
    )
    second_provider = OpenAICompatibleEmbeddingProvider(
        base_url="https://other.example/v1",
        api_key="secret-key",
        model=first_config.model or "",
        dimensions=first_config.dimensions,
    )

    assert embedding_execution_version(first_config, first_provider) != embedding_execution_version(
        first_config, second_provider
    )


def test_disabled_embedding_stage_never_requires_database_or_provider() -> None:
    assert run_embedding_stage(_settings(embedding_enabled=False)) == {"status": "disabled"}
