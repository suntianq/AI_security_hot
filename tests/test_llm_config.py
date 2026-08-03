"""Offline tests for profile-based OpenAI-compatible/DeepSeek configuration."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from ai_security_hot.config.models import load_model_profiles, resolve_model_config
from ai_security_hot.config.settings import Settings
from ai_security_hot.llm.provider import (
    ModelProviderError,
    OpenAICompatibleProvider,
    provider_cache_namespace,
)
from ai_security_hot.llm.registry import build_provider


def _write_profiles(path: Path) -> None:
    path.write_text(
        """
version: 1
active_profile: deepseek-v4
profiles:
  deepseek-v4:
    provider: openai-compatible
    base_url: https://deepseek.example/v1
    model: deepseek-v4
    response_format: json_object
    timeout_seconds: 60
    max_input_chars: 16000
    classification_max_output_tokens: 700
    semantic_max_output_tokens: 3000
""".strip(),
        encoding="utf-8",
    )


def test_profile_resolves_non_secrets_and_public_summary_redacts_key(tmp_path: Path) -> None:
    config_path = tmp_path / "models.yaml"
    _write_profiles(config_path)
    settings = Settings.model_validate(
        {
            "llm_config_file": str(config_path),
            "llm_api_key": "super-secret",
        }
    )

    config = resolve_model_config(settings)

    assert config.profile == "deepseek-v4"
    assert config.base_url == "https://deepseek.example/v1"
    assert config.model == "deepseek-v4"
    assert config.response_format == "json_object"
    assert config.max_input_chars == 16000
    assert config.semantic_max_output_tokens == 3000
    assert config.api_key_configured is True
    rendered = json.dumps(config.public_summary())
    assert "super-secret" not in rendered
    assert config.public_summary()["ready"] is True


def test_intel_environment_values_override_active_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "models.yaml"
    _write_profiles(config_path)
    monkeypatch.setenv("INTEL_LLM_CONFIG_FILE", str(config_path))
    monkeypatch.setenv("INTEL_LLM_BASE_URL", "https://gateway.example/chat/completions")
    monkeypatch.setenv("INTEL_LLM_MODEL", "private-deepseek-v4")
    monkeypatch.setenv("INTEL_LLM_RESPONSE_FORMAT", "prompt_only")
    settings = Settings()

    config = resolve_model_config(settings)

    assert config.base_url == "https://gateway.example/chat/completions"
    assert config.model == "private-deepseek-v4"
    assert config.response_format == "prompt_only"
    assert config.field_sources["base_url"] == "INTEL_LLM_BASE_URL"
    assert config.field_sources["model"] == "INTEL_LLM_MODEL"


def test_missing_or_invalid_selected_profile_is_rejected(tmp_path: Path) -> None:
    config_path = tmp_path / "models.yaml"
    _write_profiles(config_path)

    with pytest.raises(ValueError, match="unknown model profile"):
        resolve_model_config(
            Settings.model_validate(
                {
                    "llm_config_file": str(config_path),
                    "llm_profile": "does-not-exist",
                }
            )
        )

    config_path.write_text(
        """
version: 1
active_profile: broken
profiles:
  broken:
    provider: openai-compatible
    base_url: file:///tmp/socket
    model: deepseek-v4
""".strip(),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match=r"absolute http\(s\) URL"):
        load_model_profiles(config_path)

    config_path.write_text(
        """
version: 1
active_profile: broken
profiles:
  broken:
    provider: openai-compatible
    base_url: https://user:secret@gateway.example/v1
    model: deepseek-v4
""".strip(),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="must not contain credentials"):
        load_model_profiles(config_path)


def test_build_provider_uses_resolved_profile_without_network(tmp_path: Path) -> None:
    config_path = tmp_path / "models.yaml"
    _write_profiles(config_path)
    settings = Settings.model_validate(
        {
            "llm_config_file": str(config_path),
            "llm_api_key": "test-key",
        }
    )

    provider = build_provider(settings)

    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.model == "deepseek-v4"
    assert provider.response_format == "json_object"
    assert provider.chat_completions_url == "https://deepseek.example/v1/chat/completions"


@respx.mock
def test_json_object_mode_and_full_endpoint_are_deepseek_compatible() -> None:
    route = respx.post("https://gateway.example/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": '```json\n{"ok": true}\n```'}}],
                "usage": {"total_tokens": 12},
            },
        )
    )
    provider = OpenAICompatibleProvider(
        base_url="https://gateway.example/v1/chat/completions",
        api_key="test-key",
        model="deepseek-v4",
        response_format="json_object",
        thinking_mode="disabled",
    )

    result = provider.complete(
        system="Return JSON only.",
        user="{}",
        output_schema={"title": "Output", "type": "object"},
        max_output_tokens=100,
    )

    payload = json.loads(route.calls[0].request.content)
    assert payload["response_format"] == {"type": "json_object"}
    assert payload["thinking"] == {"type": "disabled"}
    assert "complete JSON Schema" in payload["messages"][0]["content"]
    assert '"title":"Output"' in payload["messages"][0]["content"]
    assert payload["model"] == "deepseek-v4"
    assert result.content == '{"ok": true}'
    assert result.usage == {"total_tokens": 12}


@respx.mock
def test_prompt_only_omits_unsupported_response_format() -> None:
    route = respx.post("https://gateway.example/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"ok": true}'}}]},
        )
    )
    provider = OpenAICompatibleProvider(
        base_url="https://gateway.example/v1",
        api_key="test-key",
        model="deepseek-v4",
        response_format="prompt_only",
    )

    provider.complete(
        system="Return JSON only.",
        user="{}",
        output_schema={"title": "Output", "type": "object"},
        max_output_tokens=100,
    )

    payload = json.loads(route.calls[0].request.content)
    assert "response_format" not in payload
    assert "complete JSON Schema" in payload["messages"][0]["content"]


@respx.mock
def test_non_text_response_retains_complete_audit_context() -> None:
    payload = {
        "choices": [
            {
                "message": {"content": [{"type": "text", "text": "not plain text"}]},
                "finish_reason": "length",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }
    respx.post("https://gateway.example/v1/chat/completions").mock(
        return_value=httpx.Response(200, json=payload)
    )
    provider = OpenAICompatibleProvider(
        base_url="https://gateway.example/v1",
        api_key="test-key",
        model="deepseek-v4",
    )

    with pytest.raises(ModelProviderError) as caught:
        provider.complete(
            system="Return JSON only.",
            user="{}",
            output_schema={"title": "Output", "type": "object"},
            max_output_tokens=100,
        )

    assert json.loads(caught.value.raw_response or "{}") == payload
    assert caught.value.usage == payload["usage"]
    assert caught.value.finish_reason == "length"


def test_cache_namespace_changes_with_endpoint_or_response_mode() -> None:
    left = OpenAICompatibleProvider(
        base_url="https://one.example/v1",
        api_key="key",
        model="deepseek-v4",
        response_format="json_object",
    )
    right = OpenAICompatibleProvider(
        base_url="https://two.example/v1",
        api_key="key",
        model="deepseek-v4",
        response_format="json_object",
    )
    prompt_only = OpenAICompatibleProvider(
        base_url="https://one.example/v1",
        api_key="key",
        model="deepseek-v4",
        response_format="prompt_only",
    )

    assert provider_cache_namespace(left) != provider_cache_namespace(right)
    assert provider_cache_namespace(left) != provider_cache_namespace(prompt_only)
