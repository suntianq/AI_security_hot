"""Replaceable LLM provider boundary; no pipeline imports HTTP details."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Protocol

import httpx

from ai_security_hot.config.models import ResponseFormat, ThinkingMode

OPENAI_COMPATIBLE_ADAPTER_VERSION = "openai-compatible-v3"


@dataclass(frozen=True)
class ModelResponse:
    content: str
    usage: dict = field(default_factory=dict)
    finish_reason: str | None = None


class ModelProviderError(RuntimeError):
    """Provider failure with the complete safe response audit context."""

    def __init__(
        self,
        message: str,
        *,
        raw_response: str | None = None,
        status_code: int | None = None,
        usage: dict | None = None,
        finish_reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.raw_response = raw_response
        self.status_code = status_code
        self.usage = usage or {}
        self.finish_reason = finish_reason


class ModelProvider(Protocol):
    name: str
    model: str

    def complete(
        self,
        *,
        system: str,
        user: str,
        output_schema: dict,
        max_output_tokens: int,
    ) -> ModelResponse: ...


class OpenAICompatibleProvider:
    """Chat Completions adapter for OpenAI, DeepSeek and compatible gateways."""

    name = "openai-compatible"

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout_seconds: float = 30.0,
        response_format: ResponseFormat = "json_schema",
        thinking_mode: ThinkingMode = "default",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.response_format = response_format
        self.thinking_mode = thinking_mode
        endpoint_identity = (
            f"{OPENAI_COMPATIBLE_ADAPTER_VERSION}\0{self.base_url}\0"
            f"{response_format}\0{thinking_mode}"
        ).encode()
        self.cache_namespace = f"{self.name}:{hashlib.sha256(endpoint_identity).hexdigest()[:12]}"

    @property
    def chat_completions_url(self) -> str:
        """Accept either an API base URL or an explicit Chat Completions URL."""

        if self.base_url.endswith("/chat/completions"):
            return self.base_url
        return f"{self.base_url}/chat/completions"

    def complete(
        self,
        *,
        system: str,
        user: str,
        output_schema: dict,
        max_output_tokens: int,
    ) -> ModelResponse:
        headers = {"Authorization": f"Bearer {self.api_key}"}
        raw_schema_name = str(output_schema.get("title") or "model_output")
        schema_name = re.sub(r"[^A-Za-z0-9_-]", "_", raw_schema_name)[:64]
        effective_system = system
        if self.response_format != "json_schema":
            schema_json = json.dumps(output_schema, ensure_ascii=False, separators=(",", ":"))
            effective_system = (
                f"{system}\n\nReturn exactly one JSON object matching this complete "
                "JSON Schema. Include every required field, including fields whose value "
                "is null, empty, or false. Do not use Markdown. "
                f"JSON Schema: {schema_json}"
            )
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": effective_system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "max_tokens": max_output_tokens,
        }
        if self.thinking_mode != "default":
            payload["thinking"] = {"type": self.thinking_mode}
        if self.response_format == "json_schema":
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": schema_name,
                    "strict": True,
                    "schema": output_schema,
                },
            }
        elif self.response_format == "json_object":
            payload["response_format"] = {"type": "json_object"}

        try:
            with httpx.Client(timeout=self.timeout_seconds, headers=headers) as client:
                response = client.post(self.chat_completions_url, json=payload)
        except httpx.RequestError as exc:
            raise ModelProviderError(f"transport error: {exc}") from exc
        raw_http = response.text
        try:
            data = response.json()
        except ValueError as exc:
            raise ModelProviderError(
                "provider returned invalid JSON",
                raw_response=raw_http,
                status_code=response.status_code,
            ) from exc
        usage_value = data.get("usage") if isinstance(data, dict) else None
        usage: dict = dict(usage_value) if isinstance(usage_value, dict) else {}
        choices = data.get("choices") if isinstance(data, dict) else None
        choice = (
            choices[0]
            if isinstance(choices, list) and choices and isinstance(choices[0], dict)
            else {}
        )
        finish = choice.get("finish_reason")
        if response.is_error:
            raise ModelProviderError(
                f"provider HTTP {response.status_code}",
                raw_response=raw_http,
                status_code=response.status_code,
                usage=usage,
                finish_reason=str(finish) if finish is not None else None,
            )
        try:
            content = choice["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise ModelProviderError(
                "provider response missing message content",
                raw_response=raw_http,
                status_code=response.status_code,
                usage=usage,
                finish_reason=str(finish) if finish is not None else None,
            ) from exc
        if not isinstance(content, str):
            raise ModelProviderError(
                "model returned non-text content",
                raw_response=raw_http,
                status_code=response.status_code,
                usage=usage,
                finish_reason=str(finish) if finish is not None else None,
            )
        content = _unwrap_json_fence(content)
        finish_reason = finish
        return ModelResponse(
            content=content,
            usage=usage,
            finish_reason=str(finish_reason) if finish_reason is not None else None,
        )


def provider_cache_namespace(provider: ModelProvider) -> str:
    """Return an endpoint-aware cache namespace with a safe legacy fallback."""

    namespace = getattr(provider, "cache_namespace", provider.name)
    return str(namespace)[:64]


def _unwrap_json_fence(content: str) -> str:
    """Tolerate one Markdown JSON fence while retaining strict schema validation."""

    stripped = content.strip()
    match = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", stripped, flags=re.DOTALL | re.IGNORECASE)
    return match.group(1).strip() if match else content
