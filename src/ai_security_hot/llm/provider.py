"""Replaceable LLM provider boundary; no classifier imports HTTP details."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

import httpx


@dataclass(frozen=True)
class ModelResponse:
    content: str
    usage: dict = field(default_factory=dict)


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
    """Chat Completions adapter with strict JSON-schema response format."""

    name = "openai-compatible"

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout_seconds: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds

    def complete(
        self,
        *,
        system: str,
        user: str,
        output_schema: dict,
        max_output_tokens: int,
    ) -> ModelResponse:
        headers = {"Authorization": f"Bearer {self.api_key}"}
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "max_tokens": max_output_tokens,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "document_classification",
                    "strict": True,
                    "schema": output_schema,
                },
            },
        }
        with httpx.Client(timeout=self.timeout_seconds, headers=headers) as client:
            response = client.post(f"{self.base_url}/chat/completions", json=payload)
            response.raise_for_status()
            data = response.json()
        content = data["choices"][0]["message"]["content"]
        if not isinstance(content, str):
            raise ValueError("model returned non-text content")
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        return ModelResponse(content=content, usage=usage)
