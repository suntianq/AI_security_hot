"""Generic, validated model-task execution independent from pipeline stages."""

from __future__ import annotations

import json
from dataclasses import dataclass

from pydantic import BaseModel

from ai_security_hot.domain.models import content_sha256
from ai_security_hot.llm.provider import ModelProvider


@dataclass(frozen=True)
class ModelTaskSpec[OutputT: BaseModel]:
    name: str
    task_version: str
    prompt_version: str
    output_model: type[OutputT]
    system_prompt: str
    max_output_tokens: int

    def __post_init__(self) -> None:
        if not self.name or len(self.name) > 32:
            raise ValueError("task name must contain 1..32 characters")
        if not self.task_version or not self.prompt_version:
            raise ValueError("task and prompt versions are required")


@dataclass(frozen=True)
class PreparedModelTask[OutputT: BaseModel]:
    spec: ModelTaskSpec[OutputT]
    input_json: str
    input_hash: str
    execution_version: str


@dataclass(frozen=True)
class ModelTaskResult[OutputT: BaseModel]:
    output: OutputT
    usage: dict
    prepared: PreparedModelTask[OutputT]


class ValidatedModelTaskRunner:
    """Prepare deterministic cache keys, invoke a provider and validate output."""

    def __init__(self, provider: ModelProvider) -> None:
        self.provider = provider

    def prepare[OutputT: BaseModel](
        self,
        spec: ModelTaskSpec[OutputT],
        payload: dict,
    ) -> PreparedModelTask[OutputT]:
        input_json = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        input_hash = content_sha256(input_json)
        execution_version = content_sha256(
            spec.name,
            spec.task_version,
            spec.prompt_version,
            self.provider.name,
            self.provider.model,
        )[:32]
        return PreparedModelTask(
            spec=spec,
            input_json=input_json,
            input_hash=input_hash,
            execution_version=execution_version,
        )

    def run[OutputT: BaseModel](
        self, prepared: PreparedModelTask[OutputT]
    ) -> ModelTaskResult[OutputT]:
        response = self.provider.complete(
            system=prepared.spec.system_prompt,
            user=prepared.input_json,
            output_schema=prepared.spec.output_model.model_json_schema(),
            max_output_tokens=prepared.spec.max_output_tokens,
        )
        output = prepared.spec.output_model.model_validate_json(response.content)
        return ModelTaskResult(output=output, usage=response.usage, prepared=prepared)

    @staticmethod
    def validate_cached[OutputT: BaseModel](
        prepared: PreparedModelTask[OutputT],
        cached: dict,
    ) -> ModelTaskResult[OutputT]:
        output = prepared.spec.output_model.model_validate(cached)
        return ModelTaskResult(output=output, usage={}, prepared=prepared)
