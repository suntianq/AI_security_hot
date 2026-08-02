"""Generic, validated model-task execution independent from pipeline stages."""

from __future__ import annotations

import json
from dataclasses import dataclass

from pydantic import BaseModel, ValidationError

from ai_security_hot.domain.models import content_sha256
from ai_security_hot.llm.provider import ModelProvider, provider_cache_namespace


def _validation_summary(error: ValidationError) -> str:
    """Compact, bounded summary of a pydantic ValidationError."""
    try:
        errors = error.errors()
    except Exception:  # pragma: no cover - defensive
        return str(error)[:2000]
    lines = []
    for item in errors[:20]:
        loc = ".".join(str(part) for part in item.get("loc", []))
        msg = item.get("msg", "")
        lines.append(f"{loc}: {msg}")
    return "\n".join(lines)[:2000]


def _merge_usage(left: dict, right: dict) -> dict:
    """Sum common OpenAI-style usage counters across two calls."""
    merged = dict(left or {})
    for key, value in (right or {}).items():
        if isinstance(value, int) and isinstance(merged.get(key), int):
            merged[key] = merged[key] + value
        else:
            merged[key] = value
    return merged


@dataclass(frozen=True)
class ModelTaskSpec[OutputT: BaseModel]:
    name: str
    task_version: str
    prompt_version: str
    output_model: type[OutputT]
    system_prompt: str
    max_output_tokens: int
    # Optional extra fingerprint (e.g. ontology version) folded into
    # execution_version so schema/ontology changes invalidate cached outputs.
    extra_fingerprint: str = ""

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
    finish_reason: str | None = None
    raw_response: str | None = None


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
            provider_cache_namespace(self.provider),
            self.provider.model,
            spec.extra_fingerprint,
        )[:32]
        return PreparedModelTask(
            spec=spec,
            input_json=input_json,
            input_hash=input_hash,
            execution_version=execution_version,
        )

    def run[OutputT: BaseModel](
        self,
        prepared: PreparedModelTask[OutputT],
        *,
        repair_once: bool = True,
    ) -> ModelTaskResult[OutputT]:
        """Invoke the provider and validate; on schema failure do one bounded
        repair (re-prompt with the invalid response + validation errors) before
        giving up and letting the caller schedule a retry."""
        response = self.provider.complete(
            system=prepared.spec.system_prompt,
            user=prepared.input_json,
            output_schema=prepared.spec.output_model.model_json_schema(),
            max_output_tokens=prepared.spec.max_output_tokens,
        )
        try:
            output = prepared.spec.output_model.model_validate_json(response.content)
            return ModelTaskResult(
                output=output,
                usage=response.usage,
                prepared=prepared,
                finish_reason=response.finish_reason,
                raw_response=response.content,
            )
        except ValidationError as first_error:
            if not repair_once:
                raise
            repair_result = self._repair(
                prepared,
                invalid_raw=response.content,
                validation_summary=_validation_summary(first_error),
                prior_usage=response.usage,
            )
            return repair_result

    def _repair[OutputT: BaseModel](
        self,
        prepared: PreparedModelTask[OutputT],
        *,
        invalid_raw: str,
        validation_summary: str,
        prior_usage: dict,
    ) -> ModelTaskResult[OutputT]:
        repair_user = (
            f"{prepared.input_json}\n\n"
            "Your previous JSON response failed schema validation and must be "
            "corrected. Here is what you produced (invalid):\n"
            f"<invalid_response>{invalid_raw[:4000]}</invalid_response>\n"
            "Validation errors:\n"
            f"<validation_errors>{validation_summary[:2000]}</validation_errors>\n"
            "Return the corrected JSON object matching the original schema. "
            "Do not include the invalid response in the output."
        )
        response = self.provider.complete(
            system=prepared.spec.system_prompt,
            user=repair_user,
            output_schema=prepared.spec.output_model.model_json_schema(),
            max_output_tokens=prepared.spec.max_output_tokens,
        )
        output = prepared.spec.output_model.model_validate_json(response.content)
        return ModelTaskResult(
            output=output,
            usage=_merge_usage(prior_usage, response.usage),
            prepared=prepared,
            finish_reason=response.finish_reason,
            raw_response=response.content,
        )

    @staticmethod
    def validate_cached[OutputT: BaseModel](
        prepared: PreparedModelTask[OutputT],
        cached: dict,
    ) -> ModelTaskResult[OutputT]:
        output = prepared.spec.output_model.model_validate(cached)
        return ModelTaskResult(output=output, usage={}, prepared=prepared)
