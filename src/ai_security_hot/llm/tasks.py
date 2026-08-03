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
class ModelTaskAttempt:
    ordinal: int
    phase: str
    status: str
    raw_response: str | None = None
    usage: dict = None  # type: ignore[assignment]
    finish_reason: str | None = None
    validation_error: str | None = None
    provider_error: str | None = None

    def __post_init__(self) -> None:
        if self.usage is None:
            object.__setattr__(self, "usage", {})


class ModelTaskFailure(RuntimeError):
    """Failed model task retaining every provider and repair attempt."""

    def __init__(self, message: str, attempts: list[ModelTaskAttempt]) -> None:
        super().__init__(message)
        self.attempts = tuple(attempts)
        usage: dict = {}
        for attempt in attempts:
            usage = _merge_usage(usage, attempt.usage)
        self.usage = usage
        self.finish_reason = next(
            (a.finish_reason for a in reversed(attempts) if a.finish_reason), None
        )
        self.raw_response = attempts[-1].raw_response if attempts else None


@dataclass(frozen=True)
class ModelTaskResult[OutputT: BaseModel]:
    output: OutputT
    usage: dict
    prepared: PreparedModelTask[OutputT]
    finish_reason: str | None = None
    raw_response: str | None = None
    attempts: tuple[ModelTaskAttempt, ...] = ()


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
        self, prepared: PreparedModelTask[OutputT], *, repair_once: bool = True
    ) -> ModelTaskResult[OutputT]:
        attempts: list[ModelTaskAttempt] = []
        response = self._complete(prepared, prepared.input_json, "initial", attempts)
        try:
            output = prepared.spec.output_model.model_validate_json(response.content)
        except ValidationError as error:
            attempts.append(
                ModelTaskAttempt(
                    1,
                    "initial",
                    "validation_failed",
                    response.content,
                    response.usage,
                    response.finish_reason,
                    _validation_summary(error),
                )
            )
            if not repair_once:
                raise ModelTaskFailure("model output failed schema validation", attempts) from error
            repair_user = (
                f"{prepared.input_json}\n\nYour previous JSON response failed schema validation.\n"
                f"<invalid_response>{response.content[:4000]}</invalid_response>\n"
                f"<validation_errors>{_validation_summary(error)}</validation_errors>\n"
                "Return only a corrected JSON object matching the original schema."
            )
            repaired = self._complete(prepared, repair_user, "repair", attempts)
            try:
                output = prepared.spec.output_model.model_validate_json(repaired.content)
            except ValidationError as repair_error:
                attempts.append(
                    ModelTaskAttempt(
                        2,
                        "repair",
                        "validation_failed",
                        repaired.content,
                        repaired.usage,
                        repaired.finish_reason,
                        _validation_summary(repair_error),
                    )
                )
                raise ModelTaskFailure(
                    "model repair failed schema validation", attempts
                ) from repair_error
            attempts.append(
                ModelTaskAttempt(
                    2, "repair", "success", repaired.content, repaired.usage, repaired.finish_reason
                )
            )
            return ModelTaskResult(
                output,
                _merge_usage(response.usage, repaired.usage),
                prepared,
                repaired.finish_reason,
                repaired.content,
                tuple(attempts),
            )
        attempts.append(
            ModelTaskAttempt(
                1, "initial", "success", response.content, response.usage, response.finish_reason
            )
        )
        return ModelTaskResult(
            output,
            response.usage,
            prepared,
            response.finish_reason,
            response.content,
            tuple(attempts),
        )

    def _complete(self, prepared, user: str, phase: str, attempts: list[ModelTaskAttempt]):
        try:
            return self.provider.complete(
                system=prepared.spec.system_prompt,
                user=user,
                output_schema=prepared.spec.output_model.model_json_schema(),
                max_output_tokens=prepared.spec.max_output_tokens,
            )
        except Exception as error:
            attempts.append(
                ModelTaskAttempt(
                    len(attempts) + 1,
                    phase,
                    "provider_failed",
                    getattr(error, "raw_response", None),
                    getattr(error, "usage", {}),
                    getattr(error, "finish_reason", None),
                    provider_error=f"{type(error).__name__}: {error}",
                )
            )
            raise ModelTaskFailure("model provider call failed", attempts) from error

    @staticmethod
    def validate_cached[OutputT: BaseModel](
        prepared: PreparedModelTask[OutputT],
        cached: dict,
    ) -> ModelTaskResult[OutputT]:
        output = prepared.spec.output_model.model_validate(cached)
        return ModelTaskResult(output=output, usage={}, prepared=prepared)
