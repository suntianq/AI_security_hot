"""Offline contract tests for the M2.2 shadow semantic-enrichment foundation."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from ai_security_hot.domain.models import NormalizedDocument
from ai_security_hot.domain.semantic import DocumentSemanticOutput, locate_evidence
from ai_security_hot.llm.provider import ModelResponse
from ai_security_hot.llm.tasks import ValidatedModelTaskRunner
from ai_security_hot.models import semantic_tables  # noqa: F401
from ai_security_hot.models.base import Base
from ai_security_hot.semantic.document_task import DocumentSemanticTask


def _semantic_output() -> dict:
    return {
        "relevant": True,
        "relevance_confidence": 0.98,
        "relevance_reason": "A first-party model release with security controls.",
        "content_type": "release",
        "summary": "Anthropic released Claude 5 with a new security control.",
        "entities": [
            {
                "entity_type": "company",
                "name": "Anthropic",
                "canonical_name": "Anthropic",
                "version": None,
                "role": "publisher",
                "confidence": 0.99,
                "evidence": {"text": "Anthropic released Claude 5"},
            }
        ],
        "atomic_events": [
            {
                "event_type": "release",
                "subject": "Anthropic",
                "action": "released",
                "object": "Claude 5",
                "time_text": "today",
                "location": None,
                "summary": "Anthropic released Claude 5.",
                "confidence": 0.97,
                "evidence": [{"text": "Anthropic released Claude 5 today."}],
                "entities": [],
                "claims": [
                    {
                        "claim_type": "action",
                        "text": "Anthropic released Claude 5.",
                        "normalized_value": {"action": "release"},
                        "confidence": 0.97,
                        "evidence": {"text": "Anthropic released Claude 5 today."},
                    }
                ],
            }
        ],
    }


class _FakeProvider:
    name = "fake"
    model = "semantic-test-v1"

    def __init__(self, output: dict) -> None:
        self.output = output
        self.calls = 0

    def complete(
        self,
        *,
        system: str,
        user: str,
        output_schema: dict,
        max_output_tokens: int,
    ) -> ModelResponse:
        self.calls += 1
        assert "untrusted document" in system
        assert json.loads(user)["title"] == "Claude 5 release"
        assert output_schema["additionalProperties"] is False
        assert max_output_tokens == 2500
        return ModelResponse(
            content=json.dumps(self.output),
            usage={"total_tokens": 123},
        )


def _document() -> NormalizedDocument:
    return NormalizedDocument(
        raw_item_native_id="release-1",
        endpoint_id="anthropic-news",
        title_original="Claude 5 release",
        body_text="Anthropic released Claude 5 today. It adds a new security control.",
        canonical_url="https://example.com/claude-5",
        language="en",
        parse_quality=1.0,
    )


def test_semantic_schema_is_strict_and_irrelevant_documents_cannot_emit_events() -> None:
    extra = _semantic_output()
    extra["unexpected"] = True
    with pytest.raises(ValidationError, match="extra_forbidden"):
        DocumentSemanticOutput.model_validate(extra)

    irrelevant = _semantic_output()
    irrelevant["relevant"] = False
    with pytest.raises(ValidationError, match="must not emit atomic_events"):
        DocumentSemanticOutput.model_validate(irrelevant)


def test_semantic_schema_requires_every_structured_output_field() -> None:
    schema = DocumentSemanticOutput.model_json_schema()
    object_schemas = [schema, *schema.get("$defs", {}).values()]
    for object_schema in object_schemas:
        if object_schema.get("type") == "object":
            assert set(object_schema.get("properties", {})) == set(
                object_schema.get("required", [])
            )


def test_model_task_runner_is_deterministic_and_validates_output() -> None:
    provider = _FakeProvider(_semantic_output())
    task = DocumentSemanticTask()
    runner = ValidatedModelTaskRunner(provider)

    left = runner.prepare(task.spec, task.payload(_document()))
    right = runner.prepare(task.spec, task.payload(_document()))
    result = runner.run(left)
    cached = runner.validate_cached(left, result.output.model_dump(mode="json"))

    assert left.input_hash == right.input_hash
    assert left.execution_version == right.execution_version
    assert result.output.atomic_events[0].object == "Claude 5"
    assert result.usage == {"total_tokens": 123}
    assert cached.output == result.output
    assert provider.calls == 1


def test_document_task_bounds_input_and_evidence_offsets_are_exact_only() -> None:
    document = _document().model_copy(update={"body_text": "x" * 50})
    task = DocumentSemanticTask(max_input_chars=12)

    assert task.payload(document)["body"] == "x" * 12
    exact = locate_evidence(
        "Claude 5 release",
        "Anthropic released Claude 5 today.",
        "released Claude 5",
    )
    normalized_only = locate_evidence(
        "Claude 5 release",
        "Anthropic  released Claude 5 today.",
        "Anthropic released Claude 5",
    )
    assert exact.field == "body"
    assert exact.start == 10
    assert exact.end == 27
    assert normalized_only.field == "unknown"
    assert normalized_only.start is None


def test_semantic_tables_are_registered_on_shared_metadata() -> None:
    expected = {
        "semantic_work_items",
        "document_enrichments",
        "semantic_entities",
        "atomic_events",
        "entity_mentions",
        "extracted_claims",
    }
    assert expected <= set(Base.metadata.tables)
