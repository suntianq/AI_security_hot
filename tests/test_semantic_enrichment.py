"""Offline contract tests for the M2.2 shadow semantic-enrichment foundation."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from ai_security_hot.domain.models import NormalizedDocument
from ai_security_hot.domain.semantic import (
    DocumentSemanticOutput,
    EvidenceQuote,
    locate_evidence,
)
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
        "ontology_version": "semantic-onto-v1",
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


class _RepairProvider:
    """Returns invalid JSON on the first call, valid JSON on the repair call."""

    name = "fake"
    model = "semantic-test-v1"

    def __init__(self, valid_output: dict) -> None:
        self.valid_output = valid_output
        self.calls = 0

    def complete(self, *, system, user, output_schema, max_output_tokens) -> ModelResponse:
        self.calls += 1
        if self.calls == 1:
            # malformed: missing required 'summary' field
            bad = dict(self.valid_output)
            bad.pop("summary", None)
            return ModelResponse(
                content=json.dumps(bad),
                usage={"total_tokens": 100},
                finish_reason="stop",
            )
        # repair call must carry the invalid response + errors
        assert "<invalid_response>" in user
        assert "<validation_errors>" in user
        return ModelResponse(
            content=json.dumps(self.valid_output),
            usage={"total_tokens": 50},
            finish_reason="stop",
        )


def test_runner_repairs_invalid_output_once() -> None:
    from ai_security_hot.llm.tasks import ValidatedModelTaskRunner

    provider = _RepairProvider(_semantic_output())
    task = DocumentSemanticTask()
    runner = ValidatedModelTaskRunner(provider)
    prepared = runner.prepare(task.spec, task.payload(_document()))

    result = runner.run(prepared)  # first call invalid, second repairs
    assert provider.calls == 2
    assert result.output.summary  # repaired output valid
    assert result.usage == {"total_tokens": 150}  # 100 + 50 merged
    assert result.finish_reason == "stop"


def test_runner_repair_disabled_raises_validation_error() -> None:
    from pydantic import ValidationError

    from ai_security_hot.llm.tasks import ValidatedModelTaskRunner

    provider = _RepairProvider(_semantic_output())
    task = DocumentSemanticTask()
    runner = ValidatedModelTaskRunner(provider)
    prepared = runner.prepare(task.spec, task.payload(_document()))

    with pytest.raises(ValidationError):
        runner.run(prepared, repair_once=False)  # no repair => validation error surfaces


def test_benchmark_is_a_valid_entity_type() -> None:
    from ai_security_hot.domain.semantic import ExtractedEntity

    entity = ExtractedEntity(
        entity_type="benchmark",  # must now be accepted by the ontology
        name="MMLU-Pro",
        canonical_name="MMLU-Pro",
        version=None,
        role=None,
        confidence=0.9,
        evidence=EvidenceQuote(text="MMLU-Pro"),
    )
    assert entity.entity_type == "benchmark"


def test_ontology_version_folds_into_execution_version() -> None:
    from ai_security_hot.domain.semantic import ONTO_VERSION
    from ai_security_hot.llm.tasks import ValidatedModelTaskRunner

    provider = _FakeProvider(_semantic_output())
    task = DocumentSemanticTask()
    runner = ValidatedModelTaskRunner(provider)
    prepared = runner.prepare(task.spec, task.payload(_document()))

    assert task.spec.extra_fingerprint == ONTO_VERSION
    # execution_version is deterministic and includes the ontology fingerprint
    again = runner.prepare(task.spec, task.payload(_document()))
    assert prepared.execution_version == again.execution_version
    assert len(prepared.execution_version) == 32


def test_stratified_sampling_is_source_balanced() -> None:
    """Stratified sampling must not let one source dominate the sample."""
    from unittest.mock import patch

    from ai_security_hot.semantic.sampling import stratified_sample

    class _Doc:
        def __init__(self, doc_id, endpoint):
            self.id = doc_id
            self.endpoint_id = endpoint
            self.tech_directions = []
            self.classified_event_type = None
            self.published_at_utc = None

    fake_docs = [_Doc(i, f"source-{i % 4}") for i in range(40)]
    # _eligible_docs is mocked, so the session is never touched — pass a stub.
    fake_session = object()
    with patch("ai_security_hot.semantic.sampling._eligible_docs", return_value=fake_docs):
        sample = stratified_sample(fake_session, size=10)
    sources = {doc.endpoint_id for doc in sample}
    assert len(sources) >= 3  # not dominated by a single source
    assert len(sample) == 10


def test_relation_adjudication_same_fingerprint() -> None:
    from ai_security_hot.semantic.relations import AtomicEventRef, adjudicate

    left = AtomicEventRef(id=1, document_id=10, fingerprint="fp-abc",
                          subject="Anthropic", action="released", object="Claude 5",
                          time_text="2026-08-01", published_at=None)
    right = AtomicEventRef(id=2, document_id=11, fingerprint="fp-abc",
                           subject="Anthropic", action="released", object="Claude 5",
                           time_text="2026-08-01", published_at=None)
    verdict = adjudicate(left, right)
    assert verdict.decision == "same_event"
    assert verdict.reason == "identical_atomic_fingerprint"


def test_relation_adjudication_shared_entity_close_time() -> None:
    from datetime import UTC, datetime, timedelta

    from ai_security_hot.semantic.relations import AtomicEventRef, adjudicate

    now = datetime.now(UTC)
    left = AtomicEventRef(id=1, document_id=10, fingerprint="fp-1",
                          subject="OpenAI", action="announced", object="GPT-5",
                          time_text=None, published_at=now)
    right = AtomicEventRef(id=2, document_id=11, fingerprint="fp-2",
                           subject="OpenAI", action="released", object="GPT-5.5",
                           time_text=None, published_at=now + timedelta(days=3))
    verdict = adjudicate(left, right, shared_entities={"entity:5"})
    assert verdict.decision == "related_event"
    assert verdict.shared_entity == "entity:5"


def test_relation_adjudication_different() -> None:
    from datetime import UTC, datetime, timedelta

    from ai_security_hot.semantic.relations import AtomicEventRef, adjudicate

    now = datetime.now(UTC)
    left = AtomicEventRef(id=1, document_id=10, fingerprint="fp-1",
                          subject="Anthropic", action="released", object="Claude",
                          time_text=None, published_at=now)
    right = AtomicEventRef(id=2, document_id=11, fingerprint="fp-2",
                           subject="Google", action="released", object="Gemini",
                           time_text=None, published_at=now + timedelta(days=60))
    verdict = adjudicate(left, right, shared_entities=set())
    assert verdict.decision == "different_event"


def test_claim_merge_groups_by_type_and_value() -> None:
    from ai_security_hot.semantic.claim_merge import SourceClaim, merge_related_pair

    left = SourceClaim(atomic_event_id=1, document_id=10, claim_type="action",
                       text="OpenAI released GPT-5", normalized_value={"action": "release"},
                       confidence=0.9, evidence_excerpt="released", evidence_field="body")
    right = SourceClaim(atomic_event_id=2, document_id=11, claim_type="action",
                        text="OpenAI launched GPT-5", normalized_value={"action": "release"},
                        confidence=0.85, evidence_excerpt="launched", evidence_field="body")
    merged = merge_related_pair([left], [right])
    assert len(merged) == 1  # same type + normalized_value → one merged claim
    assert merged[0].sources == [10, 11]  # both documents preserved
    assert merged[0].stance == "support"
    assert merged[0].claim_key.startswith("merged:")


def test_claim_merge_detects_contradiction() -> None:
    from ai_security_hot.semantic.claim_merge import SourceClaim, merge_claims

    high = SourceClaim(atomic_event_id=1, document_id=10, claim_type="status",
                       text="Exploited in the wild", normalized_value={"status": "exploited"},
                       confidence=0.95, evidence_excerpt="exploited", evidence_field="body")
    low = SourceClaim(atomic_event_id=2, document_id=11, claim_type="status",
                      text="Not exploited", normalized_value={"status": "exploited"},
                      confidence=0.3, evidence_excerpt="not exploited", evidence_field="body")
    merged = merge_claims([high, low])
    assert len(merged) == 1
    assert merged[0].stance == "contradict"  # 0.95 vs 0.3 spread > 0.5


def test_promotion_gate_blocks_single_document() -> None:
    from ai_security_hot.semantic.promotion import build_promotion_preview

    preview = build_promotion_preview(
        fingerprint="fp-1", title="Event", summary="s", event_type="incident",
        topic="security_for_ai", category="general", document_ids=[10],
        merged_claim_count=3,
    )
    assert preview.gated is False  # only 1 doc < PROMOTE_MIN_DOCUMENTS=2


def test_promotion_gate_met_with_two_documents() -> None:
    from ai_security_hot.semantic.promotion import build_promotion_preview

    preview = build_promotion_preview(
        fingerprint="fp-2", title="Event", summary="s", event_type="incident",
        topic="security_for_ai", category="general", document_ids=[10, 11],
        merged_claim_count=2,
    )
    assert preview.gated is True
    draft = preview.to_event_draft()
    assert draft.fingerprint == "fp-2"
    assert len(draft.memberships) == 2
