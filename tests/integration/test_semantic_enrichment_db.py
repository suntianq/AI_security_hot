"""Transactional PostgreSQL test for shadow semantic persistence and leases."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from ai_security_hot.domain.semantic import DocumentSemanticOutput
from ai_security_hot.models.semantic_tables import (
    AtomicEvent,
    DocumentEnrichment,
    EntityMention,
    ExtractedClaim,
    SemanticWorkItem,
)
from ai_security_hot.models.tables import Document, RawItem, Source, SourceEndpoint
from ai_security_hot.storage import semantic_repository

NOW = datetime(2026, 7, 31, 8, 0, tzinfo=UTC)


@pytest.mark.db
def test_shadow_enrichment_persists_atomic_evidence_transactionally() -> None:
    database_url = os.environ.get("INTEL_DATABASE_URL")
    if not database_url:
        pytest.skip("INTEL_DATABASE_URL is required for PostgreSQL integration tests")
    engine = create_engine(database_url)
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, expire_on_commit=False)
    try:
        session.add(Source(id="semantic-test-source", name="Semantic test", trust_tier="A"))
        session.add(
            SourceEndpoint(
                id="semantic-test-endpoint",
                source_id="semantic-test-source",
                connector="rss",
                url="https://semantic-test.invalid/feed",
                enabled=True,
                state_version="1",
                priority="P1",
                trust_tier="A",
                egress_route="direct",
                policy={},
                status="active",
            )
        )
        session.flush()
        raw = RawItem(
            endpoint_id="semantic-test-endpoint",
            source_id="semantic-test-source",
            native_id="release-1",
            request_url="https://semantic-test.invalid/release",
            final_url="https://semantic-test.invalid/release",
            http_status=200,
            published_at=NOW,
            fetched_at=NOW,
            language="en",
            content_hash="a" * 64,
            raw_text="Anthropic released Claude 5 today.",
            canonical_url="https://semantic-test.invalid/release",
            connector_version="test-v1",
            stage="done",
        )
        session.add(raw)
        session.flush()
        document = Document(
            raw_item_id=raw.id,
            endpoint_id="semantic-test-endpoint",
            title_original="Claude 5 release",
            body_text="Anthropic released Claude 5 today.",
            canonical_url="https://semantic-test.invalid/release",
            published_at_utc=NOW,
            language="en",
            identifiers={},
            entities={},
            parse_quality=1.0,
            source_status="active",
            record_status="published",
            tech_directions=["llm"],
            company_models=["anthropic_claude"],
            classified_event_type="release",
            classified_at=NOW,
            dedupe_version="dedupe-v2",
        )
        session.add(document)
        session.flush()
        work = SemanticWorkItem(
            subject_type="document",
            subject_id=document.id,
            task="document_semantic",
            task_version="document-semantic-v1",
            execution_version="test-execution",
            mode="shadow",
            status="pending",
        )
        session.add(work)
        session.flush()

        claimed = semantic_repository.claim_document_work(
            session,
            task="document_semantic",
            execution_version="test-execution",
            limit=1,
            lease_seconds=300,
        )
        assert len(claimed) == 1

        output = DocumentSemanticOutput.model_validate(
            {
                "relevant": True,
                "relevance_confidence": 0.99,
                "relevance_reason": "First-party model release.",
                "content_type": "release",
                "summary": "Anthropic released Claude 5.",
                "ontology_version": "semantic-onto-v1",
                "entities": [],
                "atomic_events": [
                    {
                        "event_type": "release",
                        "subject": "Anthropic",
                        "action": "released",
                        "object": "Claude 5",
                        "time_text": "today",
                        "location": None,
                        "summary": "Anthropic released Claude 5.",
                        "confidence": 0.98,
                        "evidence": [{"text": "Anthropic released Claude 5 today."}],
                        "entities": [
                            {
                                "entity_type": "model_version",
                                "name": "Claude 5",
                                "canonical_name": "Claude",
                                "version": "5",
                                "role": "released_model",
                                "confidence": 0.99,
                                "evidence": {"text": "Claude 5"},
                            }
                        ],
                        "claims": [
                            {
                                "claim_type": "action",
                                "text": "Anthropic released Claude 5.",
                                "normalized_value": {"action": "release"},
                                "confidence": 0.98,
                                "evidence": {"text": "Anthropic released Claude 5 today."},
                            }
                        ],
                    }
                ],
            }
        )
        semantic_repository.complete_document_work(
            session,
            work_item_id=claimed[0].work_item_id,
            lease_token=claimed[0].lease_token,
            document=claimed[0].document,
            output=output,
            input_hash="b" * 64,
            execution_version="test-execution",
            enrichment_version="document-semantic-v1",
            provider="fake",
            model="fake-v1",
            prompt_version="test-prompt-v1",
        )
        session.flush()

        assert (session.scalar(select(func.count()).select_from(DocumentEnrichment)) or 0) >= 1
        assert (session.scalar(select(func.count()).select_from(AtomicEvent)) or 0) >= 1
        mention = session.execute(
            select(EntityMention).where(EntityMention.document_id == document.id)
        ).scalar_one()
        claim = session.execute(
            select(ExtractedClaim)
            .join(AtomicEvent, AtomicEvent.id == ExtractedClaim.atomic_event_id)
            .where(AtomicEvent.document_id == document.id)
        ).scalar_one()
        assert mention.evidence_field == "title"
        assert claim.evidence_field == "body"
        assert work.status == "succeeded"
        assert work.lease_token is None
    finally:
        session.close()
        transaction.rollback()
        connection.close()
        engine.dispose()
