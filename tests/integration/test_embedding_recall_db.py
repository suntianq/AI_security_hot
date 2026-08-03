"""PostgreSQL lifecycle regression for bounded embedding candidate recall."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from ai_security_hot.embeddings.pipeline import (
    claim_embedding_work,
    complete_embedding_work,
    enqueue_embedding_work,
    recall_embedding_candidates,
)
from ai_security_hot.models.semantic_tables import (
    AtomicEvent,
    DocumentEnrichment,
    EntityMention,
    RelationCandidate,
    RelationVerdict,
    SemanticEntity,
)
from ai_security_hot.models.tables import (
    Document,
    DocumentIdentity,
    RawItem,
    Source,
    SourceEndpoint,
)
from ai_security_hot.semantic.candidate_scan import enqueue_candidate_pairs
from ai_security_hot.semantic.versions import RELATION_VERSION

NOW = datetime(2026, 8, 3, 8, 0, tzinfo=UTC)
pytestmark = pytest.mark.db


def _add_atomic(session: Session, ordinal: int) -> tuple[Document, AtomicEvent]:
    url = f"https://embedding-recall.invalid/{ordinal}"
    raw = RawItem(
        endpoint_id="embedding-recall-endpoint",
        source_id="embedding-recall-source",
        native_id=f"item-{ordinal}",
        request_url=url,
        final_url=url,
        http_status=200,
        published_at=NOW,
        fetched_at=NOW,
        language="en",
        content_hash=f"{ordinal:064x}",
        raw_text=f"Embedding test article {ordinal}",
        canonical_url=url,
        connector_version="test-v1",
        stage="done",
    )
    session.add(raw)
    session.flush()
    document = Document(
        raw_item_id=raw.id,
        endpoint_id="embedding-recall-endpoint",
        title_original=f"Embedding test article {ordinal}",
        body_text=f"Evidence for embedding test article {ordinal}.",
        canonical_url=url,
        published_at_utc=NOW,
        language="en",
        identifiers={},
        entities={},
        parse_quality=1.0,
        source_status="active",
        record_status="published",
        tech_directions=["security_for_ai"],
        company_models=[],
        classified_event_type="news",
        classified_at=NOW,
        dedupe_version="dedupe-v2",
    )
    session.add(document)
    session.flush()
    enrichment = DocumentEnrichment(
        document_id=document.id,
        enrichment_version="document-semantic-v1",
        execution_version=f"embedding-{ordinal}",
        mode="shadow",
        input_hash=f"{ordinal + 100:064x}",
        provider="fake",
        model="fake-v1",
        prompt_version="test-v1",
        relevant=True,
        relevance_confidence=0.99,
        content_type="news",
        summary=f"Summary {ordinal}",
        output={},
    )
    session.add(enrichment)
    session.flush()
    atomic = AtomicEvent(
        enrichment_id=enrichment.id,
        document_id=document.id,
        ordinal=0,
        fingerprint=f"{ordinal + 200:064x}",
        event_type="incident",
        subject=f"Vendor {ordinal}",
        action="reported",
        object="incident",
        summary=f"Atomic event {ordinal}",
        confidence=0.95,
        evidence=[],
        mode="shadow",
    )
    session.add(atomic)
    session.flush()
    return document, atomic


def test_embedding_recall_is_bounded_auditable_and_never_auto_merges() -> None:
    database_url = os.environ.get("INTEL_DATABASE_URL")
    if not database_url:
        pytest.skip("INTEL_DATABASE_URL is required for PostgreSQL integration tests")
    engine = create_engine(database_url)
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, expire_on_commit=False)
    execution_version = "embedding-test-v1"
    try:
        session.add(Source(id="embedding-recall-source", name="Embedding test", trust_tier="A"))
        session.add(
            SourceEndpoint(
                id="embedding-recall-endpoint",
                source_id="embedding-recall-source",
                connector="rss",
                url="https://embedding-recall.invalid/feed",
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
        first_document, first_atomic = _add_atomic(session, 1)
        second_document, second_atomic = _add_atomic(session, 2)
        third_document, third_atomic = _add_atomic(session, 3)
        fourth_document, fourth_atomic = _add_atomic(session, 4)
        session.add_all(
            [
                DocumentIdentity(
                    document_id=third_document.id,
                    kind="incident",
                    value="incident-one",
                    fingerprint="incident:one",
                    event_key=True,
                ),
                DocumentIdentity(
                    document_id=fourth_document.id,
                    kind="incident",
                    value="incident-two",
                    fingerprint="incident:two",
                    event_key=True,
                ),
            ]
        )
        session.flush()

        assert enqueue_embedding_work(session, execution_version=execution_version, limit=10) == 4
        assert enqueue_embedding_work(session, execution_version=execution_version, limit=10) == 0
        leases = claim_embedding_work(
            session,
            execution_version=execution_version,
            limit=10,
            lease_seconds=300,
            max_input_chars=4000,
        )
        assert len(leases) == 4
        vectors = {
            first_atomic.id: [1.0, 0.0, 0.0],
            second_atomic.id: [0.999, 0.01, 0.0],
            third_atomic.id: [0.998, 0.02, 0.0],
            fourth_atomic.id: [0.997, 0.03, 0.0],
        }
        for lease in leases:
            complete_embedding_work(
                session,
                lease,
                execution_version=execution_version,
                provider_name="fake:embedding",
                model="fake-embed-v1",
                vector=vectors[lease.atomic_event_id],
                usage={"prompt_tokens": 1},
            )

        summary = recall_embedding_candidates(
            session,
            execution_version=execution_version,
            seed_limit=10,
            pool_limit=10,
            top_k=10,
            threshold=0.9,
            window_days=30,
        )
        assert summary["seeds"] == 4
        vector_only = session.execute(
            select(RelationCandidate).where(
                RelationCandidate.left_atomic_id == first_atomic.id,
                RelationCandidate.right_atomic_id == second_atomic.id,
                RelationCandidate.algorithm_version == RELATION_VERSION,
            )
        ).scalar_one()
        assert vector_only.status == "recalled"
        assert vector_only.embedding_score is not None
        assert vector_only.shared_entity is None
        shared_entity = SemanticEntity(
            canonical_key="shared-product-key",
            entity_type="product",
            canonical_name="Shared Product",
            aliases=["Shared Product"],
        )
        session.add(shared_entity)
        session.flush()
        for atomic, document in (
            (first_atomic, first_document),
            (second_atomic, second_document),
        ):
            session.add(
                EntityMention(
                    entity_id=shared_entity.id,
                    document_id=document.id,
                    enrichment_id=atomic.enrichment_id,
                    atomic_event_id=atomic.id,
                    mention_text="Shared Product",
                    role="subject",
                    confidence=0.95,
                    evidence_excerpt="Shared Product",
                    evidence_field="body",
                )
            )
        session.flush()
        entity_summary = enqueue_candidate_pairs(
            session, seed_limit=10, pair_limit=10, bucket_limit=10
        )
        assert entity_summary["enqueued"] >= 1
        session.refresh(vector_only)
        assert vector_only.status == "pending"
        assert vector_only.shared_entity == "shared-product-key"
        blocked = session.execute(
            select(RelationCandidate).where(
                RelationCandidate.left_atomic_id == third_atomic.id,
                RelationCandidate.right_atomic_id == fourth_atomic.id,
                RelationCandidate.algorithm_version == RELATION_VERSION,
            )
        ).scalar_one()
        assert blocked.status == "blocked"
        assert blocked.hard_conflict == "conflict:incident"
        assert session.scalar(select(func.count()).select_from(RelationVerdict)) == 0

        second_pass = recall_embedding_candidates(
            session,
            execution_version=execution_version,
            seed_limit=10,
            pool_limit=10,
            top_k=10,
            threshold=0.9,
            window_days=30,
        )
        assert second_pass["seeds"] == 0
        assert first_document.id != second_document.id
    finally:
        session.close()
        transaction.rollback()
        connection.close()
        engine.dispose()
