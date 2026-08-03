"""PostgreSQL regression test for the durable semantic lifecycle."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from ai_security_hot.models.semantic_tables import (
    AtomicEvent,
    DocumentEnrichment,
    RelationCandidate,
    RelationVerdict,
    SemanticRelationComponent,
)
from ai_security_hot.models.tables import (
    Claim,
    ClaimEvidence,
    Document,
    Event,
    EventDocument,
    RawItem,
    Source,
    SourceEndpoint,
)
from ai_security_hot.semantic.candidate_scan import (
    RELATION_VERSION,
    claim_candidate_queue,
    fail_candidate,
)
from ai_security_hot.semantic.claim_merge import SourceClaim, merge_claims
from ai_security_hot.semantic.components import (
    claim_component_work,
    complete_component_work,
    enqueue_component_work,
    enqueue_missing_component_work,
    enqueue_stale_component_work,
    rebuild_component_closure,
)
from ai_security_hot.semantic.promotion import (
    apply_promotion,
    build_promotion_preview,
    load_same_event_components,
    rollback_promotion,
)
from ai_security_hot.snapshots import generate_daily_snapshot, read_daily_snapshot

NOW = datetime(2026, 8, 3, 8, 0, tzinfo=UTC)
pytestmark = pytest.mark.db


def _add_atomic(session: Session, ordinal: int) -> tuple[Document, AtomicEvent]:
    url = f"https://semantic-lifecycle.invalid/{ordinal}"
    raw = RawItem(
        endpoint_id="semantic-lifecycle-endpoint",
        source_id="semantic-lifecycle-source",
        native_id=f"item-{ordinal}",
        request_url=url,
        final_url=url,
        http_status=200,
        published_at=NOW,
        fetched_at=NOW,
        language="en",
        content_hash=f"{ordinal:064x}",
        raw_text=f"Lifecycle test article {ordinal}",
        canonical_url=url,
        connector_version="test-v1",
        stage="done",
    )
    session.add(raw)
    session.flush()
    document = Document(
        raw_item_id=raw.id,
        endpoint_id="semantic-lifecycle-endpoint",
        title_original=f"Lifecycle test article {ordinal}",
        body_text=f"Evidence for lifecycle test article {ordinal}.",
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
        execution_version=f"lifecycle-{ordinal}",
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
        subject="Vendor",
        action="confirmed",
        object="incident",
        summary=f"Atomic event {ordinal}",
        confidence=0.95,
        evidence=[],
        mode="shadow",
    )
    session.add(atomic)
    session.flush()
    return document, atomic


def test_relation_queue_promotion_rollback_and_snapshot_lifecycle() -> None:
    database_url = os.environ.get("INTEL_DATABASE_URL")
    if not database_url:
        pytest.skip("INTEL_DATABASE_URL is required for PostgreSQL integration tests")
    engine = create_engine(database_url)
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, expire_on_commit=False)
    try:
        session.add(
            Source(
                id="semantic-lifecycle-source",
                name="Semantic lifecycle test",
                trust_tier="A",
            )
        )
        session.add(
            SourceEndpoint(
                id="semantic-lifecycle-endpoint",
                source_id="semantic-lifecycle-source",
                connector="rss",
                url="https://semantic-lifecycle.invalid/feed",
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
        _, fourth_atomic = _add_atomic(session, 4)
        _, fifth_atomic = _add_atomic(session, 5)
        retired_bridge_document, retired_bridge = _add_atomic(session, 6)
        retired_bridge_document.source_status = "retired"

        session.add_all(
            [
                RelationVerdict(
                    left_atomic_id=first_atomic.id,
                    right_atomic_id=second_atomic.id,
                    decision="same_event",
                    confidence=0.98,
                    reason="same_fingerprint",
                    algorithm_version="relation-v1",
                ),
                RelationVerdict(
                    left_atomic_id=first_atomic.id,
                    right_atomic_id=second_atomic.id,
                    decision="same_event",
                    confidence=0.98,
                    reason="same_fingerprint",
                    algorithm_version=RELATION_VERSION,
                ),
                RelationVerdict(
                    left_atomic_id=second_atomic.id,
                    right_atomic_id=third_atomic.id,
                    decision="related_event",
                    confidence=0.8,
                    reason="shared_entity",
                    algorithm_version=RELATION_VERSION,
                ),
                RelationVerdict(
                    left_atomic_id=fourth_atomic.id,
                    right_atomic_id=retired_bridge.id,
                    decision="same_event",
                    confidence=0.9,
                    reason="retired_bridge",
                    algorithm_version=RELATION_VERSION,
                ),
                RelationVerdict(
                    left_atomic_id=fifth_atomic.id,
                    right_atomic_id=retired_bridge.id,
                    decision="same_event",
                    confidence=0.9,
                    reason="retired_bridge",
                    algorithm_version=RELATION_VERSION,
                ),
            ]
        )
        session.flush()
        assert enqueue_missing_component_work(session, limit=20) == 2
        assert enqueue_missing_component_work(session, limit=20) == 0
        rebuild_result = rebuild_component_closure(
            session,
            {first_atomic.id, fourth_atomic.id},
        )
        assert rebuild_result["groups"] == 1
        components = load_same_event_components(session)
        assert len(components) == 1
        component = components[0]
        assert component.atomic_ids == [first_atomic.id, second_atomic.id]
        stable_component_id = component.id
        initial_component_revision = component.revision
        bootstrap_leases = claim_component_work(session, limit=10)
        assert len(bootstrap_leases) == 2
        for bootstrap_lease in bootstrap_leases:
            complete_component_work(session, bootstrap_lease)

        related_verdict = session.execute(
            select(RelationVerdict).where(
                RelationVerdict.left_atomic_id == second_atomic.id,
                RelationVerdict.right_atomic_id == third_atomic.id,
                RelationVerdict.algorithm_version == RELATION_VERSION,
            )
        ).scalar_one()
        related_verdict.decision = "same_event"
        session.flush()
        rebuild_component_closure(session, {third_atomic.id})
        expanded = load_same_event_components(session)[0]
        assert expanded.id == stable_component_id
        assert expanded.revision == initial_component_revision + 1
        assert expanded.atomic_ids == [first_atomic.id, second_atomic.id, third_atomic.id]

        related_verdict.decision = "different_event"
        session.flush()
        rebuild_component_closure(session, {third_atomic.id})
        component = load_same_event_components(session)[0]
        assert component.id == stable_component_id
        assert component.revision == initial_component_revision + 2
        assert component.atomic_ids == [first_atomic.id, second_atomic.id]

        enqueue_component_work(session, {first_atomic.id}, reason="test_generation_1")
        component_leases = claim_component_work(session, limit=1)
        assert len(component_leases) == 1
        first_generation = component_leases[0].generation
        enqueue_component_work(session, {first_atomic.id}, reason="test_generation_2")
        complete_component_work(session, component_leases[0])
        second_generation_lease = claim_component_work(session, limit=1)[0]
        assert second_generation_lease.generation == first_generation + 1
        complete_component_work(session, second_generation_lease)

        fourth_fifth = RelationVerdict(
            left_atomic_id=fourth_atomic.id,
            right_atomic_id=fifth_atomic.id,
            decision="same_event",
            confidence=0.96,
            reason="second_component",
            algorithm_version=RELATION_VERSION,
        )
        session.add(fourth_fifth)
        session.flush()
        rebuild_component_closure(session, {fourth_atomic.id})
        two_components = load_same_event_components(session)
        assert len(two_components) == 2
        secondary_component = next(
            item for item in two_components if fourth_atomic.id in item.atomic_ids
        )

        merge_edge = RelationVerdict(
            left_atomic_id=second_atomic.id,
            right_atomic_id=fourth_atomic.id,
            decision="same_event",
            confidence=0.94,
            reason="component_merge",
            algorithm_version=RELATION_VERSION,
        )
        session.add(merge_edge)
        session.flush()
        rebuild_component_closure(session, {fourth_atomic.id})
        merged_component = load_same_event_components(session)
        assert len(merged_component) == 1
        assert merged_component[0].id == stable_component_id
        superseded_component = session.get(
            SemanticRelationComponent,
            secondary_component.id,
        )
        assert superseded_component is not None
        assert superseded_component.status == "superseded"

        merge_edge.decision = "different_event"
        session.flush()
        rebuild_component_closure(session, {fourth_atomic.id})
        split_components = load_same_event_components(session)
        assert len(split_components) == 2
        component = next(item for item in split_components if first_atomic.id in item.atomic_ids)
        assert component.id == stable_component_id

        candidate = RelationCandidate(
            left_atomic_id=first_atomic.id,
            right_atomic_id=second_atomic.id,
            shared_entity="vendor:product",
            algorithm_version=RELATION_VERSION,
            max_attempts=1,
        )
        session.add(candidate)
        session.flush()
        leases = claim_candidate_queue(session, limit=1)
        assert len(leases) == 1
        assert candidate.status == "running"
        assert fail_candidate(session, leases[0], RuntimeError("deliberate failure"))
        assert candidate.status == "failed"
        assert candidate.lease_token is None
        assert candidate.error == "RuntimeError: deliberate failure"

        merged_claims = merge_claims(
            [
                SourceClaim(
                    atomic_event_id=first_atomic.id,
                    document_id=first_document.id,
                    claim_type="status",
                    text="The incident is confirmed.",
                    normalized_value={"state": "confirmed"},
                    confidence=0.95,
                    evidence_excerpt="confirmed",
                    evidence_field="body",
                ),
                SourceClaim(
                    atomic_event_id=second_atomic.id,
                    document_id=second_document.id,
                    claim_type="status",
                    text="The incident is denied.",
                    normalized_value={"state": "denied"},
                    confidence=0.9,
                    evidence_excerpt="denied",
                    evidence_field="body",
                ),
            ]
        )
        assert {item.status for item in merged_claims} == {"disputed"}
        preview = build_promotion_preview(
            fingerprint=component.fingerprint,
            title="Promoted incident",
            summary="Two sources report conflicting status.",
            event_type="incident",
            topic="security_for_ai",
            category="general",
            document_ids=[first_document.id, second_document.id],
            merged_claim_count=len(merged_claims),
            first_seen_at=NOW,
            last_seen_at=NOW,
        )
        event = Event(
            fingerprint=component.fingerprint,
            event_type="incident",
            topic="security_for_ai",
            category="general",
            title="Original title",
            summary="Original summary",
            status="detected",
            score=55,
            evidence_level="B",
            cluster_version="cluster-v2",
            first_seen_at=NOW,
            last_seen_at=NOW,
            current_version=1,
        )
        session.add(event)
        session.flush()
        session.add(
            EventDocument(
                event_id=event.id,
                document_id=third_document.id,
                stance="support",
                evidence_level="B",
                relation_reason="original",
            )
        )
        old_claim = Claim(
            event_id=event.id,
            claim_key="manual:original",
            claim_type="summary",
            text="Original claim",
            normalized_value={},
            status="supported",
            confidence=0.8,
        )
        session.add(old_claim)
        session.flush()
        session.add(
            ClaimEvidence(
                claim_id=old_claim.id,
                document_id=third_document.id,
                stance="support",
                evidence_level="B",
            )
        )
        session.flush()

        promotion, changed = apply_promotion(
            session,
            preview,
            merged_claims,
            atomic_ids=component.atomic_ids,
            relation_component_id=component.id,
            component_key=component.component_key,
            component_revision=component.revision,
        )
        session.flush()
        assert changed
        assert not promotion.created_event
        assert promotion.before_state is not None
        assert event.title == "Promoted incident"
        evidence_stances = set(
            session.execute(
                select(ClaimEvidence.stance)
                .join(Claim, Claim.id == ClaimEvidence.claim_id)
                .where(Claim.event_id == event.id, Claim.claim_key.like("merged:%"))
            ).scalars()
        )
        assert evidence_stances == {"support", "contradict"}

        same_promotion, changed_again = apply_promotion(
            session,
            preview,
            merged_claims,
            atomic_ids=component.atomic_ids,
            relation_component_id=component.id,
            component_key=component.component_key,
            component_revision=component.revision,
        )
        assert same_promotion.id == promotion.id
        assert not changed_again

        rolled_back, rollback_changed = rollback_promotion(session, promotion.id)
        session.flush()
        assert rollback_changed
        assert rolled_back.status == "rolled_back"
        assert event.title == "Original title"
        restored_documents = list(
            session.execute(
                select(EventDocument.document_id).where(EventDocument.event_id == event.id)
            ).scalars()
        )
        assert restored_documents == [third_document.id]
        restored_claims = list(
            session.execute(select(Claim.claim_key).where(Claim.event_id == event.id)).scalars()
        )
        assert restored_claims == ["manual:original"]
        _, rollback_changed_again = rollback_promotion(session, promotion.id)
        assert not rollback_changed_again
        reapplied, reapply_changed = apply_promotion(
            session,
            preview,
            merged_claims,
            atomic_ids=component.atomic_ids,
            relation_component_id=component.id,
            component_key=component.component_key,
            component_revision=component.revision,
        )
        assert reapply_changed
        assert reapplied.rolled_back_at is None
        _, second_rollback_changed = rollback_promotion(session, promotion.id)
        assert second_rollback_changed

        related_verdict.decision = "same_event"
        session.flush()
        rebuild_component_closure(session, {third_atomic.id})
        revised_component = load_same_event_components(session)[0]
        with pytest.raises(RuntimeError, match=r"component changed|membership changed"):
            apply_promotion(
                session,
                preview,
                merged_claims,
                atomic_ids=component.atomic_ids,
                relation_component_id=component.id,
                component_key=component.component_key,
                component_revision=component.revision,
            )
        revised_promotion, revised_changed = apply_promotion(
            session,
            preview,
            merged_claims,
            atomic_ids=revised_component.atomic_ids,
            relation_component_id=revised_component.id,
            component_key=revised_component.component_key,
            component_revision=revised_component.revision,
        )
        assert revised_changed
        assert revised_promotion.id != promotion.id
        assert revised_promotion.component_revision > promotion.component_revision
        _, revised_rollback = rollback_promotion(session, revised_promotion.id)
        assert revised_rollback

        first_snapshot = generate_daily_snapshot(
            session,
            natural_date=NOW.date(),
            timezone="UTC",
        )
        second_snapshot = generate_daily_snapshot(
            session,
            natural_date=NOW.date(),
            timezone="UTC",
        )
        assert second_snapshot.id == first_snapshot.id
        assert first_snapshot.revision == 1
        no_snapshot, no_items = read_daily_snapshot(
            session,
            natural_date=NOW.date(),
            timezone="UTC",
            category=None,
            as_of=first_snapshot.generated_at - timedelta(microseconds=1),
            limit=100,
            min_score=0,
        )
        assert no_snapshot is None
        assert no_items == []
        stored_snapshot, items = read_daily_snapshot(
            session,
            natural_date=NOW.date(),
            timezone="UTC",
            category=None,
            as_of=first_snapshot.generated_at,
            limit=100,
            min_score=0,
        )
        assert stored_snapshot is not None
        assert stored_snapshot.id == first_snapshot.id
        assert [item["id"] for item in items] == [event.id]

        second_document.source_status = "retired"
        fourth_document = session.get(Document, fourth_atomic.document_id)
        fifth_document = session.get(Document, fifth_atomic.document_id)
        assert fourth_document is not None and fifth_document is not None
        fourth_document.source_status = "retired"
        fifth_document.source_status = "retired"
        session.flush()
        assert enqueue_stale_component_work(session, limit=20) >= 1
        stale_leases = claim_component_work(session, limit=10)
        assert stale_leases
        for stale_lease in stale_leases:
            complete_component_work(session, stale_lease)
        assert load_same_event_components(session) == []
    finally:
        session.close()
        transaction.rollback()
        connection.close()
        engine.dispose()
