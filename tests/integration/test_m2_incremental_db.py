"""Transactional PostgreSQL integration test for the M2.1 local lifecycle."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from ai_security_hot.events.intelligence import CLUSTER_VERSION, DEDUPE_VERSION
from ai_security_hot.models.tables import (
    CandidateReview,
    Claim,
    ClaimEvidence,
    Document,
    DocumentBlockToken,
    DocumentBlockTokenStat,
    DuplicateComponent,
    Event,
    EventVersion,
    M2WorkItem,
    RawItem,
    Source,
    SourceEndpoint,
)
from ai_security_hot.storage import event_repository

NOW = datetime(2026, 7, 31, 8, 0, tzinfo=UTC)


def _add_document(
    session: Session,
    endpoint_id: str,
    native_id: str,
    title: str,
    url: str,
    *,
    quality: float,
    body: str | None = None,
) -> Document:
    raw = RawItem(
        endpoint_id=endpoint_id,
        source_id="m2-test-source",
        native_id=native_id,
        request_url=url,
        final_url=url,
        http_status=200,
        published_at=NOW,
        fetched_at=NOW,
        language="en",
        content_hash=(native_id.encode().hex() + "0" * 64)[:64],
        raw_text=title,
        canonical_url=url,
        connector_version="test-v1",
        operation="upsert",
        stage="done",
    )
    session.add(raw)
    session.flush()
    document = Document(
        raw_item_id=raw.id,
        endpoint_id=endpoint_id,
        title_original=title,
        body_text=body or (f"Evidence body for {title}. " * 30),
        canonical_url=url,
        published_at_utc=NOW,
        language="en",
        identifiers={},
        entities={},
        parse_quality=quality,
        source_status="active",
        record_status="published",
        tech_directions=["security_for_ai"],
        company_models=[],
        classified_event_type="news",
    )
    session.add(document)
    session.flush()
    return document


@pytest.mark.db
def test_local_retirement_reselects_master_and_versions_only_affected_events() -> None:
    database_url = os.environ.get("INTEL_DATABASE_URL")
    if not database_url:
        pytest.skip("INTEL_DATABASE_URL is required for PostgreSQL integration tests")
    engine = create_engine(database_url)
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, expire_on_commit=False)
    try:
        session.add(Source(id="m2-test-source", name="M2 test", trust_tier="B"))
        session.add(
            SourceEndpoint(
                id="m2-test-endpoint",
                source_id="m2-test-source",
                connector="rss",
                url="https://m2-test.invalid/feed",
                enabled=True,
                state_version="1",
                priority="P1",
                trust_tier="B",
                egress_route="direct",
                policy={},
                status="active",
            )
        )
        session.flush()
        master = _add_document(
            session,
            "m2-test-endpoint",
            "master",
            "Vendor publishes an important agent security incident report",
            "https://m2-test.invalid/shared-report",
            quality=0.95,
        )
        duplicate = _add_document(
            session,
            "m2-test-endpoint",
            "duplicate",
            "Vendor updates its important agent security incident report",
            "https://m2-test.invalid/shared-report",
            quality=0.75,
        )
        unrelated = _add_document(
            session,
            "m2-test-endpoint",
            "unrelated",
            "Researchers publish a separate LLM safety benchmark",
            "https://m2-test.invalid/unrelated",
            quality=0.9,
        )

        event_repository.backfill_signature_batch(session, limit=100)
        first_dedupe = event_repository.run_local_dedupe(session, limit=100)
        first_cluster = event_repository.run_local_cluster(session, limit=100)
        session.flush()

        assert first_dedupe["affected_documents"] == 3
        assert first_cluster["events_created"] == 2
        assert duplicate.near_dup_of == master.id
        stable_component_id = master.dedupe_component_id
        unrelated_component_id = unrelated.dedupe_component_id
        unrelated_event = session.execute(
            select(Event).where(Event.fingerprint == f"document:{unrelated.id}")
        ).scalar_one()
        unrelated_version = unrelated_event.current_version

        queued = event_repository.enqueue_work(
            session,
            {master.id},
            stage="dedupe",
            reason="test_retirement",
            algorithm_version=DEDUPE_VERSION,
            component_ids={master.id: stable_component_id},
        )
        queued_again = event_repository.enqueue_work(
            session,
            {master.id},
            stage="dedupe",
            reason="duplicate_test_retirement",
            algorithm_version=DEDUPE_VERSION,
            component_ids={master.id: stable_component_id},
        )
        assert queued == 1
        assert queued_again == 0
        event_repository.enqueue_work(
            session,
            {master.id},
            stage="cluster",
            reason="test_retirement",
            algorithm_version=CLUSTER_VERSION,
            component_ids={master.id: stable_component_id},
        )
        master.source_status = "retired"
        master.source_status_reason = "test_retirement"
        master.withdrawn_at = NOW
        master.dedupe_version = DEDUPE_VERSION
        master.cluster_version = None
        session.flush()

        second_dedupe = event_repository.run_local_dedupe(session, limit=10)
        second_cluster = event_repository.run_local_cluster(session, limit=10)
        session.flush()

        # Candidate blocking may conservatively inspect a nearby document, but
        # it must not fall back to the complete corpus. Unchanged candidates do
        # not invalidate their event component.
        assert second_dedupe["affected_documents"] < first_dedupe["affected_documents"]
        assert second_cluster["affected_documents"] == 1
        assert duplicate.near_dup_of is None
        assert duplicate.dedupe_component_id == stable_component_id
        assert unrelated.dedupe_component_id == unrelated_component_id
        assert unrelated_event.current_version == unrelated_version

        stable_component = session.get(DuplicateComponent, stable_component_id)
        assert stable_component is not None
        assert stable_component.master_document_id == duplicate.id

        old_event = session.execute(
            select(Event).where(Event.fingerprint == f"document:{master.id}")
        ).scalar_one()
        new_event = session.execute(
            select(Event).where(Event.fingerprint == f"document:{duplicate.id}")
        ).scalar_one()
        assert old_event.status == "superseded"
        assert new_event.status == "detected"
        assert (
            session.execute(
                select(func.count())
                .select_from(EventVersion)
                .where(EventVersion.event_id == old_event.id)
            ).scalar_one()
            >= 2
        )

        claims = list(
            session.execute(select(Claim).where(Claim.event_id == new_event.id)).scalars()
        )
        assert {claim.claim_type for claim in claims} == {"event_summary"}
        assert (
            session.execute(
                select(func.count())
                .select_from(ClaimEvidence)
                .where(
                    ClaimEvidence.claim_id.in_([claim.id for claim in claims]),
                    ClaimEvidence.document_id == duplicate.id,
                )
            ).scalar_one()
            == 1
        )

        version_before_claim = new_event.current_version
        claim_result = event_repository.upsert_manual_claim(
            session,
            int(new_event.id),
            claim_key="impact:production-exploitation",
            claim_type="impact",
            text="Production exploitation is disputed by available evidence.",
            status="disputed",
            confidence=0.5,
            evidence=[
                {
                    "document_id": duplicate.id,
                    "stance": "support",
                    "evidence_level": "B",
                },
                {
                    "document_id": unrelated.id,
                    "stance": "contradict",
                    "evidence_level": "B",
                },
            ],
        )
        session.flush()
        assert claim_result["event_version"] == version_before_claim + 1
        claim_version = session.execute(
            select(EventVersion).where(
                EventVersion.event_id == new_event.id,
                EventVersion.version == claim_result["event_version"],
            )
        ).scalar_one()
        assert claim_version.change_type == "claim_changed"
        assert claim_version.diff["claims_added"] == ["impact:production-exploitation"]
        manual_claim = next(
            row
            for row in claim_version.snapshot["claims"]
            if row["claim_key"] == "impact:production-exploitation"
        )
        assert {row["stance"] for row in manual_claim["evidence"]} == {
            "support",
            "contradict",
        }

        review = CandidateReview(
            left_document_id=duplicate.id,
            right_document_id=unrelated.id,
            candidate_kind="semantic_candidate",
            score=0.84,
            features={"title_score": 84.0},
            status="pending",
            algorithm_version=DEDUPE_VERSION,
        )
        session.add(review)
        session.flush()
        review_result = event_repository.resolve_candidate_review(
            session,
            int(review.id),
            decision="rejected",
            reviewer="pytest",
            notes="different events",
        )
        session.flush()
        assert review_result["status"] == "rejected"
        assert (
            session.execute(
                select(func.count()).select_from(M2WorkItem).where(M2WorkItem.status == "pending")
            ).scalar_one()
            >= 2
        )
    finally:
        session.close()
        transaction.rollback()
        connection.close()
        engine.dispose()


@pytest.mark.db
def test_high_frequency_exact_hash_bucket_is_bounded() -> None:
    database_url = os.environ.get("INTEL_DATABASE_URL")
    if not database_url:
        pytest.skip("INTEL_DATABASE_URL is required for PostgreSQL integration tests")
    engine = create_engine(database_url)
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, expire_on_commit=False)
    try:
        session.add(Source(id="m2-bucket-source", name="M2 bucket test", trust_tier="B"))
        session.add(
            SourceEndpoint(
                id="m2-bucket-endpoint",
                source_id="m2-bucket-source",
                connector="rest",
                url="https://m2-bucket.invalid/catalogue",
                enabled=True,
                state_version="1",
                priority="P1",
                trust_tier="B",
                egress_route="direct",
                policy={},
                status="active",
            )
        )
        session.flush()
        document_ids = [
            _add_document(
                session,
                "m2-bucket-endpoint",
                f"record-{index}",
                f"R{index:04d}",
                f"https://m2-bucket.invalid/catalogue#record-{index}",
                quality=0.8,
                body=" ".join(f"token{index:04d}{offset:02d}" for offset in range(24)),
            ).id
            for index in range(101)
        ]
        event_repository.backfill_signature_batch(session, limit=200)
        first_token = session.execute(
            select(DocumentBlockToken.token)
            .where(DocumentBlockToken.document_id == document_ids[0])
            .limit(1)
        ).scalar_one()
        token_stat = session.get(DocumentBlockTokenStat, first_token)

        pairs, truncated = event_repository._candidate_pairs(session, document_ids, max_pairs=100)

        assert token_stat is not None
        assert token_stat.active_document_count >= 1
        assert not truncated
        assert len(pairs) < 100
    finally:
        session.close()
        transaction.rollback()
        connection.close()
        engine.dispose()
