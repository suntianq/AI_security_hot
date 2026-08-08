"""PostgreSQL integration test for daily hotspot snapshot algorithm version."""

from __future__ import annotations

import os
from datetime import UTC, date, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from ai_security_hot.events.intelligence import SCORE_VERSION
from ai_security_hot.models.tables import (
    DailyHotspotItem,
    Document,
    Event,
    EventDocument,
    RawItem,
    Source,
    SourceEndpoint,
)
from ai_security_hot.snapshots import generate_daily_snapshot

NOW = datetime(2026, 8, 8, 4, 0, tzinfo=UTC)
pytestmark = pytest.mark.db


@pytest.fixture
def db_session() -> object:
    database_url = os.environ.get("INTEL_DATABASE_URL")
    if not database_url:
        pytest.skip("INTEL_DATABASE_URL is required for PostgreSQL integration tests")
    engine = create_engine(database_url)
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, expire_on_commit=False)
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()
        engine.dispose()


def _seed(db_session: Session) -> tuple[Event, int]:
    db_session.add(Source(id="snap-test-source", name="Snap test", trust_tier="A"))
    db_session.flush()
    db_session.add(
        SourceEndpoint(
            id="snap-test-endpoint",
            source_id="snap-test-source",
            connector="rss",
            url="https://snap-test.invalid/feed",
            enabled=True,
            state_version="1",
            priority="P1",
            trust_tier="A",
            egress_route="direct",
            policy={},
            status="active",
        )
    )
    db_session.flush()
    url = "https://snap-test.invalid/d/1"
    raw = RawItem(
        endpoint_id="snap-test-endpoint",
        source_id="snap-test-source",
        native_id="snap-1",
        request_url=url,
        final_url=url,
        http_status=200,
        published_at=NOW,
        fetched_at=NOW,
        language="en",
        content_hash="1" * 64,
        raw_text="Snapshot test body.",
        canonical_url=url,
        connector_version="test-v1",
        stage="done",
    )
    db_session.add(raw)
    db_session.flush()
    doc = Document(
        raw_item_id=raw.id,
        endpoint_id="snap-test-endpoint",
        title_original="Snapshot test event",
        body_text="Snapshot test body.",
        canonical_url=url,
        published_at_utc=NOW,
        language="en",
        identifiers={},
        entities={},
        parse_quality=0.9,
        source_status="active",
        record_status="published",
        tech_directions=[],
        company_models=[],
        classified_event_type="news",
        classified_at=NOW,
        dedupe_version="dedupe-test-v1",
    )
    db_session.add(doc)
    db_session.flush()
    event = Event(
        fingerprint="snap:test-fingerprint",
        event_type="news",
        topic="llm",
        category="general",
        title="Snapshot test event",
        status="detected",
        score=80,
        evidence_level="A",
        cluster_version="cluster-v2",
        first_seen_at=NOW,
        last_seen_at=NOW,
        current_version=1,
    )
    db_session.add(event)
    db_session.flush()
    db_session.add(EventDocument(event_id=event.id, document_id=doc.id, stance="support"))
    db_session.flush()
    return event, int(doc.id)


def test_daily_snapshot_records_algorithm_version(db_session: Session) -> None:
    event, _doc_id = _seed(db_session)
    snapshot = generate_daily_snapshot(
        db_session,
        natural_date=date(2026, 8, 8),
        timezone="Asia/Shanghai",
        limit=100,
    )
    assert snapshot.algorithm_version == SCORE_VERSION
    # The dev DB may hold other real events for the day, so only assert our
    # seeded event is present (with its score).
    item = (
        db_session.query(DailyHotspotItem)
        .filter_by(snapshot_id=snapshot.id, event_id=event.id)
        .one()
    )
    assert item.payload["score"] == 80
