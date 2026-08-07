"""PostgreSQL integration tests for the public feed + search services.

These read the real current-document corpus, so each test bounds the query with
a ``since`` far in the future (2030) and unique tokens to stay deterministic no
matter what production data the database already holds.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ai_security_hot.models.tables import Document, RawItem, Source, SourceEndpoint
from ai_security_hot.services.feed import build_feed, search_documents

BASE = datetime(2030, 1, 1, tzinfo=UTC)  # isolation bound: nothing real is fetched this late
pytestmark = pytest.mark.db

_COUNTER = 0


def _ensure_endpoint(session: Session, endpoint_id: str) -> None:
    """Make the module endpoint exist; a no-op when production already has it."""
    session.execute(
        pg_insert(SourceEndpoint)
        .values(
            id=endpoint_id,
            source_id="feed-test-source",
            connector="rss",
            url=f"https://feed-test.invalid/{endpoint_id}",
            enabled=True,
            state_version="1",
            priority="P1",
            trust_tier="A",
            egress_route="direct",
            policy={},
            status="active",
        )
        .on_conflict_do_nothing(index_elements=["id"])
    )


def _add_doc(
    session: Session,
    *,
    endpoint: str,
    title: str,
    fetched_minutes: int,
    body: str | None = None,
    tech: list[str] | None = None,
    entities: dict | None = None,
    source_status: str = "active",
    record_status: str = "published",
) -> Document:
    """Seed one RawItem + Document pair fetched at BASE + fetched_minutes."""
    global _COUNTER
    _COUNTER += 1
    ordinal = _COUNTER
    url = f"https://feed-test.invalid/d/{ordinal}"
    raw = RawItem(
        endpoint_id=endpoint,
        source_id="feed-test-source",
        native_id=f"feed-{ordinal}",
        request_url=url,
        final_url=url,
        http_status=200,
        published_at=BASE + timedelta(minutes=fetched_minutes),
        fetched_at=BASE + timedelta(minutes=fetched_minutes),
        language="en",
        content_hash=f"{ordinal:064x}",
        raw_text=body or title,
        canonical_url=url,
        connector_version="test-v1",
        stage="done",
    )
    session.add(raw)
    session.flush()
    document = Document(
        raw_item_id=raw.id,
        endpoint_id=endpoint,
        title_original=title,
        body_text=body or title,
        canonical_url=url,
        published_at_utc=BASE + timedelta(minutes=fetched_minutes),
        language="en",
        identifiers={},
        entities=entities or {},
        parse_quality=1.0,
        source_status=source_status,
        record_status=record_status,
        tech_directions=tech or [],
        company_models=[],
        classified_event_type="news",
        classified_at=BASE,
        dedupe_version="dedupe-test-v1",
    )
    session.add(document)
    session.flush()
    return document


@pytest.fixture
def db_session() -> Iterator[Session]:
    database_url = os.environ.get("INTEL_DATABASE_URL")
    if not database_url:
        pytest.skip("INTEL_DATABASE_URL is required for PostgreSQL integration tests")
    engine = create_engine(database_url)
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, expire_on_commit=False)
    session.add(Source(id="feed-test-source", name="Feed test", trust_tier="A"))
    session.flush()
    for ep in ("aihot-selected-api", "nvd-recent", "arxiv-ai-llm"):
        _ensure_endpoint(session, ep)
    session.flush()
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()
        engine.dispose()


def test_feed_orders_by_fetched_desc_and_paginates(db_session: Session) -> None:
    docs = [
        _add_doc(
            db_session,
            endpoint="aihot-selected-api",
            title=f"Feed page doc {i}",
            fetched_minutes=i,
        )
        for i in range(1, 6)
    ]
    db_session.flush()

    seen: list[int] = []
    cursor: datetime | None = None
    while True:
        page = build_feed(db_session, limit=2, since=BASE, before=cursor)
        seen.extend(d["id"] for d in page["items"])
        next_before = page["next_before"]
        if next_before is None:
            break
        cursor = datetime.fromisoformat(next_before)
        assert len(page["items"]) <= 3  # limit + 1: extra row is examined for the cursor
    expected = [d.id for d in reversed(docs)]
    assert seen == expected


def test_feed_filters_module_tech_source(db_session: Session) -> None:
    d_news = _add_doc(
        db_session,
        endpoint="aihot-selected-api",
        title="News doc",
        fetched_minutes=1,
        tech=["llm"],
    )
    d_cve = _add_doc(
        db_session,
        endpoint="nvd-recent",
        title="CVE doc",
        fetched_minutes=2,
        entities={"cvss": ["9.8"], "products": ["linux"]},
    )
    d_paper = _add_doc(
        db_session,
        endpoint="arxiv-ai-llm",
        title="Paper doc",
        fetched_minutes=3,
        tech=["llm"],
    )
    db_session.flush()

    cve_ids = [d["id"] for d in build_feed(db_session, since=BASE, module="cve")["items"]]
    news_ids = [d["id"] for d in build_feed(db_session, since=BASE, module="news")["items"]]
    assert cve_ids == [d_cve.id]
    assert news_ids == [d_news.id]
    assert {d["id"] for d in build_feed(db_session, since=BASE, tech_direction="llm")["items"]} == {
        d_news.id,
        d_paper.id,
    }
    nvd_ids = [d["id"] for d in build_feed(db_session, since=BASE, source="nvd-recent")["items"]]
    assert nvd_ids == [d_cve.id]
    assert build_feed(db_session, since=BASE, module="cve")["items"][0]["module"] == "cve"


def test_feed_respects_current_document_conditions(db_session: Session) -> None:
    d_active = _add_doc(
        db_session, endpoint="aihot-selected-api", title="Active doc", fetched_minutes=1
    )
    _add_doc(
        db_session,
        endpoint="aihot-selected-api",
        title="Withdrawn doc",
        fetched_minutes=2,
        record_status="withdrawn",
    )
    _add_doc(
        db_session,
        endpoint="aihot-selected-api",
        title="Retired doc",
        fetched_minutes=3,
        source_status="retired",
    )
    db_session.flush()

    items = build_feed(db_session, since=BASE, limit=10)["items"]
    assert [d["id"] for d in items] == [d_active.id]


def test_feed_since_filter(db_session: Session) -> None:
    d_early = _add_doc(
        db_session, endpoint="aihot-selected-api", title="Early doc", fetched_minutes=1
    )
    d_late = _add_doc(
        db_session, endpoint="aihot-selected-api", title="Late doc", fetched_minutes=10
    )
    db_session.flush()

    items = build_feed(db_session, since=BASE + timedelta(minutes=5))["items"]
    assert [d["id"] for d in items] == [d_late.id]
    assert d_early.id not in [d["id"] for d in items]


def test_search_matches_title_and_body(db_session: Session) -> None:
    d_title = _add_doc(
        db_session,
        endpoint="aihot-selected-api",
        title="FEEDSEARCHTOKEN11 in the title",
        fetched_minutes=1,
    )
    d_body = _add_doc(
        db_session,
        endpoint="aihot-selected-api",
        title="Body-only doc",
        body="Body text mentions FEEDSEARCHTOKEN22",
        fetched_minutes=2,
    )
    db_session.flush()

    title_hits = search_documents(db_session, q="FEEDSEARCHTOKEN11", since=BASE)
    assert title_hits["total"] == 1
    assert title_hits["items"][0]["id"] == d_title.id

    body_hits = search_documents(db_session, q="FEEDSEARCHTOKEN22", since=BASE)
    assert body_hits["total"] == 1
    assert body_hits["items"][0]["id"] == d_body.id

    none_hits = search_documents(db_session, q="FEEDNOSUCHTOKEN", since=BASE)
    assert none_hits["total"] == 0
    assert none_hits["items"] == []


def test_search_pagination_and_total(db_session: Session) -> None:
    for i in range(1, 6):
        _add_doc(
            db_session,
            endpoint="aihot-selected-api",
            title=f"FEEDSEARCHPAGE doc {i}",
            fetched_minutes=i,
        )
    db_session.flush()

    first = search_documents(db_session, q="FEEDSEARCHPAGE", page=1, limit=2, since=BASE)
    assert first["total"] == 5
    assert len(first["items"]) == 2
    last = search_documents(db_session, q="FEEDSEARCHPAGE", page=3, limit=2, since=BASE)
    assert last["total"] == 5
    assert len(last["items"]) == 1


def test_search_excludes_non_current(db_session: Session) -> None:
    _add_doc(
        db_session,
        endpoint="aihot-selected-api",
        title="FEEDSEARCHTOKEN33 withdrawn",
        fetched_minutes=1,
        record_status="withdrawn",
    )
    db_session.flush()

    hits = search_documents(db_session, q="FEEDSEARCHTOKEN33", since=BASE)
    assert hits["total"] == 0
    assert hits["items"] == []
