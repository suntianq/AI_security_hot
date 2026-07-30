"""Live end-to-end crawl test (plan §四 / user requirement: real data).

Runs the real fetch + normalize pipeline against the configured sources and
asserts that real documents with parse_quality land in the DB. Marked `live`
because it makes real network requests; run explicitly with:

    uv run pytest -m live

Skips (does not fail) if the database is unreachable.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import OperationalError

from ai_security_hot.config.sources import load_registry
from ai_security_hot.models.base import session_scope
from ai_security_hot.models.tables import Document, RawItem, SourceEndpoint
from ai_security_hot.pipelines.stages import run_fetch_stage, run_normalize_stage
from ai_security_hot.storage import repositories as repo

pytestmark = pytest.mark.live


def _db_available() -> bool:
    try:
        with session_scope() as s:
            s.execute(select(1))
        return True
    except OperationalError:
        return False


@pytest.mark.skipif(
    os.environ.get("INTEL_RUN_LIVE") != "1",
    reason="set INTEL_RUN_LIVE=1 to run the live crawl test",
)
def test_real_crawl_produces_documents() -> None:
    if not _db_available():
        pytest.skip("database not reachable")

    registry = load_registry()
    with session_scope() as session:
        repo.sync_registry(session, registry)
        legacy = session.get(SourceEndpoint, "aihot-selected-rss")
        replacement = session.get(SourceEndpoint, "aihot-selected-api")
        assert legacy is not None
        assert replacement is not None
        assert legacy.replacement_endpoint_id == replacement.id
        assert legacy.status == "retired"
        first_retired_at = legacy.retired_at
        assert first_retired_at is not None

    # Registry sync is order-independent and idempotent: the retired timestamp
    # must not move every time a worker starts and reloads sources.yaml.
    with session_scope() as session:
        repo.sync_registry(session, registry)
        legacy = session.get(SourceEndpoint, "aihot-selected-rss")
        assert legacy is not None
        assert legacy.retired_at == first_retired_at

    fetch_stats = run_fetch_stage(limit=10)
    assert fetch_stats["endpoints"] >= 1

    # drain normalization
    total_norm = 0
    for _ in range(50):
        s = run_normalize_stage(limit=500)
        total_norm += s["normalized"]
        if s["normalized"] == 0:
            break

    with session_scope() as session:
        raw_count = session.execute(select(func.count()).select_from(RawItem)).scalar_one()
        doc_count = session.execute(select(func.count()).select_from(Document)).scalar_one()
        # at least one real document with a good parse
        good = session.execute(
            select(func.count()).select_from(Document).where(Document.parse_quality >= 0.6)
        ).scalar_one()
        # at least one CVE extracted from the KEV feed
        with_cve = session.execute(
            select(func.count())
            .select_from(Document)
            .where(Document.identifiers["cve"].astext != "[]")
        ).scalar_one()

    assert raw_count > 0, "no raw items fetched"
    assert doc_count > 0, "no documents normalized"
    assert good > 0, "no documents met the minimum parse-quality bar"
    assert with_cve > 0, "no CVE identifiers extracted from KEV feed"
