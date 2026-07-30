"""Repositories — the only layer that maps domain objects to/from ORM rows.

Includes registry sync, DB-lease endpoint claiming (plan 修正 5: DB is the
single scheduling source of truth) and idempotent raw-item persistence
(先存 RawItem before advancing the checkpoint — MVP §3).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from secrets import randbelow

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ai_security_hot.config.sources import SourceRegistry
from ai_security_hot.connectors.base import Checkpoint
from ai_security_hot.domain.enums import PipelineStage
from ai_security_hot.domain.models import RawItem as RawItemDTO
from ai_security_hot.models.tables import Document, FetchRun, RawItem, Source, SourceEndpoint


def _reset_endpoint_state_for_url_change(
    row: SourceEndpoint, *, now: datetime
) -> None:
    """Start a fresh HTTP/health checkpoint when an endpoint URL changes."""
    row.etag = None
    row.last_modified = None
    row.cursor = None
    row.last_published_at = None
    row.last_fetched_at = None
    row.last_success_at = None
    row.content_hash = None
    row.consecutive_failures = 0
    row.status = "active"
    row.last_error = None
    row.next_run_at = now
    row.lease_until = None


def sync_registry(session: Session, registry: SourceRegistry) -> None:
    """Upsert sources + endpoints from sources.yaml into the DB."""
    for s in registry.sources:
        session.merge(Source(id=s.id, name=s.name, trust_tier=s.trust_tier.value,
                             language=s.language, org=s.org))
    for ep in registry.endpoints:
        row = session.get(SourceEndpoint, ep.id)
        policy_json = {
            "schedule": ep.schedule.model_dump(),
            "fetch": ep.fetch.model_dump(),
            "topics": ep.topics,
            "options": ep.options,
        }
        if row is None:
            session.add(SourceEndpoint(
                id=ep.id, source_id=ep.source_id, connector=ep.connector.value,
                parser=ep.parser, url=ep.url, enabled=ep.enabled,
                priority=ep.priority.value, trust_tier=ep.trust_tier.value,
                language=ep.language, egress_route=ep.egress.route.value,
                policy=policy_json, next_run_at=datetime.now(UTC),
            ))
        else:
            url_changed = row.url != ep.url
            row.source_id = ep.source_id
            row.priority = ep.priority.value
            row.trust_tier = ep.trust_tier.value
            row.language = ep.language
            row.connector = ep.connector.value
            row.parser = ep.parser
            row.url = ep.url
            row.enabled = ep.enabled
            row.egress_route = ep.egress.route.value
            row.policy = policy_json
            if url_changed:
                _reset_endpoint_state_for_url_change(row, now=datetime.now(UTC))
    session.commit()


def claim_due_endpoints(session: Session, limit: int, lease_seconds: int = 300) -> list[str]:
    """Atomically lease endpoints whose next_run_at is due (plan 修正 5).

    Uses SELECT ... FOR UPDATE SKIP LOCKED so multiple workers never grab the
    same endpoint.
    """
    now = datetime.now(UTC)
    stmt = (
        select(SourceEndpoint.id)
        .where(
            SourceEndpoint.enabled.is_(True),
            SourceEndpoint.next_run_at <= now,
            (SourceEndpoint.lease_until.is_(None)) | (SourceEndpoint.lease_until < now),
        )
        .order_by(SourceEndpoint.next_run_at)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    ids = list(session.execute(stmt).scalars().all())
    if ids:
        session.execute(
            update(SourceEndpoint)
            .where(SourceEndpoint.id.in_(ids))
            .values(lease_until=now + timedelta(seconds=lease_seconds))
        )
    session.commit()
    return ids


def load_checkpoint(
    session: Session,
    endpoint_id: str,
    *,
    known_limit: int = 5000,
) -> Checkpoint:
    row = session.get(SourceEndpoint, endpoint_id)
    if row is None:
        raise KeyError(f"unknown endpoint: {endpoint_id}")

    # Descending order makes the first row for a native id its newest version.
    known_rows = session.execute(
        select(RawItem.native_id, RawItem.content_hash)
        .where(RawItem.endpoint_id == endpoint_id)
        .order_by(RawItem.id.desc())
        .limit(known_limit)
    ).all()
    known_content_hashes: dict[str, str] = {}
    for native_id, content_hash in known_rows:
        known_content_hashes.setdefault(native_id, content_hash)

    return Checkpoint(
        etag=row.etag,
        last_modified=row.last_modified,
        cursor=row.cursor,
        last_success_at=row.last_success_at,
        last_published_at=row.last_published_at,
        known_content_hashes=known_content_hashes,
    )


def persist_raw_items(session: Session, items: list[RawItemDTO]) -> int:
    """Idempotent insert of raw items; returns count of newly inserted rows.

    ON CONFLICT DO NOTHING on (endpoint_id, native_id, content_hash), so an
    unchanged re-poll is a no-op while a source-side revision creates a new
    immutable RawItem version.
    """
    new = 0
    for it in items:
        stmt = (
            pg_insert(RawItem)
            .values(
                endpoint_id=it.endpoint_id, source_id=it.source_id, native_id=it.native_id,
                request_url=it.request_url, final_url=it.final_url, http_status=it.http_status,
                published_at=it.published_at, fetched_at=it.fetched_at, language=it.language,
                content_hash=it.content_hash, blob_ref=it.blob_ref, raw_text=it.raw_text,
                canonical_url=it.canonical_url, connector_version=it.connector_version,
                stage=PipelineStage.FETCHED.value,
            )
            .on_conflict_do_nothing()
            .returning(RawItem.id)
        )
        if session.execute(stmt).first() is not None:
            new += 1
    session.commit()
    return new


def advance_checkpoint(
    session: Session, endpoint_id: str, checkpoint: Checkpoint,
    *,
    success: bool,
    error: str | None,
    interval_minutes: int,
    jitter_seconds: int = 0,
) -> None:
    """Persist checkpoint + reschedule + clear the lease (after raw items saved)."""
    now = datetime.now(UTC)
    row = session.get(SourceEndpoint, endpoint_id)
    if row is None:
        raise KeyError(f"unknown endpoint: {endpoint_id}")
    row.etag = checkpoint.etag
    row.last_modified = checkpoint.last_modified
    row.cursor = checkpoint.cursor
    if checkpoint.last_published_at is not None:
        row.last_published_at = checkpoint.last_published_at
    row.last_fetched_at = now
    row.lease_until = None
    jitter = randbelow(jitter_seconds + 1) if jitter_seconds > 0 else 0
    if success:
        row.last_success_at = now
        row.next_run_at = now + timedelta(minutes=interval_minutes, seconds=jitter)
        row.consecutive_failures = 0
        row.status = "active"
        row.last_error = None
    else:
        row.consecutive_failures += 1
        # Retry quickly at first, then back off up to the normal source interval.
        retry_minutes = min(interval_minutes, 2 ** min(row.consecutive_failures, 10))
        row.next_run_at = now + timedelta(minutes=retry_minutes, seconds=jitter)
        row.last_error = error
        if row.consecutive_failures >= 5:
            row.status = "degraded"
    session.commit()


def record_fetch_run(
    session: Session, endpoint_id: str, *, status: str,
    items_fetched: int, items_new: int, error: str | None,
    started_at: datetime | None = None,
) -> None:
    session.add(FetchRun(
        endpoint_id=endpoint_id, started_at=started_at or datetime.now(UTC),
        finished_at=datetime.now(UTC), status=status,
        items_fetched=items_fetched, items_new=items_new, error=error,
    ))
    session.commit()


def claim_stage_items(
    session: Session, stage: PipelineStage, limit: int, lease_seconds: int = 300
) -> list[RawItem]:
    """Lease raw items in a given stage for processing (plan 修正 1)."""
    now = datetime.now(UTC)
    stmt = (
        select(RawItem)
        .where(
            RawItem.stage == stage.value,
            (RawItem.stage_lease_until.is_(None)) | (RawItem.stage_lease_until < now),
        )
        .order_by(RawItem.id)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    rows = list(session.execute(stmt).scalars().all())
    for r in rows:
        r.stage_lease_until = now + timedelta(seconds=lease_seconds)
    session.commit()
    return rows


def persist_document(
    session: Session, raw_item_id: int, doc, next_stage: PipelineStage
) -> None:
    """Store a normalized document and advance the raw item's stage."""
    session.add(Document(
        raw_item_id=raw_item_id, endpoint_id=doc.endpoint_id,
        title_original=doc.title_original, title_zh=doc.title_zh, body_text=doc.body_text,
        canonical_url=doc.canonical_url, author=doc.author, org=doc.org,
        published_at_utc=doc.published_at_utc, language=doc.language,
        identifiers={"cve": doc.cve_ids, "ghsa": doc.ghsa_ids,
                     "cnvd": doc.cnvd_ids, "cwe": doc.cwe_ids},
        entities=doc.entities, parse_quality=doc.parse_quality,
    ))
    raw = session.get(RawItem, raw_item_id)
    if raw is None:
        raise KeyError(f"unknown raw_item: {raw_item_id}")
    raw.stage = next_stage.value
    raw.stage_lease_until = None
    raw.parser_version = doc.__class__.__name__
    session.commit()


def claim_fulltext_candidates(
    session: Session, endpoint_ids: list[str], limit: int, lease_seconds: int = 300
) -> list[tuple[RawItem, Document]]:
    """Lease NORMALIZED raw items (+ their document) from fulltext-enabled
    endpoints, so the fulltext stage can second-fetch the article body."""
    if not endpoint_ids:
        return []
    now = datetime.now(UTC)
    stmt = (
        select(RawItem, Document)
        .join(Document, Document.raw_item_id == RawItem.id)
        .where(
            RawItem.stage == PipelineStage.NORMALIZED.value,
            RawItem.endpoint_id.in_(endpoint_ids),
            (RawItem.stage_lease_until.is_(None)) | (RawItem.stage_lease_until < now),
        )
        .order_by(RawItem.id)
        .limit(limit)
        .with_for_update(skip_locked=True, of=RawItem)
    )
    rows = list(session.execute(stmt).all())
    for raw, _doc in rows:
        raw.stage_lease_until = now + timedelta(seconds=lease_seconds)
    session.commit()
    return [(raw, doc) for raw, doc in rows]


def apply_fulltext(
    session: Session,
    raw_item_id: int,
    document_id: int,
    *,
    body_text: str | None,
    parse_quality: float | None,
) -> None:
    """Update a document's body with second-fetched full text and mark the
    raw item DONE. If body_text is None (fetch failed / SPA), leave the body
    but still advance so we don't re-fetch every tick."""
    raw = session.get(RawItem, raw_item_id)
    doc = session.get(Document, document_id)
    if raw is None or doc is None:
        raise KeyError(f"unknown raw_item/document: {raw_item_id}/{document_id}")
    if body_text:
        doc.body_text = body_text
        if parse_quality is not None:
            doc.parse_quality = parse_quality
    raw.stage = PipelineStage.DONE.value
    raw.stage_lease_until = None
    session.commit()


def iter_documents_for_export(
    session: Session,
    *,
    source: str | None = None,
    min_quality: float = 0.0,
    limit: int | None = None,
) -> Iterator[dict]:
    """Stream documents as plain dicts for export (JSON/JSONL/CSV).

    Streaming (yield_per) keeps memory flat even for large exports.
    """
    stmt = (
        select(Document)
        .where(Document.parse_quality >= min_quality)
        .order_by(Document.id)
        .execution_options(yield_per=500)
    )
    if source:
        stmt = stmt.where(Document.endpoint_id == source)
    if limit is not None:
        stmt = stmt.limit(limit)

    for d in session.execute(stmt).scalars():
        ids = d.identifiers or {}
        yield {
            "id": d.id,
            "source": d.endpoint_id,
            "title": d.title_original,
            "title_zh": d.title_zh,
            "url": d.canonical_url,
            "org": d.org,
            "language": d.language,
            "published_at": d.published_at_utc.isoformat() if d.published_at_utc else None,
            "cve": ids.get("cve", []),
            "ghsa": ids.get("ghsa", []),
            "cnvd": ids.get("cnvd", []),
            "cwe": ids.get("cwe", []),
            "parse_quality": d.parse_quality,
        }


def claim_unclassified_documents(
    session: Session,
    limit: int,
    *,
    rule_version: str | None = None,
) -> list[Document]:
    """Fetch new documents and rule-classified documents on an older taxonomy."""
    needs_classification = Document.classified_at.is_(None)
    if rule_version:
        needs_classification = needs_classification | (
            (Document.classify_method == "rule")
            & (
                Document.classify_rule_version.is_(None)
                | (Document.classify_rule_version != rule_version)
            )
        )
    stmt = (
        select(Document)
        .where(needs_classification)
        .order_by(Document.id)
        .limit(limit)
    )
    return list(session.execute(stmt).scalars().all())


def apply_classification(session: Session, document_id: int, cls) -> None:
    """Write a Classification back to the document row (+ provenance)."""
    doc = session.get(Document, document_id)
    if doc is None:
        raise KeyError(f"unknown document: {document_id}")
    doc.tech_directions = cls.tech_directions
    doc.company_models = cls.company_models
    doc.classified_event_type = cls.event_type
    doc.classify_confidence = cls.confidence
    doc.classify_method = cls.method
    doc.classify_model_version = cls.model_version
    doc.classify_prompt_version = cls.prompt_version
    doc.classify_rule_version = cls.rule_version
    doc.classify_input_hash = cls.input_hash
    doc.classified_at = datetime.now(UTC)
    session.commit()
