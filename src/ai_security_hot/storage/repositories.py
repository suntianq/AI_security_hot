"""Repositories — the only layer that maps domain objects to/from ORM rows.

Includes registry sync, DB-lease endpoint claiming (plan 修正 5: DB is the
single scheduling source of truth) and idempotent raw-item persistence
(先存 RawItem before advancing the checkpoint — MVP §3).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from secrets import randbelow, token_urlsafe

from sqlalchemy import delete, func, select, tuple_, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ai_security_hot.config.sources import SourceRegistry
from ai_security_hot.connectors.base import Checkpoint
from ai_security_hot.domain.enums import (
    NON_CURRENT_UPSTREAM_STATUSES,
    DocumentSourceStatus,
    PipelineStage,
    SourceRecordStatus,
    SourceStatus,
)
from ai_security_hot.domain.models import RawItem as RawItemDTO
from ai_security_hot.events.intelligence import (
    CLUSTER_VERSION,
    DEDUPE_VERSION,
    DedupDecision,
    EventDraft,
    IntelDocument,
)
from ai_security_hot.models.tables import (
    Document,
    Event,
    EventDocument,
    FetchRun,
    ModelCache,
    ModelRun,
    RawItem,
    Source,
    SourceEndpoint,
    SourceRecord,
)


def _reset_endpoint_state_for_url_change(row: SourceEndpoint, *, now: datetime) -> None:
    """Start a fresh checkpoint after a URL or protocol-state version change."""
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
    row.lease_token = None


def current_document_conditions() -> tuple:
    """Canonical SQL predicate for the current intelligence corpus."""
    return (
        Document.source_status == DocumentSourceStatus.ACTIVE.value,
        Document.record_status.not_in(NON_CURRENT_UPSTREAM_STATUSES),
    )


def is_current_document(source_status: str, record_status: str) -> bool:
    """Python equivalent used by exports and self-contained reports."""
    return (
        source_status == DocumentSourceStatus.ACTIVE.value
        and record_status not in NON_CURRENT_UPSTREAM_STATUSES
    )


def _retire_replaced_endpoint(
    session: Session, endpoint_id: str, replacement_id: str, *, now: datetime
) -> int:
    """Retire a superseded endpoint's projection while preserving evidence."""
    reason = f"endpoint_replaced:{replacement_id}"
    retired_ids = list(
        session.execute(
            update(Document)
            .where(
                Document.endpoint_id == endpoint_id,
                Document.source_status == DocumentSourceStatus.ACTIVE.value,
            )
            .values(
                source_status=DocumentSourceStatus.RETIRED.value,
                source_status_reason=reason,
                withdrawn_at=now,
                classify_lease_until=None,
                classify_lease_token=None,
                near_dup_of=None,
                duplicate_kind=None,
                duplicate_score=None,
                dedupe_version=DEDUPE_VERSION,
                cluster_version=None,
            )
            .returning(Document.id)
        ).scalars()
    )
    session.execute(
        update(SourceRecord)
        .where(
            SourceRecord.endpoint_id == endpoint_id,
            SourceRecord.status == SourceRecordStatus.ACTIVE.value,
        )
        .values(
            status=SourceRecordStatus.RETIRED.value,
            withdrawn_at=now,
            last_seen_at=now,
        )
    )
    if retired_ids:
        # Removing a possible duplicate master can change any active component.
        session.execute(
            update(Document)
            .where(Document.source_status == DocumentSourceStatus.ACTIVE.value)
            .values(dedupe_version=None, cluster_version=None)
        )
    return len(retired_ids)


def sync_registry(session: Session, registry: SourceRegistry) -> None:
    """Upsert registry, retire replacements and pause removed endpoints."""
    now = datetime.now(UTC)
    configured_ids = {ep.id for ep in registry.endpoints}
    for s in registry.sources:
        session.merge(
            Source(
                id=s.id,
                name=s.name,
                trust_tier=s.trust_tier.value,
                language=s.language,
                org=s.org,
            )
        )
    for ep in registry.endpoints:
        row = session.get(SourceEndpoint, ep.id)
        policy_json = {
            "schedule": ep.schedule.model_dump(),
            "fetch": ep.fetch.model_dump(),
            "topics": ep.topics,
            "fulltext": ep.fulltext,
            "options": ep.options,
        }
        if row is None:
            session.add(
                SourceEndpoint(
                    id=ep.id,
                    source_id=ep.source_id,
                    connector=ep.connector.value,
                    parser=ep.parser,
                    url=ep.url,
                    enabled=ep.enabled,
                    state_version=ep.state_version,
                    replacement_endpoint_id=ep.replaced_by,
                    retired_at=now if ep.replaced_by else None,
                    status=(
                        SourceStatus.RETIRED.value
                        if ep.replaced_by
                        else (
                            SourceStatus.ACTIVE.value if ep.enabled else SourceStatus.PAUSED.value
                        )
                    ),
                    priority=ep.priority.value,
                    trust_tier=ep.trust_tier.value,
                    language=ep.language,
                    egress_route=ep.egress.route.value,
                    policy=policy_json,
                    next_run_at=now,
                )
            )
        else:
            state_changed = row.url != ep.url or row.state_version != ep.state_version
            row.source_id = ep.source_id
            row.priority = ep.priority.value
            row.trust_tier = ep.trust_tier.value
            row.language = ep.language
            row.connector = ep.connector.value
            row.parser = ep.parser
            row.url = ep.url
            row.enabled = ep.enabled
            row.state_version = ep.state_version
            row.replacement_endpoint_id = ep.replaced_by
            row.retired_at = now if ep.replaced_by else None
            row.egress_route = ep.egress.route.value
            row.policy = policy_json
            if state_changed:
                _reset_endpoint_state_for_url_change(row, now=now)
            if not ep.enabled:
                row.status = (
                    SourceStatus.RETIRED.value if ep.replaced_by else SourceStatus.PAUSED.value
                )
                row.lease_until = None
                row.lease_token = None
            elif row.status in {SourceStatus.PAUSED.value, SourceStatus.RETIRED.value}:
                row.status = SourceStatus.ACTIVE.value

    session.flush()
    for ep in registry.endpoints:
        if ep.replaced_by:
            _retire_replaced_endpoint(session, ep.id, ep.replaced_by, now=now)

    # YAML is authoritative. Keeping removed endpoints active in PostgreSQL
    # creates ghost fetches and makes connector renames unsafe.
    missing = session.execute(
        select(SourceEndpoint).where(SourceEndpoint.id.not_in(configured_ids))
    ).scalars()
    for row in missing:
        row.enabled = False
        row.status = "paused"
        row.lease_until = None
        row.lease_token = None

    # NORMALIZED means "waiting for fulltext". Endpoints that do not need a
    # second fetch can immediately enter the classification-ready DONE state.
    non_fulltext_ids = [ep.id for ep in registry.endpoints if not ep.fulltext]
    if non_fulltext_ids:
        session.execute(
            update(RawItem)
            .where(
                RawItem.endpoint_id.in_(non_fulltext_ids),
                RawItem.stage == PipelineStage.NORMALIZED.value,
            )
            .values(stage=PipelineStage.DONE.value, stage_lease_until=None)
        )
    session.commit()


class EndpointLeaseLost(RuntimeError):
    """A stale worker no longer owns the endpoint checkpoint."""


def claim_due_endpoints(
    session: Session, limit: int, lease_seconds: int = 300
) -> list[tuple[str, str]]:
    """Atomically lease due endpoints and return fencing tokens.

    ``FOR UPDATE SKIP LOCKED`` prevents simultaneous claims. The opaque token
    prevents a worker that outlived its lease from persisting or advancing a
    checkpoint after another worker has taken ownership.
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
    ids = [str(value) for value in session.execute(stmt).scalars()]
    if not ids:
        session.commit()
        return []
    token = token_urlsafe(32)
    session.execute(
        update(SourceEndpoint)
        .where(SourceEndpoint.id.in_(ids))
        .values(
            lease_until=now + timedelta(seconds=lease_seconds),
            lease_token=token,
        )
    )
    session.commit()
    return [(endpoint_id, token) for endpoint_id in ids]


def extend_endpoint_lease(
    session: Session,
    endpoint_id: str,
    lease_token: str,
    *,
    lease_seconds: int,
) -> bool:
    """Heartbeat a lease only while this worker still owns its fencing token."""
    endpoint = session.execute(
        update(SourceEndpoint)
        .where(
            SourceEndpoint.id == endpoint_id,
            SourceEndpoint.lease_token == lease_token,
            SourceEndpoint.lease_until.is_not(None),
        )
        .values(lease_until=datetime.now(UTC) + timedelta(seconds=lease_seconds))
        .returning(SourceEndpoint.id)
    ).scalar_one_or_none()
    session.commit()
    return endpoint is not None


def ensure_endpoint_lease(session: Session, endpoint_id: str, lease_token: str) -> None:
    """Fence evidence persistence behind the current endpoint ownership token."""
    row = session.execute(
        select(SourceEndpoint).where(SourceEndpoint.id == endpoint_id).with_for_update()
    ).scalar_one_or_none()
    if row is None:
        raise KeyError(f"unknown endpoint: {endpoint_id}")
    if row.lease_token != lease_token:
        raise EndpointLeaseLost(f"endpoint lease lost: {endpoint_id}")


def load_checkpoint(
    session: Session,
    endpoint_id: str,
    *,
    known_limit: int = 5000,
    include_active_ids: bool = False,
) -> Checkpoint:
    row = session.get(SourceEndpoint, endpoint_id)
    if row is None:
        raise KeyError(f"unknown endpoint: {endpoint_id}")

    # SourceRecord is the current projection; RawItem remains immutable history.
    known_rows = session.execute(
        select(SourceRecord.native_id, SourceRecord.content_hash)
        .where(SourceRecord.endpoint_id == endpoint_id)
        .order_by(SourceRecord.last_seen_at.desc())
        .limit(known_limit)
    ).all()
    active_ids: set[str] = set()
    if include_active_ids:
        active_ids = set(
            session.execute(
                select(SourceRecord.native_id).where(
                    SourceRecord.endpoint_id == endpoint_id,
                    SourceRecord.status == "active",
                )
            ).scalars()
        )
    return Checkpoint(
        etag=row.etag,
        last_modified=row.last_modified,
        cursor=row.cursor,
        last_success_at=row.last_success_at,
        last_published_at=row.last_published_at,
        known_content_hashes={
            str(native_id): str(content_hash) for native_id, content_hash in known_rows
        },
        active_native_ids=active_ids,
    )


def _chunks[T](values: list[T], size: int = 500) -> Iterator[list[T]]:
    for start in range(0, len(values), size):
        yield values[start : start + size]


def persist_raw_items(session: Session, items: list[RawItemDTO]) -> int:
    """Bulk-insert immutable evidence and atomically update current projections.

    Large REST bootstraps can contain tens of thousands of records. Fixed-size
    chunks stay below PostgreSQL parameter limits while reducing database round
    trips from O(items) to O(chunks). Lifecycle corrections are intentionally
    row-wise because withdrawals/reactivations are rare and timestamp-specific.
    """
    if not items:
        return 0

    # Exact duplicate evidence within one connector response only needs one row.
    unique_items: dict[tuple[str, str, str], RawItemDTO] = {}
    for item in items:
        unique_items[(item.endpoint_id, item.native_id, item.content_hash)] = item

    raw_values = [
        {
            "endpoint_id": item.endpoint_id,
            "source_id": item.source_id,
            "native_id": item.native_id,
            "request_url": item.request_url,
            "final_url": item.final_url,
            "http_status": item.http_status,
            "published_at": item.published_at,
            "fetched_at": item.fetched_at,
            "language": item.language,
            "content_hash": item.content_hash,
            "blob_ref": item.blob_ref,
            "raw_text": item.raw_text,
            "canonical_url": item.canonical_url,
            "connector_version": item.connector_version,
            "parser_version": item.parser_version,
            "operation": item.operation,
            "stage": (
                PipelineStage.DONE.value
                if item.operation == "withdraw"
                else PipelineStage.FETCHED.value
            ),
        }
        for item in unique_items.values()
    ]
    raw_ids: dict[tuple[str, str, str], int] = {}
    inserted_keys: set[tuple[str, str, str]] = set()
    for batch in _chunks(raw_values):
        rows = session.execute(
            pg_insert(RawItem)
            .values(batch)
            .on_conflict_do_nothing()
            .returning(
                RawItem.id,
                RawItem.endpoint_id,
                RawItem.native_id,
                RawItem.content_hash,
            )
        ).all()
        for raw_id, endpoint_id, native_id, content_hash in rows:
            key = (str(endpoint_id), str(native_id), str(content_hash))
            raw_ids[key] = int(raw_id)
            inserted_keys.add(key)

    # Resolve conflicts so an unchanged historical item can reactivate its old
    # immutable evidence. Tuple predicates preserve the exact native/hash pair.
    unresolved_by_endpoint: dict[str, list[tuple[str, str]]] = {}
    for endpoint_id, native_id, content_hash in unique_items:
        key = (endpoint_id, native_id, content_hash)
        if key not in raw_ids:
            unresolved_by_endpoint.setdefault(endpoint_id, []).append((native_id, content_hash))
    for endpoint_id, pairs in unresolved_by_endpoint.items():
        for batch in _chunks(pairs):
            rows = session.execute(
                select(RawItem.id, RawItem.native_id, RawItem.content_hash).where(
                    RawItem.endpoint_id == endpoint_id,
                    tuple_(RawItem.native_id, RawItem.content_hash).in_(batch),
                )
            ).all()
            for raw_id, native_id, content_hash in rows:
                raw_ids[(endpoint_id, str(native_id), str(content_hash))] = int(raw_id)

    unresolved = set(unique_items) - set(raw_ids)
    if unresolved:
        sample = sorted(unresolved)[:3]
        raise RuntimeError(
            f"raw evidence conflict left {len(unresolved)} unresolved keys; sample={sample}"
        )

    # A connector page can contain multiple changes to one native ID. The final
    # source operation wins the current projection; every distinct RawItem above
    # remains preserved as history.
    final_items: dict[tuple[str, str], RawItemDTO] = {}
    for item in items:
        final_items[(item.endpoint_id, item.native_id)] = item

    projection_values: list[dict] = []
    resolved_finals: list[tuple[RawItemDTO, int, bool]] = []
    for item in final_items.values():
        evidence_key = (item.endpoint_id, item.native_id, item.content_hash)
        raw_id = raw_ids.get(evidence_key)
        if raw_id is None:  # guarded by the unresolved check above
            raise RuntimeError(f"raw evidence id missing for {evidence_key}")
        status = "withdrawn" if item.operation == "withdraw" else "active"
        projection_values.append(
            {
                "endpoint_id": item.endpoint_id,
                "native_id": item.native_id,
                "current_raw_item_id": raw_id,
                "content_hash": item.content_hash,
                "status": status,
                "first_seen_at": item.fetched_at,
                "last_seen_at": item.fetched_at,
                "withdrawn_at": item.fetched_at if status == "withdrawn" else None,
            }
        )
        resolved_finals.append((item, raw_id, evidence_key in inserted_keys))

    for batch in _chunks(projection_values):
        insert_stmt = pg_insert(SourceRecord).values(batch)
        session.execute(
            insert_stmt.on_conflict_do_update(
                constraint="uq_source_record_native",
                set_={
                    "current_raw_item_id": insert_stmt.excluded.current_raw_item_id,
                    "content_hash": insert_stmt.excluded.content_hash,
                    "status": insert_stmt.excluded.status,
                    "last_seen_at": insert_stmt.excluded.last_seen_at,
                    "withdrawn_at": insert_stmt.excluded.withdrawn_at,
                },
            )
        )

    for item, raw_id, inserted in resolved_finals:
        native_raw_ids = select(RawItem.id).where(
            RawItem.endpoint_id == item.endpoint_id,
            RawItem.native_id == item.native_id,
            RawItem.operation == "upsert",
        )
        if item.operation == "withdraw":
            session.execute(
                update(Document)
                .where(
                    Document.raw_item_id.in_(native_raw_ids),
                    Document.source_status == "active",
                )
                .values(
                    source_status="withdrawn",
                    source_status_reason="source_withdrawn",
                    withdrawn_at=item.fetched_at,
                    classify_lease_until=None,
                    classify_lease_token=None,
                    near_dup_of=None,
                    duplicate_kind=None,
                    duplicate_score=None,
                    dedupe_version=DEDUPE_VERSION,
                    cluster_version=None,
                )
            )
        elif not inserted:
            session.execute(
                update(Document)
                .where(Document.raw_item_id == raw_id)
                .values(
                    source_status="active",
                    source_status_reason=None,
                    withdrawn_at=None,
                    dedupe_version=None,
                    cluster_version=None,
                )
            )
            session.execute(
                update(Document)
                .where(
                    Document.raw_item_id.in_(native_raw_ids),
                    Document.raw_item_id != raw_id,
                    Document.source_status == "active",
                )
                .values(
                    source_status="superseded",
                    source_status_reason="content_revision",
                    withdrawn_at=item.fetched_at,
                    classify_lease_until=None,
                    classify_lease_token=None,
                    near_dup_of=None,
                    duplicate_kind=None,
                    duplicate_score=None,
                    dedupe_version=DEDUPE_VERSION,
                    cluster_version=None,
                )
            )

    session.commit()
    return len(inserted_keys)


def advance_checkpoint(
    session: Session,
    endpoint_id: str,
    checkpoint: Checkpoint,
    *,
    lease_token: str,
    success: bool,
    error: str | None,
    interval_minutes: int,
    jitter_seconds: int = 0,
) -> None:
    """Persist checkpoint + reschedule + clear the lease (after raw items saved)."""
    now = datetime.now(UTC)
    row = session.execute(
        select(SourceEndpoint).where(SourceEndpoint.id == endpoint_id).with_for_update()
    ).scalar_one_or_none()
    if row is None:
        raise KeyError(f"unknown endpoint: {endpoint_id}")
    if row.lease_token != lease_token:
        raise EndpointLeaseLost(f"endpoint lease lost before checkpoint: {endpoint_id}")
    row.etag = checkpoint.etag
    row.last_modified = checkpoint.last_modified
    row.cursor = checkpoint.cursor
    if checkpoint.last_published_at is not None:
        row.last_published_at = checkpoint.last_published_at
    row.last_fetched_at = now
    row.lease_until = None
    row.lease_token = None
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
    session: Session,
    endpoint_id: str,
    *,
    status: str,
    items_fetched: int,
    items_new: int,
    error: str | None,
    started_at: datetime | None = None,
) -> None:
    session.add(
        FetchRun(
            endpoint_id=endpoint_id,
            started_at=started_at or datetime.now(UTC),
            finished_at=datetime.now(UTC),
            status=status,
            items_fetched=items_fetched,
            items_new=items_new,
            error=error,
        )
    )
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


def retry_failed_stage_items(
    session: Session,
    *,
    limit: int = 500,
    endpoint_id: str | None = None,
) -> int:
    """Return deterministic parse failures to FETCHED after an operator fix."""
    ids_stmt = (
        select(RawItem.id)
        .where(RawItem.stage == PipelineStage.FAILED.value)
        .order_by(RawItem.id)
        .limit(limit)
    )
    if endpoint_id:
        ids_stmt = ids_stmt.where(RawItem.endpoint_id == endpoint_id)
    ids = list(session.execute(ids_stmt).scalars())
    if not ids:
        return 0
    session.execute(
        update(RawItem)
        .where(RawItem.id.in_(ids))
        .values(
            stage=PipelineStage.FETCHED.value,
            stage_error=None,
            stage_lease_until=None,
            parser_version=None,
        )
    )
    session.commit()
    return len(ids)


def persist_document(session: Session, raw_item_id: int, doc, next_stage: PipelineStage) -> None:
    """Store a parsed revision, then supersede the previously active revision."""
    raw = session.get(RawItem, raw_item_id)
    if raw is None:
        raise KeyError(f"unknown raw_item: {raw_item_id}")
    prior_raw_ids = select(RawItem.id).where(
        RawItem.endpoint_id == raw.endpoint_id,
        RawItem.native_id == raw.native_id,
        RawItem.id != raw_item_id,
        RawItem.operation == "upsert",
    )
    session.execute(
        update(Document)
        .where(
            Document.raw_item_id.in_(prior_raw_ids),
            Document.source_status == "active",
        )
        .values(
            source_status="superseded",
            source_status_reason="content_revision",
            withdrawn_at=raw.fetched_at,
            classify_lease_until=None,
            classify_lease_token=None,
            near_dup_of=None,
            duplicate_kind=None,
            duplicate_score=None,
            dedupe_version=DEDUPE_VERSION,
            cluster_version=None,
        )
    )
    session.add(
        Document(
            raw_item_id=raw_item_id,
            endpoint_id=doc.endpoint_id,
            title_original=doc.title_original,
            title_zh=doc.title_zh,
            body_text=doc.body_text,
            canonical_url=doc.canonical_url,
            author=doc.author,
            org=doc.org,
            published_at_utc=doc.published_at_utc,
            language=doc.language,
            identifiers={
                "cve": doc.cve_ids,
                "ghsa": doc.ghsa_ids,
                "cnvd": doc.cnvd_ids,
                "cwe": doc.cwe_ids,
            },
            entities=doc.entities,
            parse_quality=doc.parse_quality,
            source_status="active",
            source_status_reason=None,
            record_status=doc.record_status,
            record_status_raw=doc.record_status_raw,
        )
    )
    raw.stage = next_stage.value
    raw.stage_lease_until = None
    raw.parser_version = doc.__class__.__name__
    session.flush()


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
        doc.classified_at = None
        doc.classify_lease_until = None
        doc.classify_lease_token = None
        doc.dedupe_version = None
        doc.cluster_version = None
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
        .where(
            *current_document_conditions(),
            Document.parse_quality >= min_quality,
        )
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
    mode: str,
    rule_version: str,
    model_version: str | None = None,
    prompt_version: str | None = None,
    lease_seconds: int = 300,
) -> list[Document]:
    """Lease classification work with version-aware rule/hybrid semantics."""
    now = datetime.now(UTC)
    lease_available = Document.classify_lease_until.is_(None) | (
        Document.classify_lease_until < now
    )
    if mode == "rule":
        due = Document.classified_at.is_(None) | (
            (Document.classify_method == "rule")
            & (
                Document.classify_rule_version.is_(None)
                | (Document.classify_rule_version != rule_version)
            )
        )
    elif mode == "hybrid":
        retry_due = Document.classify_next_retry_at.is_(None) | (
            Document.classify_next_retry_at <= now
        )
        hybrid_current = (
            (Document.classify_method == "hybrid")
            & (Document.classify_model_version == model_version)
            & (Document.classify_prompt_version == prompt_version)
            & (Document.classify_rule_version == rule_version)
        )
        # Structured CVE rows intentionally remain rule-classified forever.
        non_cve = Document.tech_directions != ["cve"]
        due = Document.classified_at.is_(None) | (non_cve & ~hybrid_current & retry_due)
    else:
        raise ValueError(f"unknown classification mode: {mode}")

    stmt = (
        select(Document)
        .join(RawItem, RawItem.id == Document.raw_item_id)
        .where(
            *current_document_conditions(),
            RawItem.stage == PipelineStage.DONE.value,
            lease_available,
            due,
        )
        .order_by(Document.id)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    rows = list(session.execute(stmt).scalars())
    lease_token = token_urlsafe(32)
    for doc in rows:
        doc.classify_lease_until = now + timedelta(seconds=lease_seconds)
        doc.classify_lease_token = lease_token
        doc.classify_attempts = (doc.classify_attempts or 0) + 1
    session.commit()
    return rows


class ClassificationLeaseLost(RuntimeError):
    """A stale classifier may not write or audit a model result."""


def extend_classification_leases(
    session: Session,
    document_ids: list[int],
    lease_token: str,
    *,
    lease_seconds: int,
) -> set[int]:
    """Heartbeat only documents still owned by this classifier batch."""
    if not document_ids:
        return set()
    owned = set(
        session.execute(
            update(Document)
            .where(
                Document.id.in_(document_ids),
                Document.classify_lease_token == lease_token,
                Document.classify_lease_until.is_not(None),
                *current_document_conditions(),
            )
            .values(classify_lease_until=datetime.now(UTC) + timedelta(seconds=lease_seconds))
            .returning(Document.id)
        ).scalars()
    )
    session.commit()
    return {int(document_id) for document_id in owned}


def apply_classification(
    session: Session,
    document_id: int,
    cls,
    *,
    lease_token: str,
    error: str | None = None,
    retry_after_seconds: int | None = None,
) -> None:
    """Write a result only while its classifier still owns the fenced lease."""
    doc = session.execute(
        select(Document).where(Document.id == document_id).with_for_update()
    ).scalar_one_or_none()
    if doc is None:
        raise KeyError(f"unknown document: {document_id}")
    if doc.classify_lease_token != lease_token or not is_current_document(
        doc.source_status, doc.record_status
    ):
        raise ClassificationLeaseLost(f"classification lease lost: {document_id}")
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
    doc.classify_lease_until = None
    doc.classify_lease_token = None
    doc.classify_error = error[:2000] if error else None
    doc.classify_next_retry_at = (
        datetime.now(UTC) + timedelta(seconds=retry_after_seconds) if retry_after_seconds else None
    )
    doc.cluster_version = None
    session.flush()


def get_model_cache(
    session: Session,
    *,
    task: str,
    provider: str,
    model: str,
    prompt_version: str,
    input_hash: str,
) -> dict | None:
    row = session.execute(
        select(ModelCache).where(
            ModelCache.task == task,
            ModelCache.provider == provider,
            ModelCache.model == model,
            ModelCache.prompt_version == prompt_version,
            ModelCache.input_hash == input_hash,
        )
    ).scalar_one_or_none()
    if row is None:
        return None
    row.last_used_at = datetime.now(UTC)
    return dict(row.output)


def delete_model_cache(
    session: Session,
    *,
    task: str,
    provider: str,
    model: str,
    prompt_version: str,
    input_hash: str,
) -> None:
    session.execute(
        delete(ModelCache).where(
            ModelCache.task == task,
            ModelCache.provider == provider,
            ModelCache.model == model,
            ModelCache.prompt_version == prompt_version,
            ModelCache.input_hash == input_hash,
        )
    )
    session.flush()


def put_model_cache(
    session: Session,
    *,
    task: str,
    provider: str,
    model: str,
    prompt_version: str,
    input_hash: str,
    output: dict,
) -> None:
    now = datetime.now(UTC)
    session.execute(
        pg_insert(ModelCache)
        .values(
            task=task,
            provider=provider,
            model=model,
            prompt_version=prompt_version,
            input_hash=input_hash,
            output=output,
            last_used_at=now,
        )
        .on_conflict_do_update(
            constraint="uq_model_cache_key",
            set_={"last_used_at": now},
        )
    )
    session.flush()


def record_model_run(
    session: Session,
    *,
    document_id: int,
    task: str,
    provider: str,
    model: str,
    prompt_version: str,
    input_hash: str,
    status: str,
    latency_ms: int | None = None,
    usage: dict | None = None,
    error: str | None = None,
) -> None:
    session.add(
        ModelRun(
            document_id=document_id,
            task=task,
            provider=provider,
            model=model,
            prompt_version=prompt_version,
            input_hash=input_hash,
            status=status,
            latency_ms=latency_ms,
            usage=usage or {},
            error=error[:2000] if error else None,
        )
    )
    session.flush()


# Stable PostgreSQL advisory-lock keys for M2 derived-data stages.
_DEDUPE_LOCK_KEY = 0x41495348000201
_CLUSTER_LOCK_KEY = 0x41495348000202


def count_event_pipeline_backlog(session: Session) -> int:
    """Count M1 work whose absence would make a scheduled M2 rebuild premature.

    Raw FETCHED/NORMALIZED rows have not reached their final normalized form.
    Active DONE documents without a classification have not reached their
    final M1.3 labels. FAILED rows and retryable hybrid fallbacks are excluded:
    neither should block event intelligence indefinitely.
    """
    raw_pending = session.execute(
        select(func.count())
        .select_from(RawItem)
        .where(RawItem.stage.in_([PipelineStage.FETCHED.value, PipelineStage.NORMALIZED.value]))
    ).scalar_one()
    classification_pending = session.execute(
        select(func.count())
        .select_from(Document)
        .join(RawItem, RawItem.id == Document.raw_item_id)
        .where(
            *current_document_conditions(),
            RawItem.stage == PipelineStage.DONE.value,
            Document.classified_at.is_(None),
        )
    ).scalar_one()
    return int(raw_pending) + int(classification_pending)


def try_event_stage_lock(session: Session, stage: str) -> bool:
    """Take a transaction-scoped lock so manual and scheduled runs cannot race."""
    keys = {"dedupe": _DEDUPE_LOCK_KEY, "cluster": _CLUSTER_LOCK_KEY}
    if stage not in keys:
        raise ValueError(f"unknown event stage: {stage}")
    return bool(session.execute(select(func.pg_try_advisory_xact_lock(keys[stage]))).scalar_one())


def count_dedupe_due(session: Session, *, version: str = DEDUPE_VERSION) -> int:
    return int(
        session.execute(
            select(func.count())
            .select_from(Document)
            .where(
                *current_document_conditions(),
                Document.dedupe_version.is_(None) | (Document.dedupe_version != version),
            )
        ).scalar_one()
    )


def count_cluster_due(session: Session, *, version: str = CLUSTER_VERSION) -> int:
    return int(
        session.execute(
            select(func.count())
            .select_from(Document)
            .where(
                *current_document_conditions(),
                Document.dedupe_version == DEDUPE_VERSION,
                Document.cluster_version.is_(None) | (Document.cluster_version != version),
            )
        ).scalar_one()
    )


def load_intel_documents(session: Session) -> list[IntelDocument]:
    """Load the normalized evidence needed by both M2 pure functions."""
    rows = session.execute(
        select(Document, RawItem.fetched_at, SourceEndpoint.source_id, SourceEndpoint.trust_tier)
        .join(RawItem, RawItem.id == Document.raw_item_id)
        .join(SourceEndpoint, SourceEndpoint.id == Document.endpoint_id)
        .where(*current_document_conditions())
        .order_by(Document.id)
    ).all()
    return [
        IntelDocument(
            id=doc.id,
            endpoint_id=doc.endpoint_id,
            source_id=source_id,
            trust_tier=trust_tier,
            title=doc.title_original,
            body=doc.body_text,
            canonical_url=doc.canonical_url,
            published_at=doc.published_at_utc,
            fetched_at=fetched_at,
            identifiers=doc.identifiers or {},
            tech_directions=list(doc.tech_directions or []),
            event_type=doc.classified_event_type,
            parse_quality=doc.parse_quality,
        )
        for doc, fetched_at, source_id, trust_tier in rows
    ]


def apply_dedup_decisions(
    session: Session,
    decisions: dict[int, DedupDecision],
    *,
    version: str = DEDUPE_VERSION,
) -> dict[str, int]:
    """Persist a full deterministic decision set and invalidate changed clusters."""
    now = datetime.now(UTC)
    rows = {
        row.id: row
        for row in session.execute(select(Document).where(Document.id.in_(decisions))).scalars()
    }
    updated = 0
    duplicates = 0
    for document_id, decision in decisions.items():
        doc = rows[document_id]
        relationship_changed = (
            doc.near_dup_of != decision.near_dup_of
            or doc.duplicate_kind != decision.duplicate_kind
            or doc.duplicate_score != decision.duplicate_score
        )
        version_changed = doc.dedupe_version != version
        if relationship_changed or version_changed:
            doc.near_dup_of = decision.near_dup_of
            doc.duplicate_kind = decision.duplicate_kind
            doc.duplicate_score = decision.duplicate_score
            doc.dedupe_version = version
            doc.deduped_at = now
            doc.cluster_version = None
            doc.clustered_at = None
            updated += 1
        if decision.near_dup_of is not None:
            duplicates += 1
    return {"updated": updated, "duplicates": duplicates}


def load_dedup_decisions(session: Session) -> dict[int, DedupDecision]:
    rows = session.execute(
        select(
            Document.id,
            Document.near_dup_of,
            Document.duplicate_kind,
            Document.duplicate_score,
        ).where(
            Document.dedupe_version == DEDUPE_VERSION,
            *current_document_conditions(),
        )
    ).all()
    return {
        document_id: DedupDecision(document_id, near_dup_of, kind, score)
        for document_id, near_dup_of, kind, score in rows
    }


def apply_event_drafts(
    session: Session,
    drafts: dict[str, EventDraft],
    *,
    version: str = CLUSTER_VERSION,
) -> dict[str, int]:
    """Upsert events, reconcile derived memberships, and version changed events."""
    now = datetime.now(UTC)
    existing = {event.fingerprint: event for event in session.execute(select(Event)).scalars()}
    created = 0
    updated = 0
    for fingerprint, draft in drafts.items():
        event = existing.get(fingerprint)
        if event is None:
            event = Event(
                fingerprint=fingerprint,
                event_type=draft.event_type,
                topic=draft.topic,
                title=draft.title,
                summary=draft.summary,
                status=draft.status,
                score=draft.score,
                evidence_level=draft.evidence_level,
                cluster_version=version,
                first_seen_at=draft.first_seen_at,
                last_seen_at=draft.last_seen_at,
                current_version=1,
                updated_at=now,
            )
            session.add(event)
            existing[fingerprint] = event
            created += 1
            continue
        current = (
            event.event_type,
            event.topic,
            event.title,
            event.summary,
            event.status,
            event.score,
            event.evidence_level,
            event.cluster_version,
            event.first_seen_at,
            event.last_seen_at,
        )
        desired = (
            draft.event_type,
            draft.topic,
            draft.title,
            draft.summary,
            draft.status,
            draft.score,
            draft.evidence_level,
            version,
            draft.first_seen_at,
            draft.last_seen_at,
        )
        if current != desired:
            (
                event.event_type,
                event.topic,
                event.title,
                event.summary,
                event.status,
                event.score,
                event.evidence_level,
                event.cluster_version,
                event.first_seen_at,
                event.last_seen_at,
            ) = desired
            event.current_version += 1
            event.updated_at = now
            updated += 1

    desired_fingerprints = set(drafts)
    for fingerprint, event in existing.items():
        if (
            event.cluster_version is not None
            and fingerprint not in desired_fingerprints
            and event.status != "superseded"
        ):
            event.status = "superseded"
            event.current_version += 1
            event.updated_at = now
            updated += 1

    session.flush()
    desired_links = {
        (existing[fingerprint].id, membership.document_id): membership
        for fingerprint, draft in drafts.items()
        for membership in draft.memberships
    }
    active_event_ids = [existing[fingerprint].id for fingerprint in drafts]
    old_links = {}
    if active_event_ids:
        old_links = {
            (link.event_id, link.document_id): link
            for link in session.execute(
                select(EventDocument).where(EventDocument.event_id.in_(active_event_ids))
            ).scalars()
        }
    stale_link_ids = [link.id for key, link in old_links.items() if key not in desired_links]
    if stale_link_ids:
        session.execute(delete(EventDocument).where(EventDocument.id.in_(stale_link_ids)))

    links_created = 0
    links_updated = 0
    for key, membership in desired_links.items():
        link = old_links.get(key)
        if link is None:
            session.add(
                EventDocument(
                    event_id=key[0],
                    document_id=key[1],
                    stance="support",
                    evidence_level=membership.evidence_level,
                    relation_reason=membership.relation_reason,
                )
            )
            links_created += 1
        elif (
            link.evidence_level != membership.evidence_level
            or link.relation_reason != membership.relation_reason
        ):
            link.evidence_level = membership.evidence_level
            link.relation_reason = membership.relation_reason
            links_updated += 1

    session.execute(
        update(Document)
        .where(Document.dedupe_version == DEDUPE_VERSION)
        .values(cluster_version=version, clustered_at=now)
    )
    return {
        "events_created": created,
        "events_updated": updated,
        "links_created": links_created,
        "links_updated": links_updated,
        "links_removed": len(stale_link_ids),
    }
