"""Repositories — the only layer that maps domain objects to/from ORM rows.

Includes registry sync, DB-lease endpoint claiming (plan 修正 5: DB is the
single scheduling source of truth) and idempotent raw-item persistence
(先存 RawItem before advancing the checkpoint — MVP §3).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from itertools import batched
from secrets import randbelow, token_urlsafe
from typing import cast

from sqlalchemy import Table, bindparam, delete, func, select, text, tuple_, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ai_security_hot.config.settings import get_settings
from ai_security_hot.config.sources import SourceRegistry
from ai_security_hot.connectors.base import Checkpoint
from ai_security_hot.domain.enums import (
    NON_CURRENT_UPSTREAM_STATUSES,
    STRUCTURED_VULN_ENDPOINTS,
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
    EventKey,
    IntelDocument,
    build_event_draft,
    build_event_drafts,
    content_fingerprint,
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


def scope_document_conditions(scope: str = "all") -> tuple:
    """current_document_conditions plus an optional endpoint-scope filter.

    scope="vuln" restricts to structured-vulnerability endpoints (NVD/KEV);
    scope="general" excludes them; scope="all" (default) applies no filter.
    """
    conditions = list(current_document_conditions())
    if scope == "vuln":
        conditions.append(Document.endpoint_id.in_(STRUCTURED_VULN_ENDPOINTS))
    elif scope == "general":
        conditions.append(Document.endpoint_id.notin_(STRUCTURED_VULN_ENDPOINTS))
    return tuple(conditions)


def is_current_document(source_status: str, record_status: str) -> bool:
    """Python equivalent used by exports and self-contained reports."""
    return (
        source_status == DocumentSourceStatus.ACTIVE.value
        and record_status not in NON_CURRENT_UPSTREAM_STATUSES
    )


def _enqueue_m2_change(
    session: Session,
    document_ids: list[int] | set[int],
    *,
    reason: str,
    include_dedupe: bool = True,
    include_cluster: bool = True,
) -> None:
    """Persist local invalidation before mutating lifecycle/component state."""
    ids = sorted(set(document_ids))
    if not ids:
        return
    from ai_security_hot.storage import event_repository

    components = {
        int(document_id): int(component_id) if component_id is not None else None
        for document_id, component_id in session.execute(
            select(Document.id, Document.dedupe_component_id).where(Document.id.in_(ids))
        )
    }
    if include_dedupe:
        event_repository.enqueue_work(
            session,
            ids,
            stage="dedupe",
            reason=reason,
            algorithm_version=DEDUPE_VERSION,
            component_ids=components,
        )
    if include_cluster:
        event_repository.enqueue_work(
            session,
            ids,
            stage="cluster",
            reason=reason,
            algorithm_version=CLUSTER_VERSION,
            component_ids=components,
        )


def _retire_replaced_endpoint(
    session: Session, endpoint_id: str, replacement_id: str, *, now: datetime
) -> int:
    """Retire a superseded endpoint's projection while preserving evidence."""
    reason = f"endpoint_replaced:{replacement_id}"
    retired_ids = [
        int(value)
        for value in session.execute(
            select(Document.id).where(
                Document.endpoint_id == endpoint_id,
                Document.source_status == DocumentSourceStatus.ACTIVE.value,
            )
        ).scalars()
    ]
    _enqueue_m2_change(session, retired_ids, reason="endpoint_retired")
    session.execute(
        update(Document)
        .where(Document.id.in_(retired_ids))
        .values(
            source_status=DocumentSourceStatus.RETIRED.value,
            source_status_reason=reason,
            withdrawn_at=now,
            classify_lease_until=None,
            classify_lease_token=None,
            dedupe_version=DEDUPE_VERSION,
            cluster_version=None,
        )
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
                source_family=s.source_family,
                origin_source=s.origin_source,
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
                    # Replacement FKs are assigned in a second pass after every
                    # endpoint exists. Query-triggered autoflush may otherwise insert
                    # a retired endpoint before its replacement on a fresh database.
                    replacement_endpoint_id=None,
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

    # Phase 1 deliberately persists every endpoint without adding new
    # self-referential replacement FKs. This makes fresh registry syncs
    # independent of YAML ordering and SQLAlchemy autoflush boundaries.
    session.flush()

    # Phase 2 can now safely converge replacement links and retirement times.
    # Preserve the original retired_at across idempotent syncs.
    for ep in registry.endpoints:
        row = session.get(SourceEndpoint, ep.id)
        if row is None:  # pragma: no cover - phase 1 guarantees this invariant
            raise RuntimeError(f"endpoint disappeared during registry sync: {ep.id}")
        row.replacement_endpoint_id = ep.replaced_by
        if ep.replaced_by:
            row.retired_at = row.retired_at or now
        else:
            row.retired_at = None
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
            affected_ids = [
                int(value)
                for value in session.execute(
                    select(Document.id).where(
                        Document.raw_item_id.in_(native_raw_ids),
                        Document.source_status == "active",
                    )
                ).scalars()
            ]
            _enqueue_m2_change(session, affected_ids, reason="source_withdrawn")
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
                    dedupe_version=DEDUPE_VERSION,
                    cluster_version=None,
                )
            )
        elif not inserted:
            affected_ids = [
                int(value)
                for value in session.execute(
                    select(Document.id).where(Document.raw_item_id.in_(native_raw_ids))
                ).scalars()
            ]
            _enqueue_m2_change(session, affected_ids, reason="source_reactivated")
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
        row.status = SourceStatus.ACTIVE.value
        row.last_error = None
    else:
        row.consecutive_failures += 1
        failures = row.consecutive_failures
        row.last_error = error
        settings = get_settings()
        threshold = settings.circuit_breaker_threshold
        cooldown = settings.circuit_breaker_cooldown_minutes
        if failures >= threshold:
            # Circuit OPEN: stop retrying for a cooldown period.  When the
            # cooldown expires, claim_due_endpoints picks the endpoint up
            # automatically (half-open probe).  Success closes the circuit;
            # failure reopens it for another cooldown.
            row.status = SourceStatus.CIRCUIT_OPEN.value
            row.next_run_at = now + timedelta(minutes=cooldown)
        else:
            # Circuit still closed: exponential backoff capped at interval.
            retry_minutes = min(interval_minutes, 2 ** min(failures, 10))
            row.next_run_at = now + timedelta(minutes=retry_minutes, seconds=jitter)
            if failures >= 3:
                row.status = SourceStatus.DEGRADED.value
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
    prior_document_ids = [
        int(value)
        for value in session.execute(
            select(Document.id).where(
                Document.raw_item_id.in_(prior_raw_ids),
                Document.source_status == "active",
            )
        ).scalars()
    ]
    _enqueue_m2_change(session, prior_document_ids, reason="content_revision")
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
            dedupe_version=DEDUPE_VERSION,
            cluster_version=None,
        )
    )
    document = Document(
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
    session.add(document)
    raw.stage = next_stage.value
    raw.stage_lease_until = None
    raw.parser_version = doc.__class__.__name__
    session.flush()
    _enqueue_m2_change(
        session,
        {int(document.id)},
        reason="document_created",
        include_cluster=False,
    )


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
        _enqueue_m2_change(session, {document_id}, reason="fulltext_changed")
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
    _enqueue_m2_change(
        session,
        {document_id},
        reason="classification_changed",
        include_dedupe=False,
    )
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
    subject_type: str = "document",
    subject_id: int | None = None,
) -> None:
    resolved_subject_id = subject_id if subject_id is not None else document_id
    session.add(
        ModelRun(
            document_id=document_id,
            subject_type=subject_type,
            subject_id=resolved_subject_id,
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
    """Take a transaction-scoped lock so manual and scheduled runs cannot race.

    Accepts a bare stage ("dedupe"/"cluster") or a scope-qualified stage
    ("dedupe:vuln", "cluster:general", ...). Each stage+scope gets a distinct
    advisory lock so the vuln and general passes never block each other, while a
    bare stage still serializes with any scoped pass of the same kind.
    """
    base_keys = {"dedupe": _DEDUPE_LOCK_KEY, "cluster": _CLUSTER_LOCK_KEY}
    base, _, qualifier = stage.partition(":")
    if base not in base_keys:
        raise ValueError(f"unknown event stage: {stage}")
    key = base_keys[base]
    if qualifier:
        # Derive a stable per-scope key from the base key + qualifier hash.
        key = key ^ int.from_bytes(
            qualifier.encode("utf-8")[:8].ljust(8, b"\0"), "little"
        )
    return bool(session.execute(select(func.pg_try_advisory_xact_lock(key))).scalar_one())


def count_dedupe_due(
    session: Session, *, version: str = DEDUPE_VERSION, scope: str = "all"
) -> int:
    return int(
        session.execute(
            select(func.count())
            .select_from(Document)
            .where(
                *scope_document_conditions(scope),
                Document.dedupe_version.is_(None) | (Document.dedupe_version != version),
            )
        ).scalar_one()
    )


def count_cluster_due(
    session: Session, *, version: str = CLUSTER_VERSION, scope: str = "all"
) -> int:
    return int(
        session.execute(
            select(func.count())
            .select_from(Document)
            .where(
                *scope_document_conditions(scope),
                Document.dedupe_version == DEDUPE_VERSION,
                Document.cluster_version.is_(None) | (Document.cluster_version != version),
            )
        ).scalar_one()
    )


def load_intel_documents(session: Session, *, retain_body: bool = True) -> list[IntelDocument]:
    """Load M2 evidence with a scalar streaming query.

    Dedupe retains only a normalized content digest and body length. Cluster
    may opt into body text for summaries, but neither path populates the
    Session identity map with every Document ORM object.
    """
    stmt = (
        select(
            Document.id,
            Document.endpoint_id,
            SourceEndpoint.source_id,
            SourceEndpoint.trust_tier,
            Source.source_family,
            Document.title_original,
            Document.body_text,
            Document.canonical_url,
            Document.published_at_utc,
            RawItem.fetched_at,
            Document.identifiers,
            Document.tech_directions,
            Document.classified_event_type,
            Document.parse_quality,
            Document.entities,
            Document.company_models,
        )
        .join(RawItem, RawItem.id == Document.raw_item_id)
        .join(SourceEndpoint, SourceEndpoint.id == Document.endpoint_id)
        .join(Source, Source.id == SourceEndpoint.source_id)
        .where(*current_document_conditions())
        .order_by(Document.id)
        .execution_options(yield_per=1000)
    )
    documents: list[IntelDocument] = []
    for (
        document_id,
        endpoint_id,
        source_id,
        trust_tier,
        source_family,
        title,
        body,
        canonical_url,
        published_at,
        fetched_at,
        identifiers,
        tech_directions,
        event_type,
        parse_quality,
        entities,
        company_models,
    ) in session.execute(stmt):
        documents.append(
            IntelDocument(
                id=document_id,
                endpoint_id=endpoint_id,
                source_id=source_id,
                trust_tier=trust_tier,
                title=title,
                body=body if retain_body else None,
                canonical_url=canonical_url,
                published_at=published_at,
                fetched_at=fetched_at,
                identifiers=identifiers or {},
                tech_directions=list(tech_directions or []),
                event_type=event_type,
                source_family=source_family or source_id,
                parse_quality=parse_quality,
                content_digest=None if retain_body else content_fingerprint(body),
                content_length=len(body or ""),
                entities=entities or {},
                company_models=list(company_models or []),
            )
        )
    return documents


def apply_dedup_decisions(
    session: Session,
    decisions: dict[int, DedupDecision],
    *,
    version: str = DEDUPE_VERSION,
) -> dict[str, int]:
    """Persist decisions in bounded scalar batches and invalidate changed clusters."""
    now = datetime.now(UTC)
    updated = 0
    duplicates = sum(decision.near_dup_of is not None for decision in decisions.values())
    document_table = cast(Table, Document.__table__)
    update_stmt = (
        document_table.update()
        .where(document_table.c.id == bindparam("_document_id"))
        .values(
            near_dup_of=bindparam("_near_dup_of"),
            duplicate_kind=bindparam("_duplicate_kind"),
            duplicate_score=bindparam("_duplicate_score"),
            dedupe_version=bindparam("_dedupe_version"),
            deduped_at=bindparam("_deduped_at"),
            cluster_version=None,
            clustered_at=None,
        )
    )
    for decision_batch in batched(decisions.values(), 2000, strict=False):
        ids = [decision.document_id for decision in decision_batch]
        current = {
            document_id: (near_dup_of, duplicate_kind, duplicate_score, dedupe_version)
            for document_id, near_dup_of, duplicate_kind, duplicate_score, dedupe_version in (
                session.execute(
                    select(
                        Document.id,
                        Document.near_dup_of,
                        Document.duplicate_kind,
                        Document.duplicate_score,
                        Document.dedupe_version,
                    ).where(Document.id.in_(ids))
                )
            )
        }
        changes = []
        for decision in decision_batch:
            desired = (
                decision.near_dup_of,
                decision.duplicate_kind,
                decision.duplicate_score,
                version,
            )
            if current[decision.document_id] == desired:
                continue
            changes.append(
                {
                    "_document_id": decision.document_id,
                    "_near_dup_of": decision.near_dup_of,
                    "_duplicate_kind": decision.duplicate_kind,
                    "_duplicate_score": decision.duplicate_score,
                    "_dedupe_version": version,
                    "_deduped_at": now,
                }
            )
        if changes:
            session.execute(update_stmt, changes)
            updated += len(changes)
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


def _iter_dedup_components(
    session: Session,
) -> Iterator[tuple[list[IntelDocument], dict[int, DedupDecision]]]:
    """Stream complete duplicate components without retaining the corpus."""
    component_id = func.coalesce(Document.near_dup_of, Document.id).label("component_id")
    stmt = (
        select(
            component_id,
            Document.id,
            Document.near_dup_of,
            Document.duplicate_kind,
            Document.duplicate_score,
            Document.endpoint_id,
            SourceEndpoint.source_id,
            SourceEndpoint.trust_tier,
            Source.source_family,
            Document.title_original,
            Document.body_text,
            Document.canonical_url,
            Document.published_at_utc,
            RawItem.fetched_at,
            Document.identifiers,
            Document.tech_directions,
            Document.classified_event_type,
            Document.parse_quality,
            Document.entities,
            Document.company_models,
        )
        .join(RawItem, RawItem.id == Document.raw_item_id)
        .join(SourceEndpoint, SourceEndpoint.id == Document.endpoint_id)
        .join(Source, Source.id == SourceEndpoint.source_id)
        .where(
            Document.dedupe_version == DEDUPE_VERSION,
            *current_document_conditions(),
        )
        .order_by(component_id, Document.id)
        .execution_options(yield_per=1000)
    )
    active_component: int | None = None
    documents: list[IntelDocument] = []
    decisions: dict[int, DedupDecision] = {}
    result = session.execute(stmt)
    try:
        for (
            row_component_id,
            document_id,
            near_dup_of,
            duplicate_kind,
            duplicate_score,
            endpoint_id,
            source_id,
            trust_tier,
            source_family,
            title,
            body,
            canonical_url,
            published_at,
            fetched_at,
            identifiers,
            tech_directions,
            event_type,
            parse_quality,
            entities,
            company_models,
        ) in result:
            if active_component is not None and row_component_id != active_component:
                yield documents, decisions
                documents = []
                decisions = {}
            active_component = row_component_id
            documents.append(
                IntelDocument(
                    id=document_id,
                    endpoint_id=endpoint_id,
                    source_id=source_id,
                    trust_tier=trust_tier,
                    title=title,
                    body=body,
                    canonical_url=canonical_url,
                    published_at=published_at,
                    fetched_at=fetched_at,
                    identifiers=identifiers or {},
                    tech_directions=list(tech_directions or []),
                    event_type=event_type,
                    parse_quality=parse_quality,
                    source_family=source_family or source_id,
                    content_length=len(body or ""),
                    entities=entities or {},
                    company_models=list(company_models or []),
                )
            )
            decisions[document_id] = DedupDecision(
                document_id, near_dup_of, duplicate_kind, duplicate_score
            )
        if documents:
            yield documents, decisions
    finally:
        result.close()


def _stage_event_memberships(session: Session) -> dict[str, int]:
    """Write desired event evidence to a transaction-local spill table."""
    session.execute(
        text(
            """
            CREATE TEMP TABLE m2_event_memberships (
                fingerprint varchar(160) NOT NULL,
                document_id bigint NOT NULL,
                evidence_level varchar(1) NOT NULL,
                relation_reason varchar(32) NOT NULL,
                PRIMARY KEY (fingerprint, document_id)
            ) ON COMMIT DROP
            """
        )
    )
    insert_stmt = text(
        """
        INSERT INTO m2_event_memberships
            (fingerprint, document_id, evidence_level, relation_reason)
        VALUES (:fingerprint, :document_id, :evidence_level, :relation_reason)
        ON CONFLICT (fingerprint, document_id) DO UPDATE SET
            evidence_level = EXCLUDED.evidence_level,
            relation_reason = EXCLUDED.relation_reason
        """
    )
    staged: list[dict] = []
    document_count = 0
    membership_count = 0
    for documents, decisions in _iter_dedup_components(session):
        document_count += len(documents)
        for draft in build_event_drafts(documents, decisions).values():
            for membership in draft.memberships:
                staged.append(
                    {
                        "fingerprint": draft.fingerprint,
                        "document_id": membership.document_id,
                        "evidence_level": membership.evidence_level,
                        "relation_reason": membership.relation_reason,
                    }
                )
                membership_count += 1
        if len(staged) >= 2000:
            session.execute(insert_stmt, staged)
            staged.clear()
    if staged:
        session.execute(insert_stmt, staged)
    return {"documents": document_count, "memberships": membership_count}


def _iter_staged_event_drafts(session: Session) -> Iterator[EventDraft]:
    """Stream one complete event group at a time from staged memberships."""
    stmt = text(
        """
        SELECT
            membership.fingerprint,
            membership.relation_reason,
            document.id AS document_id,
            document.endpoint_id,
            endpoint.source_id,
            endpoint.trust_tier,
            source.source_family,
            document.title_original AS title,
            document.body_text AS body,
            document.canonical_url,
            document.published_at_utc AS published_at,
            raw_item.fetched_at,
            document.identifiers,
            document.tech_directions,
            document.classified_event_type AS event_type,
            document.parse_quality,
            document.entities,
            document.company_models
        FROM m2_event_memberships AS membership
        JOIN documents AS document ON document.id = membership.document_id
        JOIN raw_items AS raw_item ON raw_item.id = document.raw_item_id
        JOIN source_endpoints AS endpoint ON endpoint.id = document.endpoint_id
        JOIN sources AS source ON source.id = endpoint.source_id
        ORDER BY membership.fingerprint, document.id
        """
    ).execution_options(yield_per=1000)
    active_fingerprint: str | None = None
    documents: list[IntelDocument] = []
    reasons: dict[int, str] = {}
    result = session.execute(stmt).mappings()
    try:
        for row in result:
            fingerprint = row["fingerprint"]
            if active_fingerprint is not None and fingerprint != active_fingerprint:
                kind = active_fingerprint.partition(":")[0]
                yield build_event_draft(EventKey(active_fingerprint, kind), documents, reasons)
                documents = []
                reasons = {}
            active_fingerprint = fingerprint
            body = row["body"]
            document_id = row["document_id"]
            documents.append(
                IntelDocument(
                    id=document_id,
                    endpoint_id=row["endpoint_id"],
                    source_id=row["source_id"],
                    trust_tier=row["trust_tier"],
                    title=row["title"],
                    body=body,
                    canonical_url=row["canonical_url"],
                    published_at=row["published_at"],
                    fetched_at=row["fetched_at"],
                    identifiers=row["identifiers"] or {},
                    tech_directions=list(row["tech_directions"] or []),
                    event_type=row["event_type"],
                    parse_quality=row["parse_quality"],
                    source_family=row["source_family"] or row["source_id"],
                    content_length=len(body or ""),
                    entities=row["entities"] or {},
                    company_models=list(row["company_models"] or []),
                )
            )
            reasons[document_id] = row["relation_reason"]
        if active_fingerprint is not None:
            kind = active_fingerprint.partition(":")[0]
            yield build_event_draft(EventKey(active_fingerprint, kind), documents, reasons)
    finally:
        result.close()


def _apply_event_batch(
    session: Session,
    drafts: tuple[EventDraft, ...],
    *,
    version: str,
    now: datetime,
) -> dict[str, int]:
    """Upsert one bounded batch without retaining Event ORM instances."""
    fingerprints = [draft.fingerprint for draft in drafts]
    existing = {}
    for row in session.execute(
        select(
            Event.id,
            Event.fingerprint,
            Event.current_version,
            Event.event_type,
            Event.topic,
            Event.title,
            Event.summary,
            Event.status,
            Event.score,
            Event.evidence_level,
            Event.cluster_version,
            Event.first_seen_at,
            Event.last_seen_at,
        ).where(Event.fingerprint.in_(fingerprints))
    ):
        existing[row.fingerprint] = (
            row.id,
            row.current_version,
            (
                row.event_type,
                row.topic,
                row.title,
                row.summary,
                row.status,
                row.score,
                row.evidence_level,
                row.cluster_version,
                row.first_seen_at,
                row.last_seen_at,
            ),
        )

    created_rows = []
    changed_rows = []
    for draft in drafts:
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
        current = existing.get(draft.fingerprint)
        if current is None:
            created_rows.append(
                {
                    "fingerprint": draft.fingerprint,
                    "event_type": draft.event_type,
                    "topic": draft.topic,
                    "title": draft.title,
                    "summary": draft.summary,
                    "status": draft.status,
                    "score": draft.score,
                    "evidence_level": draft.evidence_level,
                    "cluster_version": version,
                    "first_seen_at": draft.first_seen_at,
                    "last_seen_at": draft.last_seen_at,
                    "current_version": 1,
                    "updated_at": now,
                }
            )
        elif current[2] != desired:
            changed_rows.append(
                {
                    "_event_id": current[0],
                    "_event_type": draft.event_type,
                    "_topic": draft.topic,
                    "_title": draft.title,
                    "_summary": draft.summary,
                    "_status": draft.status,
                    "_score": draft.score,
                    "_evidence_level": draft.evidence_level,
                    "_cluster_version": version,
                    "_first_seen_at": draft.first_seen_at,
                    "_last_seen_at": draft.last_seen_at,
                    "_current_version": current[1] + 1,
                    "_updated_at": now,
                }
            )

    if created_rows:
        session.execute(cast(Table, Event.__table__).insert(), created_rows)
    if changed_rows:
        event_table = cast(Table, Event.__table__)
        session.execute(
            event_table.update()
            .where(event_table.c.id == bindparam("_event_id"))
            .values(
                event_type=bindparam("_event_type"),
                topic=bindparam("_topic"),
                title=bindparam("_title"),
                summary=bindparam("_summary"),
                status=bindparam("_status"),
                score=bindparam("_score"),
                evidence_level=bindparam("_evidence_level"),
                cluster_version=bindparam("_cluster_version"),
                first_seen_at=bindparam("_first_seen_at"),
                last_seen_at=bindparam("_last_seen_at"),
                current_version=bindparam("_current_version"),
                updated_at=bindparam("_updated_at"),
            ),
            changed_rows,
        )
    return {"created": len(created_rows), "updated": len(changed_rows)}


def rebuild_events_streaming(session: Session, *, version: str = CLUSTER_VERSION) -> dict[str, int]:
    """Rebuild events with database spill and bounded Python memory."""
    now = datetime.now(UTC)
    staged = _stage_event_memberships(session)
    events_created = 0
    events_updated = 0
    event_count = 0
    for draft_batch in batched(_iter_staged_event_drafts(session), 1000, strict=False):
        batch_stats = _apply_event_batch(session, draft_batch, version=version, now=now)
        events_created += batch_stats["created"]
        events_updated += batch_stats["updated"]
        event_count += len(draft_batch)

    stale_events = int(
        session.execute(
            text(
                """
                WITH changed AS (
                    UPDATE events AS event
                    SET status = 'superseded',
                        current_version = event.current_version + 1,
                        updated_at = :now
                    WHERE event.cluster_version IS NOT NULL
                      AND event.status <> 'superseded'
                      AND NOT EXISTS (
                          SELECT 1 FROM m2_event_memberships AS membership
                          WHERE membership.fingerprint = event.fingerprint
                      )
                    RETURNING event.id
                )
                SELECT count(*) FROM changed
                """
            ),
            {"now": now},
        ).scalar_one()
    )
    events_updated += stale_events

    links_removed = int(
        session.execute(
            text(
                """
                WITH removed AS (
                    DELETE FROM event_documents AS link
                    USING events AS event
                    WHERE event.id = link.event_id
                      AND EXISTS (
                          SELECT 1 FROM m2_event_memberships AS desired_event
                          WHERE desired_event.fingerprint = event.fingerprint
                      )
                      AND NOT EXISTS (
                          SELECT 1 FROM m2_event_memberships AS membership
                          WHERE membership.fingerprint = event.fingerprint
                            AND membership.document_id = link.document_id
                      )
                    RETURNING link.id
                )
                SELECT count(*) FROM removed
                """
            )
        ).scalar_one()
    )
    links_updated = int(
        session.execute(
            text(
                """
                WITH changed AS (
                    UPDATE event_documents AS link
                    SET stance = 'support',
                        evidence_level = membership.evidence_level,
                        relation_reason = membership.relation_reason
                    FROM events AS event, m2_event_memberships AS membership
                    WHERE event.id = link.event_id
                      AND event.fingerprint = membership.fingerprint
                      AND link.document_id = membership.document_id
                      AND (link.stance, link.evidence_level, link.relation_reason)
                          IS DISTINCT FROM
                          ('support', membership.evidence_level, membership.relation_reason)
                    RETURNING link.id
                )
                SELECT count(*) FROM changed
                """
            )
        ).scalar_one()
    )
    links_created = int(
        session.execute(
            text(
                """
                WITH created AS (
                    INSERT INTO event_documents
                        (event_id, document_id, stance, evidence_level, relation_reason)
                    SELECT event.id, membership.document_id, 'support',
                           membership.evidence_level, membership.relation_reason
                    FROM m2_event_memberships AS membership
                    JOIN events AS event ON event.fingerprint = membership.fingerprint
                    ON CONFLICT ON CONSTRAINT uq_event_document DO NOTHING
                    RETURNING id
                )
                SELECT count(*) FROM created
                """
            )
        ).scalar_one()
    )

    session.execute(
        update(Document)
        .where(Document.dedupe_version == DEDUPE_VERSION, *current_document_conditions())
        .values(cluster_version=version, clustered_at=now)
    )
    return {
        "documents": staged["documents"],
        "events": event_count,
        "memberships": staged["memberships"],
        "events_created": events_created,
        "events_updated": events_updated,
        "links_created": links_created,
        "links_updated": links_updated,
        "links_removed": links_removed,
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
