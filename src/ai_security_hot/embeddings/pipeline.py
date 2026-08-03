"""Durable atomic-event embeddings and bounded semantic candidate recall."""

from __future__ import annotations

import hashlib
import logging
import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ai_security_hot.config.embeddings import ResolvedEmbeddingConfig, resolve_embedding_config
from ai_security_hot.config.settings import Settings, get_settings
from ai_security_hot.domain.models import content_sha256
from ai_security_hot.embeddings.provider import (
    EmbeddingProvider,
    EmbeddingProviderError,
    build_embedding_provider,
)
from ai_security_hot.models.base import session_scope
from ai_security_hot.models.semantic_tables import (
    AtomicEvent,
    AtomicEventEmbedding,
    EmbeddingRecallState,
    EntityMention,
    RelationCandidate,
    SemanticEntity,
    SemanticWorkItem,
)
from ai_security_hot.models.tables import Document, DocumentIdentity
from ai_security_hot.semantic.candidate_scan import STRONG_ENTITY_TYPES
from ai_security_hot.semantic.versions import (
    ATOMIC_EMBEDDING_TASK_VERSION,
    EMBEDDING_RECALL_VERSION,
    RELATION_VERSION,
)
from ai_security_hot.storage.repositories import current_document_conditions

log = logging.getLogger("intel.embeddings")
EMBEDDING_TASK = "atomic_embedding"


@dataclass(frozen=True)
class EmbeddingLease:
    work_item_id: int
    atomic_event_id: int
    document_id: int
    attempts: int
    lease_token: str
    text: str
    input_hash: str


def embedding_execution_version(
    config: ResolvedEmbeddingConfig,
    provider: EmbeddingProvider,
) -> str:
    identity = "\0".join(
        (
            ATOMIC_EMBEDDING_TASK_VERSION,
            provider.cache_namespace,
            config.model or "unconfigured",
            str(config.dimensions or "native"),
            str(config.max_input_chars),
        )
    )
    return hashlib.sha256(identity.encode()).hexdigest()[:24]


def _embedding_text(atomic: AtomicEvent, document: Document, *, max_chars: int) -> str:
    parts = [
        f"event_type: {atomic.event_type}",
        f"subject: {atomic.subject}",
        f"action: {atomic.action}",
        f"object: {atomic.object or ''}",
        f"time: {atomic.time_text or ''}",
        f"location: {atomic.location or ''}",
        f"event_summary: {atomic.summary}",
        f"document_title: {document.title_original}",
    ]
    return "\n".join(parts)[:max_chars]


def _reconcile_orphan_embedding_work(session: Session, *, execution_version: str) -> int:
    orphan_ids = list(
        session.execute(
            select(SemanticWorkItem.id)
            .outerjoin(
                AtomicEventEmbedding,
                AtomicEventEmbedding.work_item_id == SemanticWorkItem.id,
            )
            .where(
                SemanticWorkItem.subject_type == "atomic_event",
                SemanticWorkItem.task == EMBEDDING_TASK,
                SemanticWorkItem.execution_version == execution_version,
                SemanticWorkItem.status == "succeeded",
                AtomicEventEmbedding.id.is_(None),
            )
        ).scalars()
    )
    if orphan_ids:
        session.execute(
            update(SemanticWorkItem)
            .where(SemanticWorkItem.id.in_(orphan_ids))
            .values(
                status="retry",
                attempts=0,
                next_retry_at=None,
                error="succeeded embedding work has no result row (reconciled)",
                updated_at=datetime.now(UTC),
            )
        )
    session.flush()
    return len(orphan_ids)


def enqueue_embedding_work(
    session: Session,
    *,
    execution_version: str,
    limit: int,
) -> int:
    """Queue current non-CVE atomic events once per embedding execution."""

    _reconcile_orphan_embedding_work(session, execution_version=execution_version)
    has_embedding = (
        select(AtomicEventEmbedding.id)
        .where(
            AtomicEventEmbedding.atomic_event_id == AtomicEvent.id,
            AtomicEventEmbedding.execution_version == execution_version,
        )
        .exists()
    )
    has_work = (
        select(SemanticWorkItem.id)
        .where(
            SemanticWorkItem.subject_type == "atomic_event",
            SemanticWorkItem.subject_id == AtomicEvent.id,
            SemanticWorkItem.task == EMBEDDING_TASK,
            SemanticWorkItem.execution_version == execution_version,
        )
        .exists()
    )
    atomic_ids = list(
        session.execute(
            select(AtomicEvent.id)
            .join(Document, Document.id == AtomicEvent.document_id)
            .where(
                *current_document_conditions(),
                or_(
                    Document.classified_event_type.is_(None),
                    Document.classified_event_type != "cve",
                ),
                Document.tech_directions != ["cve"],
                func.coalesce(Document.identifiers["cve"].astext, "[]") == "[]",
                func.coalesce(Document.identifiers["ghsa"].astext, "[]") == "[]",
                func.coalesce(Document.identifiers["cnvd"].astext, "[]") == "[]",
                Document.dedupe_version.is_not(None),
                ~has_embedding,
                ~has_work,
            )
            .order_by(AtomicEvent.id)
            .limit(limit)
        ).scalars()
    )
    if not atomic_ids:
        return 0
    inserted = list(
        session.execute(
            pg_insert(SemanticWorkItem)
            .values(
                [
                    {
                        "subject_type": "atomic_event",
                        "subject_id": int(atomic_id),
                        "task": EMBEDDING_TASK,
                        "task_version": ATOMIC_EMBEDDING_TASK_VERSION,
                        "execution_version": execution_version,
                        "mode": "shadow",
                        "status": "pending",
                    }
                    for atomic_id in atomic_ids
                ]
            )
            .on_conflict_do_nothing(constraint="uq_semantic_work_execution")
            .returning(SemanticWorkItem.id)
        ).scalars()
    )
    session.flush()
    return len(inserted)


def claim_embedding_work(
    session: Session,
    *,
    execution_version: str,
    limit: int,
    lease_seconds: int,
    max_input_chars: int,
) -> list[EmbeddingLease]:
    now = datetime.now(UTC)
    session.execute(
        update(SemanticWorkItem)
        .where(
            SemanticWorkItem.subject_type == "atomic_event",
            SemanticWorkItem.task == EMBEDDING_TASK,
            SemanticWorkItem.execution_version == execution_version,
            SemanticWorkItem.status == "running",
            SemanticWorkItem.lease_until < now,
            SemanticWorkItem.attempts >= SemanticWorkItem.max_attempts,
        )
        .values(
            status="failed",
            lease_token=None,
            lease_until=None,
            next_retry_at=None,
            error="embedding lease expired after maximum attempts",
            updated_at=now,
        )
    )
    eligible = or_(
        SemanticWorkItem.status == "pending",
        and_(
            SemanticWorkItem.status == "retry",
            or_(
                SemanticWorkItem.next_retry_at.is_(None),
                SemanticWorkItem.next_retry_at <= now,
            ),
        ),
        and_(
            SemanticWorkItem.status == "running",
            SemanticWorkItem.lease_until < now,
        ),
    )
    rows = list(
        session.execute(
            select(SemanticWorkItem)
            .where(
                SemanticWorkItem.subject_type == "atomic_event",
                SemanticWorkItem.task == EMBEDDING_TASK,
                SemanticWorkItem.execution_version == execution_version,
                eligible,
                SemanticWorkItem.attempts < SemanticWorkItem.max_attempts,
            )
            .order_by(SemanticWorkItem.id)
            .limit(limit)
            .with_for_update(skip_locked=True)
        ).scalars()
    )
    if not rows:
        return []
    atomics = {
        int(atomic.id): atomic
        for atomic in session.execute(
            select(AtomicEvent).where(AtomicEvent.id.in_([row.subject_id for row in rows]))
        ).scalars()
    }
    documents = {
        int(document.id): document
        for document in session.execute(
            select(Document).where(
                Document.id.in_(
                    [
                        atomics[int(row.subject_id)].document_id
                        for row in rows
                        if int(row.subject_id) in atomics
                    ]
                ),
                *current_document_conditions(),
            )
        ).scalars()
    }
    leases: list[EmbeddingLease] = []
    for row in rows:
        atomic = atomics.get(int(row.subject_id))
        document = documents.get(int(atomic.document_id)) if atomic is not None else None
        if atomic is None or document is None:
            row.status = "cancelled"
            row.lease_token = None
            row.lease_until = None
            row.error = "atomic event or document is no longer current"
            row.updated_at = now
            continue
        token = token_urlsafe(32)
        text = _embedding_text(atomic, document, max_chars=max_input_chars)
        row.status = "running"
        row.lease_token = token
        row.lease_until = now + timedelta(seconds=lease_seconds)
        row.attempts += 1
        row.updated_at = now
        leases.append(
            EmbeddingLease(
                work_item_id=int(row.id),
                atomic_event_id=int(atomic.id),
                document_id=int(document.id),
                attempts=int(row.attempts),
                lease_token=token,
                text=text,
                input_hash=content_sha256(ATOMIC_EMBEDDING_TASK_VERSION, text),
            )
        )
    session.flush()
    return leases


def complete_embedding_work(
    session: Session,
    lease: EmbeddingLease,
    *,
    execution_version: str,
    provider_name: str,
    model: str,
    vector: list[float],
    usage: dict,
) -> int:
    work = session.execute(
        select(SemanticWorkItem)
        .where(
            SemanticWorkItem.id == lease.work_item_id,
            SemanticWorkItem.status == "running",
            SemanticWorkItem.lease_token == lease.lease_token,
        )
        .with_for_update()
    ).scalar_one_or_none()
    if work is None:
        raise RuntimeError(f"embedding lease lost: {lease.work_item_id}")
    current_atomic = session.execute(
        select(AtomicEvent.id)
        .join(Document, Document.id == AtomicEvent.document_id)
        .where(AtomicEvent.id == lease.atomic_event_id, *current_document_conditions())
    ).scalar_one_or_none()
    if current_atomic is None:
        work.status = "cancelled"
        work.lease_token = None
        work.lease_until = None
        work.error = "atomic event document is no longer current"
        work.updated_at = datetime.now(UTC)
        session.flush()
        return 0
    clean_vector = [float(value) for value in vector]
    if not clean_vector or any(not math.isfinite(value) for value in clean_vector):
        raise ValueError("embedding vector is empty or non-finite")
    norm = math.sqrt(sum(value * value for value in clean_vector))
    if not math.isfinite(norm) or norm <= 0:
        raise ValueError("embedding vector has zero or invalid norm")
    existing_dimension = session.execute(
        select(AtomicEventEmbedding.dimensions)
        .where(AtomicEventEmbedding.execution_version == execution_version)
        .limit(1)
    ).scalar_one_or_none()
    if existing_dimension is not None and int(existing_dimension) != len(clean_vector):
        raise ValueError(
            f"embedding dimension changed within execution {execution_version}: "
            f"{existing_dimension} != {len(clean_vector)}"
        )
    existing = session.execute(
        select(AtomicEventEmbedding).where(
            AtomicEventEmbedding.atomic_event_id == lease.atomic_event_id,
            AtomicEventEmbedding.execution_version == execution_version,
        )
    ).scalar_one_or_none()
    if existing is None:
        embedding = AtomicEventEmbedding(
            work_item_id=lease.work_item_id,
            atomic_event_id=lease.atomic_event_id,
            task_version=ATOMIC_EMBEDDING_TASK_VERSION,
            execution_version=execution_version,
            input_hash=lease.input_hash,
            provider=provider_name,
            model=model,
            dimensions=len(clean_vector),
            vector=clean_vector,
            norm=norm,
            usage=usage,
        )
        session.add(embedding)
        session.flush()
        embedding_id = int(embedding.id)
    else:
        embedding_id = int(existing.id)
    work.status = "succeeded"
    work.lease_token = None
    work.lease_until = None
    work.next_retry_at = None
    work.error = None
    work.last_usage = usage
    work.updated_at = datetime.now(UTC)
    session.flush()
    return embedding_id


def fail_embedding_work(session: Session, lease: EmbeddingLease, error: Exception) -> bool:
    work = session.execute(
        select(SemanticWorkItem)
        .where(
            SemanticWorkItem.id == lease.work_item_id,
            SemanticWorkItem.status == "running",
            SemanticWorkItem.lease_token == lease.lease_token,
        )
        .with_for_update()
    ).scalar_one_or_none()
    if work is None:
        return False
    now = datetime.now(UTC)
    terminal = work.attempts >= work.max_attempts
    work.status = "failed" if terminal else "retry"
    work.next_retry_at = (
        None if terminal else now + timedelta(seconds=min(3600, 30 * 2 ** int(work.attempts)))
    )
    message = f"{type(error).__name__}: {error}"
    if isinstance(error, EmbeddingProviderError):
        work.last_usage = error.usage
        if error.raw_response:
            message = f"{message}; response={error.raw_response}"
    work.error = message[:8000]
    work.lease_token = None
    work.lease_until = None
    work.updated_at = now
    session.flush()
    return True


def _cosine(left: AtomicEventEmbedding, right: AtomicEventEmbedding) -> float:
    left_vector = [float(value) for value in left.vector]
    right_vector = [float(value) for value in right.vector]
    if len(left_vector) != len(right_vector) or not left_vector:
        return -1.0
    denominator = float(left.norm) * float(right.norm)
    if denominator <= 0:
        return -1.0
    return sum(a * b for a, b in zip(left_vector, right_vector, strict=True)) / denominator


def _shared_strong_entity(
    session: Session, left_atomic_id: int, right_atomic_id: int
) -> str | None:
    row = session.execute(
        select(SemanticEntity.canonical_key)
        .join(EntityMention, EntityMention.entity_id == SemanticEntity.id)
        .where(
            EntityMention.atomic_event_id.in_([left_atomic_id, right_atomic_id]),
            EntityMention.confidence >= 0.7,
            SemanticEntity.entity_type.in_(STRONG_ENTITY_TYPES),
        )
        .group_by(SemanticEntity.id, SemanticEntity.canonical_key)
        .having(func.count(func.distinct(EntityMention.atomic_event_id)) == 2)
        .order_by(SemanticEntity.canonical_key)
        .limit(1)
    ).scalar_one_or_none()
    return str(row)[:64] if row is not None else None


def _hard_identity_conflict(
    session: Session, left_document_id: int, right_document_id: int
) -> str | None:
    rows = session.execute(
        select(
            DocumentIdentity.document_id, DocumentIdentity.kind, DocumentIdentity.fingerprint
        ).where(
            DocumentIdentity.document_id.in_([left_document_id, right_document_id]),
            DocumentIdentity.event_key.is_(True),
        )
    ).all()
    by_document: dict[int, dict[str, set[str]]] = {
        left_document_id: {},
        right_document_id: {},
    }
    for document_id, kind, fingerprint in rows:
        by_document[int(document_id)].setdefault(str(kind), set()).add(str(fingerprint))
    left = by_document[left_document_id]
    right = by_document[right_document_id]
    for kind in sorted(left.keys() & right.keys()):
        if left[kind].isdisjoint(right[kind]):
            return f"conflict:{kind}"[:64]
    vuln_kinds = ("cve", "ghsa", "cnvd")
    left_vulns = {value for kind in vuln_kinds for value in left.get(kind, set())}
    right_vulns = {value for kind in vuln_kinds for value in right.get(kind, set())}
    if left_vulns and right_vulns and left_vulns.isdisjoint(right_vulns):
        return "conflict:vulnerability"
    return None


def _locked_recall_state(
    session: Session,
    *,
    execution_version: str,
) -> EmbeddingRecallState:
    session.execute(
        pg_insert(EmbeddingRecallState)
        .values(
            recall_version=EMBEDDING_RECALL_VERSION,
            embedding_execution_version=execution_version,
            last_embedding_id=0,
        )
        .on_conflict_do_nothing(constraint="uq_embedding_recall_state_version")
    )
    return session.execute(
        select(EmbeddingRecallState)
        .where(
            EmbeddingRecallState.recall_version == EMBEDDING_RECALL_VERSION,
            EmbeddingRecallState.embedding_execution_version == execution_version,
        )
        .with_for_update()
    ).scalar_one()


def recall_embedding_candidates(
    session: Session,
    *,
    execution_version: str,
    seed_limit: int,
    pool_limit: int,
    top_k: int,
    threshold: float,
    window_days: int,
) -> dict:
    """Recall bounded vector candidates; vector-only pairs await a later judge."""

    state = _locked_recall_state(session, execution_version=execution_version)
    seeds = session.execute(
        select(AtomicEventEmbedding, AtomicEvent, Document)
        .join(AtomicEvent, AtomicEvent.id == AtomicEventEmbedding.atomic_event_id)
        .join(Document, Document.id == AtomicEvent.document_id)
        .where(
            AtomicEventEmbedding.execution_version == execution_version,
            AtomicEventEmbedding.id > state.last_embedding_id,
            *current_document_conditions(),
        )
        .order_by(AtomicEventEmbedding.id)
        .limit(seed_limit)
    ).all()
    inserted = updated = blocked = pending = recalled = 0
    for seed_embedding, seed_atomic, seed_document in seeds:
        observed_at = seed_document.published_at_utc or seed_atomic.created_at
        lower = observed_at - timedelta(days=window_days)
        upper = observed_at + timedelta(days=window_days)
        candidate_observed_at = func.coalesce(Document.published_at_utc, AtomicEvent.created_at)
        pool = session.execute(
            select(AtomicEventEmbedding, AtomicEvent, Document)
            .join(AtomicEvent, AtomicEvent.id == AtomicEventEmbedding.atomic_event_id)
            .join(Document, Document.id == AtomicEvent.document_id)
            .where(
                AtomicEventEmbedding.execution_version == execution_version,
                AtomicEventEmbedding.id < seed_embedding.id,
                AtomicEventEmbedding.dimensions == seed_embedding.dimensions,
                AtomicEvent.document_id != seed_atomic.document_id,
                candidate_observed_at >= lower,
                candidate_observed_at <= upper,
                *current_document_conditions(),
            )
            .order_by(AtomicEventEmbedding.id.desc())
            .limit(pool_limit)
        ).all()
        scored = sorted(
            (
                (_cosine(seed_embedding, candidate_embedding), candidate_atomic, candidate_document)
                for candidate_embedding, candidate_atomic, candidate_document in pool
            ),
            key=lambda item: (-item[0], int(item[1].id)),
        )
        for score, candidate_atomic, candidate_document in scored[:top_k]:
            if score < threshold:
                continue
            left_atomic, right_atomic = sorted((int(seed_atomic.id), int(candidate_atomic.id)))
            left_document_id = (
                int(seed_document.id)
                if left_atomic == int(seed_atomic.id)
                else int(candidate_document.id)
            )
            right_document_id = (
                int(candidate_document.id)
                if right_atomic == int(candidate_atomic.id)
                else int(seed_document.id)
            )
            shared_entity = _shared_strong_entity(session, left_atomic, right_atomic)
            conflict = _hard_identity_conflict(
                session,
                left_document_id,
                right_document_id,
            )
            deterministic = seed_atomic.fingerprint == candidate_atomic.fingerprint or bool(
                shared_entity
            )
            status = "blocked" if conflict else ("pending" if deterministic else "recalled")
            existing = session.execute(
                select(RelationCandidate)
                .where(
                    RelationCandidate.left_atomic_id == left_atomic,
                    RelationCandidate.right_atomic_id == right_atomic,
                    RelationCandidate.algorithm_version == RELATION_VERSION,
                )
                .with_for_update()
            ).scalar_one_or_none()
            if existing is None:
                session.add(
                    RelationCandidate(
                        left_atomic_id=left_atomic,
                        right_atomic_id=right_atomic,
                        shared_entity=shared_entity,
                        embedding_score=round(score, 6),
                        embedding_version=execution_version,
                        hard_conflict=conflict,
                        algorithm_version=RELATION_VERSION,
                        status=status,
                    )
                )
                inserted += 1
                blocked += int(status == "blocked")
                pending += int(status == "pending")
                recalled += int(status == "recalled")
            else:
                existing.embedding_score = max(existing.embedding_score or -1.0, round(score, 6))
                existing.embedding_version = execution_version
                existing.shared_entity = existing.shared_entity or shared_entity
                existing.hard_conflict = existing.hard_conflict or conflict
                if existing.status == "recalled":
                    existing.status = status
                updated += 1
        state.last_embedding_id = int(seed_embedding.id)
        state.updated_at = datetime.now(UTC)
    session.flush()
    return {
        "seeds": len(seeds),
        "inserted": inserted,
        "updated": updated,
        "pending": pending,
        "recalled": recalled,
        "blocked": blocked,
        "cursor": int(state.last_embedding_id),
    }


def run_embedding_stage(
    settings: Settings | None = None,
    *,
    provider: EmbeddingProvider | None = None,
) -> dict:
    """Generate one bounded embedding batch, then advance durable recall."""

    settings = settings or get_settings()
    if not settings.embedding_enabled:
        return {"status": "disabled"}
    config = resolve_embedding_config(settings)
    provider = provider or build_embedding_provider(settings, config=config)
    if not config.model:
        raise ValueError("embedding model is not configured")
    execution_version = embedding_execution_version(config, provider)
    with session_scope() as session:
        enqueued = enqueue_embedding_work(
            session,
            execution_version=execution_version,
            limit=settings.embedding_batch_size,
        )
    with session_scope() as session:
        leases = claim_embedding_work(
            session,
            execution_version=execution_version,
            limit=settings.embedding_batch_size,
            lease_seconds=settings.embedding_lease_seconds,
            max_input_chars=config.max_input_chars,
        )
    completed = failed = 0
    if leases:
        try:
            response = provider.embed([lease.text for lease in leases])
        except Exception as exc:
            failed = len(leases)
            for lease in leases:
                with session_scope() as session:
                    fail_embedding_work(session, lease, exc)
            log.exception(
                "embedding provider batch failed: work_items=%s",
                [row.work_item_id for row in leases],
            )
        else:
            for lease, vector in zip(leases, response.vectors, strict=True):
                try:
                    with session_scope() as session:
                        completed += int(
                            complete_embedding_work(
                                session,
                                lease,
                                execution_version=execution_version,
                                provider_name=provider.cache_namespace,
                                model=provider.model,
                                vector=vector,
                                usage=response.usage,
                            )
                            > 0
                        )
                except Exception as exc:
                    failed += 1
                    with session_scope() as session:
                        fail_embedding_work(session, lease, exc)
                    log.exception("embedding result persistence failed: id=%s", lease.work_item_id)
    with session_scope() as session:
        recall = recall_embedding_candidates(
            session,
            execution_version=execution_version,
            seed_limit=settings.embedding_batch_size,
            pool_limit=settings.embedding_recall_pool_limit,
            top_k=settings.embedding_recall_top_k,
            threshold=settings.embedding_recall_threshold,
            window_days=settings.embedding_recall_window_days,
        )
    return {
        "status": "ok",
        "execution_version": execution_version,
        "enqueued": enqueued,
        "claimed": len(leases),
        "completed": completed,
        "failed": failed,
        "recall": recall,
    }
