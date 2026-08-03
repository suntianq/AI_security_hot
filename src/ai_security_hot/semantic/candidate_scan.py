"""Cross-document atomic-event candidate recall + adjudication (M2.3, shadow).

Finds atomic-event pairs across different documents that share a strong entity
(SemanticEntity via EntityMention), then runs the deterministic adjudicator and
records shadow verdicts. Nothing here mutates materialized Events.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe

from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session

from ai_security_hot.models.semantic_tables import (
    AtomicEvent,
    EntityMention,
    RelationCandidate,
    RelationScanState,
    SemanticEntity,
)
from ai_security_hot.semantic.relations import (
    AtomicEventRef,
    RelationVerdict,
    adjudicate,
)
from ai_security_hot.semantic.versions import RELATION_VERSION

log = logging.getLogger("intel.relations")


def _atomic_refs(session: Session, atomic_ids: list[int]) -> dict[int, AtomicEventRef]:
    """Build AtomicEventRef for a set of atomic-event ids, joining published time."""
    from ai_security_hot.models.tables import Document
    from ai_security_hot.storage.repositories import current_document_conditions

    rows = session.execute(
        select(
            AtomicEvent.id,
            AtomicEvent.document_id,
            AtomicEvent.fingerprint,
            AtomicEvent.subject,
            AtomicEvent.action,
            AtomicEvent.object,
            AtomicEvent.time_text,
            Document.published_at_utc,
        )
        .join(Document, Document.id == AtomicEvent.document_id)
        .where(AtomicEvent.id.in_(atomic_ids), *current_document_conditions())
    ).all()
    refs: dict[int, AtomicEventRef] = {}
    for row in rows:
        refs[int(row.id)] = AtomicEventRef(
            id=int(row.id),
            document_id=int(row.document_id),
            fingerprint=row.fingerprint,
            subject=row.subject,
            action=row.action,
            object=row.object,
            time_text=row.time_text,
            published_at=row.published_at_utc,
        )
    return refs


def scan_candidate_pairs(
    session: Session,
    *,
    min_documents: int = 2,
    limit: int = 500,
) -> list[tuple[int, int, str]]:
    """Return candidate (left_atomic_id, right_atomic_id, shared_entity) pairs
    where two atomic events from DIFFERENT documents share a strong entity."""
    from ai_security_hot.models.tables import Document
    from ai_security_hot.storage.repositories import current_document_conditions

    # Entities appearing in >= min_documents distinct current documents.
    shared_entity_ids = (
        session.execute(
            select(SemanticEntity.id)
            .join(EntityMention, EntityMention.entity_id == SemanticEntity.id)
            .join(Document, Document.id == EntityMention.document_id)
            .where(*current_document_conditions())
            .group_by(SemanticEntity.id)
            .having(func.count(func.distinct(EntityMention.document_id)) >= min_documents)
        )
        .scalars()
        .all()
    )

    # entity -> [(atomic_id, doc_id)]
    entity_atomics: dict[int, list[tuple[int, int]]] = defaultdict(list)
    if shared_entity_ids:
        rows = session.execute(
            select(EntityMention.entity_id, AtomicEvent.id, AtomicEvent.document_id)
            .join(AtomicEvent, AtomicEvent.id == EntityMention.atomic_event_id)
            .join(Document, Document.id == AtomicEvent.document_id)
            .where(
                *current_document_conditions(),
                EntityMention.entity_id.in_(shared_entity_ids),
                EntityMention.atomic_event_id.is_not(None),
            )
        ).all()
        for entity_id, atomic_id, doc_id in rows:
            entity_atomics[int(entity_id)].append((int(atomic_id), int(doc_id)))

    candidates: list[tuple[int, int, str]] = []
    for entity_id, atomics in entity_atomics.items():
        docs_by_atomic: dict[int, set[int]] = {}
        for atomic_id, doc_id in atomics:
            docs_by_atomic.setdefault(atomic_id, set()).add(doc_id)
        atomic_ids = list(docs_by_atomic.keys())
        for i in range(len(atomic_ids)):
            for j in range(i + 1, len(atomic_ids)):
                left, right = atomic_ids[i], atomic_ids[j]
                if docs_by_atomic[left] & docs_by_atomic[right]:
                    continue  # same document somewhere — skip
                candidates.append((left, right, f"entity:{entity_id}"))
                if len(candidates) >= limit:
                    return candidates
    return candidates


def adjudicate_candidates(
    session: Session, candidates: Sequence[tuple[int, int, str | None]]
) -> list[RelationVerdict]:
    """Adjudicate candidate pairs and return verdicts (shadow, not persisted)."""
    atomic_ids = {aid for pair in candidates for aid in pair[:2]}
    refs = _atomic_refs(session, list(atomic_ids))
    verdicts: list[RelationVerdict] = []
    for left_id, right_id, _entity in candidates:
        left = refs.get(left_id)
        right = refs.get(right_id)
        if left is None or right is None:
            continue
        verdicts.append(adjudicate(left, right, shared_entities={_entity} if _entity else set()))
    return verdicts


def persist_verdicts(
    session: Session,
    verdicts: list[RelationVerdict],
    *,
    algorithm_version: str,
) -> int:
    """Upsert a versioned verdict without overwriting prior algorithm runs."""
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from ai_security_hot.models.semantic_tables import RelationVerdict as RelationVerdictRow

    for verdict in verdicts:
        stmt = pg_insert(RelationVerdictRow).values(
            left_atomic_id=verdict.left_atomic_id,
            right_atomic_id=verdict.right_atomic_id,
            decision=verdict.decision,
            confidence=verdict.confidence,
            reason=verdict.reason,
            shared_entity=verdict.shared_entity,
            algorithm_version=algorithm_version,
        )
        session.execute(
            stmt.on_conflict_do_update(
                constraint="uq_relation_pair_version",
                set_={
                    "decision": stmt.excluded.decision,
                    "confidence": stmt.excluded.confidence,
                    "reason": stmt.excluded.reason,
                    "shared_entity": stmt.excluded.shared_entity,
                },
            )
        )
    if verdicts:
        from ai_security_hot.semantic.components import enqueue_component_work

        enqueue_component_work(
            session,
            {
                atomic_id
                for verdict in verdicts
                for atomic_id in (verdict.left_atomic_id, verdict.right_atomic_id)
            },
            reason="relation_verdict_changed",
        )
    session.flush()
    return len(verdicts)


STRONG_ENTITY_TYPES = {
    "model_version",
    "package",
    "repository",
    "vulnerability",
    "ai_component",
    "campaign",
    "product",
}


@dataclass(frozen=True)
class CandidateLease:
    id: int
    left_atomic_id: int
    right_atomic_id: int
    shared_entity: str | None
    attempts: int
    lease_token: str


def _locked_scan_state(session: Session) -> RelationScanState:
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    session.execute(
        pg_insert(RelationScanState)
        .values(algorithm_version=RELATION_VERSION, last_atomic_id=0)
        .on_conflict_do_nothing(index_elements=["algorithm_version"])
    )
    return session.execute(
        select(RelationScanState)
        .where(RelationScanState.algorithm_version == RELATION_VERSION)
        .with_for_update()
    ).scalar_one()


def enqueue_candidate_pairs(
    session: Session, *, seed_limit: int = 100, pair_limit: int = 500, bucket_limit: int = 100
) -> dict:
    """Scan new current-document AtomicEvents with a serialized durable cursor."""
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from ai_security_hot.models.tables import Document
    from ai_security_hot.storage.repositories import current_document_conditions

    state = _locked_scan_state(session)
    seeds = list(
        session.execute(
            select(AtomicEvent)
            .join(Document, Document.id == AtomicEvent.document_id)
            .where(
                AtomicEvent.id > state.last_atomic_id,
                *current_document_conditions(),
            )
            .order_by(AtomicEvent.id)
            .limit(seed_limit)
        ).scalars()
    )
    inserted = 0
    processed = 0
    for seed in seeds:
        seed_complete = True
        mentions = session.execute(
            select(EntityMention.entity_id, SemanticEntity.canonical_key)
            .join(SemanticEntity, SemanticEntity.id == EntityMention.entity_id)
            .where(
                EntityMention.atomic_event_id == seed.id,
                EntityMention.confidence >= 0.7,
                SemanticEntity.entity_type.in_(STRONG_ENTITY_TYPES),
            )
        ).all()
        for entity_id, entity_key in mentions:
            matches = session.execute(
                select(AtomicEvent.id)
                .join(EntityMention, EntityMention.atomic_event_id == AtomicEvent.id)
                .join(Document, Document.id == AtomicEvent.document_id)
                .where(
                    EntityMention.entity_id == entity_id,
                    AtomicEvent.id != seed.id,
                    AtomicEvent.document_id != seed.document_id,
                    *current_document_conditions(),
                )
                .order_by(AtomicEvent.id.desc())
                .limit(bucket_limit)
            ).scalars()
            for other_id in matches:
                left, right = sorted((int(seed.id), int(other_id)))
                candidate_stmt = pg_insert(RelationCandidate).values(
                    left_atomic_id=left,
                    right_atomic_id=right,
                    shared_entity=str(entity_key),
                    algorithm_version=RELATION_VERSION,
                )
                inserted_id = session.execute(
                    candidate_stmt.on_conflict_do_update(
                        constraint="uq_relation_candidate_version",
                        set_={
                            "shared_entity": candidate_stmt.excluded.shared_entity,
                            "status": "pending",
                            "error": None,
                            "updated_at": datetime.now(UTC),
                        },
                        where=(
                            (RelationCandidate.status == "recalled")
                            & RelationCandidate.hard_conflict.is_(None)
                        ),
                    ).returning(RelationCandidate.id)
                ).scalar_one_or_none()
                inserted += int(inserted_id is not None)
                if inserted >= pair_limit:
                    seed_complete = False
                    break
            if not seed_complete:
                break
        if not seed_complete:
            break
        state.last_atomic_id = seed.id
        state.updated_at = datetime.now(UTC)
        processed += 1
    session.flush()
    return {"seeds": processed, "enqueued": inserted, "cursor": int(state.last_atomic_id)}


def claim_candidate_queue(
    session: Session, *, limit: int = 100, lease_seconds: int = 300
) -> list[CandidateLease]:
    """Claim and fence work; the caller must commit before adjudication."""
    now = datetime.now(UTC)
    session.execute(
        update(RelationCandidate)
        .where(
            RelationCandidate.status == "running",
            RelationCandidate.lease_until < now,
            RelationCandidate.attempts >= RelationCandidate.max_attempts,
        )
        .values(
            status="failed",
            lease_token=None,
            lease_until=None,
            next_retry_at=None,
            error="lease expired after maximum attempts",
            updated_at=now,
        )
    )
    token = token_urlsafe(24)
    eligible = or_(
        RelationCandidate.status.in_(["pending", "retry"]),
        (RelationCandidate.status == "running") & (RelationCandidate.lease_until < now),
    )
    rows = list(
        session.execute(
            select(RelationCandidate)
            .where(
                eligible,
                RelationCandidate.attempts < RelationCandidate.max_attempts,
                or_(
                    RelationCandidate.next_retry_at.is_(None),
                    RelationCandidate.next_retry_at <= now,
                ),
            )
            .order_by(RelationCandidate.id)
            .limit(limit)
            .with_for_update(skip_locked=True)
        ).scalars()
    )
    leases = []
    for row in rows:
        row.status = "running"
        row.lease_token = token
        row.lease_until = now + timedelta(seconds=lease_seconds)
        row.attempts += 1
        row.updated_at = now
        leases.append(
            CandidateLease(
                int(row.id),
                int(row.left_atomic_id),
                int(row.right_atomic_id),
                row.shared_entity,
                int(row.attempts),
                token,
            )
        )
    session.flush()
    return leases


def complete_candidate(session: Session, lease: CandidateLease) -> int:
    """Adjudicate one fenced candidate and atomically write its verdict/status."""
    row = session.execute(
        select(RelationCandidate)
        .where(
            RelationCandidate.id == lease.id,
            RelationCandidate.status == "running",
            RelationCandidate.lease_token == lease.lease_token,
        )
        .with_for_update()
    ).scalar_one_or_none()
    if row is None:
        raise RuntimeError(f"relation candidate lease lost: {lease.id}")
    verdicts = adjudicate_candidates(
        session, [(lease.left_atomic_id, lease.right_atomic_id, lease.shared_entity)]
    )
    written = persist_verdicts(session, verdicts, algorithm_version=RELATION_VERSION)
    row.status = "succeeded"
    row.lease_token = None
    row.lease_until = None
    row.next_retry_at = None
    row.error = None
    row.updated_at = datetime.now(UTC)
    session.flush()
    return written


def fail_candidate(
    session: Session, lease: CandidateLease, error: Exception, *, retry_base_seconds: int = 30
) -> bool:
    """Persist retry/terminal failure only when the fencing token is still owned."""
    row = session.execute(
        select(RelationCandidate)
        .where(
            RelationCandidate.id == lease.id,
            RelationCandidate.status == "running",
            RelationCandidate.lease_token == lease.lease_token,
        )
        .with_for_update()
    ).scalar_one_or_none()
    if row is None:
        return False
    now = datetime.now(UTC)
    terminal = row.attempts >= row.max_attempts
    row.status = "failed" if terminal else "retry"
    row.next_retry_at = (
        None
        if terminal
        else now + timedelta(seconds=min(3600, retry_base_seconds * 2 ** int(row.attempts)))
    )
    row.error = f"{type(error).__name__}: {error}"[:2000]
    row.lease_token = None
    row.lease_until = None
    row.updated_at = now
    session.flush()
    return True


def run_incremental_relation_scan(
    *, seed_limit: int = 100, pair_limit: int = 500, work_limit: int = 100
) -> dict:
    """Run enqueue, durable claim, then per-item isolated completion/failure transactions."""
    from ai_security_hot.models.base import session_scope

    with session_scope() as session:
        queued = enqueue_candidate_pairs(session, seed_limit=seed_limit, pair_limit=pair_limit)
    with session_scope() as session:
        leases = claim_candidate_queue(session, limit=work_limit)
    persisted = failed = 0
    for lease in leases:
        try:
            with session_scope() as session:
                persisted += complete_candidate(session, lease)
        except Exception as exc:
            failed += 1
            with session_scope() as session:
                fail_candidate(session, lease, exc)
            log.exception("relation candidate failed: id=%s", lease.id)
    return {**queued, "claimed": len(leases), "persisted": persisted, "failed": failed}
