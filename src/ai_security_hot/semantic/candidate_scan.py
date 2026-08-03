"""Cross-document atomic-event candidate recall + adjudication (M2.3, shadow).

Finds atomic-event pairs across different documents that share a strong entity
(SemanticEntity via EntityMention), then runs the deterministic adjudicator and
records shadow verdicts. Nothing here mutates materialized Events.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe

from sqlalchemy import func, or_, select
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

log = logging.getLogger("intel.relations")


def _atomic_refs(session: Session, atomic_ids: list[int]) -> dict[int, AtomicEventRef]:
    """Build AtomicEventRef for a set of atomic-event ids, joining published time."""
    from ai_security_hot.models.tables import Document

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
        .where(AtomicEvent.id.in_(atomic_ids))
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
    # Entities appearing in >= min_documents distinct documents.
    shared_entity_ids = (
        session.execute(
            select(SemanticEntity.id)
            .join(EntityMention, EntityMention.entity_id == SemanticEntity.id)
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
            .where(
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
    session: Session, candidates: list[tuple[int, int, str]]
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
        verdicts.append(adjudicate(left, right, shared_entities={_entity}))
    return verdicts


def persist_verdicts(session: Session, verdicts: list[RelationVerdict]) -> int:
    """Upsert shadow relation verdicts. Returns number of rows written."""
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    from ai_security_hot.models.semantic_tables import RelationVerdict as RelationVerdictRow

    if not verdicts:
        return 0
    rows = [
        {
            "left_atomic_id": v.left_atomic_id,
            "right_atomic_id": v.right_atomic_id,
            "decision": v.decision,
            "confidence": v.confidence,
            "reason": v.reason,
            "shared_entity": v.shared_entity,
            "algorithm_version": "relation-v1",
        }
        for v in verdicts
    ]
    # Insert row-by-row: a multi-row ON CONFLICT DO UPDATE is ambiguous when two
    # excluded rows could update the same target (CardinalityViolation).
    for row in rows:
        stmt = pg_insert(RelationVerdictRow).values(**row)
        stmt = stmt.on_conflict_do_update(
            index_elements=["left_atomic_id", "right_atomic_id"],
            set_={
                "decision": stmt.excluded.decision,
                "confidence": stmt.excluded.confidence,
                "reason": stmt.excluded.reason,
                "shared_entity": stmt.excluded.shared_entity,
            },
        )
        session.execute(stmt)
    session.flush()
    return len(rows)


RELATION_VERSION = "relation-v2"
STRONG_ENTITY_TYPES = {
    "model_version",
    "package",
    "repository",
    "vulnerability",
    "ai_component",
    "campaign",
    "product",
}


def enqueue_candidate_pairs(
    session: Session, *, seed_limit: int = 100, pair_limit: int = 500, bucket_limit: int = 100
) -> dict:
    """Incrementally scan only new AtomicEvents and durably enqueue bounded pairs."""
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    state = session.get(RelationScanState, RELATION_VERSION)
    if state is None:
        state = RelationScanState(algorithm_version=RELATION_VERSION, last_atomic_id=0)
        session.add(state)
        session.flush()
    seeds = list(
        session.execute(
            select(AtomicEvent)
            .where(AtomicEvent.id > state.last_atomic_id)
            .order_by(AtomicEvent.id)
            .limit(seed_limit)
        ).scalars()
    )
    inserted = 0
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
                select(AtomicEvent.id, AtomicEvent.document_id)
                .join(EntityMention, EntityMention.atomic_event_id == AtomicEvent.id)
                .where(
                    EntityMention.entity_id == entity_id,
                    AtomicEvent.id != seed.id,
                    AtomicEvent.document_id != seed.document_id,
                )
                .order_by(AtomicEvent.id.desc())
                .limit(bucket_limit)
            ).all()
            for other_id, _doc_id in matches:
                left, right = sorted((int(seed.id), int(other_id)))
                result = session.execute(
                    pg_insert(RelationCandidate)
                    .values(
                        left_atomic_id=left,
                        right_atomic_id=right,
                        shared_entity=str(entity_key),
                        algorithm_version=RELATION_VERSION,
                    )
                    .on_conflict_do_nothing(constraint="uq_relation_candidate_version")
                )
                inserted += int(result.rowcount or 0)
                if inserted >= pair_limit:
                    seed_complete = False
                    break
            if not seed_complete:
                break
        if not seed_complete:
            # Do not advance past a partially scanned seed. On the next run,
            # conflict-safe inserts skip prior pairs and resume without loss.
            break
        state.last_atomic_id = seed.id
        state.updated_at = datetime.now(UTC)
    session.flush()
    return {"seeds": len(seeds), "enqueued": inserted, "cursor": int(state.last_atomic_id)}


def process_candidate_queue(
    session: Session, *, limit: int = 100, lease_seconds: int = 300
) -> dict:
    """Lease queue rows with SKIP LOCKED; expired leases are recoverable."""
    now = datetime.now(UTC)
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
    for row in rows:
        row.status = "running"
        row.lease_token = token
        row.lease_until = now + timedelta(seconds=lease_seconds)
        row.attempts += 1
    session.flush()
    candidates = [
        (int(row.left_atomic_id), int(row.right_atomic_id), row.shared_entity) for row in rows
    ]
    try:
        verdicts = adjudicate_candidates(session, candidates)
        persist_verdicts(session, verdicts)
        for row in rows:
            row.status = "succeeded"
            row.lease_token = None
            row.lease_until = None
            row.error = None
            row.updated_at = datetime.now(UTC)
        return {"claimed": len(rows), "persisted": len(verdicts)}
    except Exception as exc:
        for row in rows:
            row.status = "failed" if row.attempts >= row.max_attempts else "retry"
            row.next_retry_at = now + timedelta(seconds=min(3600, 30 * 2**row.attempts))
            row.error = f"{type(exc).__name__}: {exc}"
            row.lease_token = None
            row.lease_until = None
        raise


def run_incremental_relation_scan(
    session: Session, *, seed_limit: int = 100, pair_limit: int = 500, work_limit: int = 100
) -> dict:
    queued = enqueue_candidate_pairs(session, seed_limit=seed_limit, pair_limit=pair_limit)
    processed = process_candidate_queue(session, limit=work_limit)
    return {**queued, **processed}
