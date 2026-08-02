"""Cross-document atomic-event candidate recall + adjudication (M2.3, shadow).

Finds atomic-event pairs across different documents that share a strong entity
(SemanticEntity via EntityMention), then runs the deterministic adjudicator and
records shadow verdicts. Nothing here mutates materialized Events.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ai_security_hot.models.semantic_tables import (
    AtomicEvent,
    EntityMention,
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
    shared_entity_ids = session.execute(
        select(SemanticEntity.id)
        .join(EntityMention, EntityMention.entity_id == SemanticEntity.id)
        .group_by(SemanticEntity.id)
        .having(func.count(func.distinct(EntityMention.document_id)) >= min_documents)
    ).scalars().all()

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
        verdicts.append(
            adjudicate(left, right, shared_entities={_entity})
        )
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
