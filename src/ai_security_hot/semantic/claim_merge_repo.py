"""Repository layer for M2.4 claim merging (shadow only, no formal writes).

Reads related atomic-event pairs from relation_verdicts, loads their extracted
claims, and merges them for preview. Merged claims are never written to the
formal Claim table here; the promotion path (B2) is intentionally gated and
currently only produces a dry-run preview.
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from ai_security_hot.models.semantic_tables import (
    AtomicEvent,
    ExtractedClaim,
    RelationVerdict,
)
from ai_security_hot.semantic.claim_merge import SourceClaim, merge_related_pair

log = logging.getLogger("intel.claim_merge")


def _load_claims_for_atomics(
    session: Session, atomic_ids: set[int]
) -> dict[int, list[SourceClaim]]:
    rows = session.execute(
        select(
            ExtractedClaim.atomic_event_id,
            AtomicEvent.document_id,
            ExtractedClaim.claim_type,
            ExtractedClaim.text,
            ExtractedClaim.normalized_value,
            ExtractedClaim.confidence,
            ExtractedClaim.evidence_excerpt,
            ExtractedClaim.evidence_field,
        )
        .join(AtomicEvent, AtomicEvent.id == ExtractedClaim.atomic_event_id)
        .where(ExtractedClaim.atomic_event_id.in_(atomic_ids))
    ).all()
    by_atomic: dict[int, list[SourceClaim]] = {}
    for row in rows:
        by_atomic.setdefault(int(row.atomic_event_id), []).append(
            SourceClaim(
                atomic_event_id=int(row.atomic_event_id),
                document_id=int(row.document_id),
                claim_type=row.claim_type,
                text=row.text,
                normalized_value=row.normalized_value,
                confidence=row.confidence,
                evidence_excerpt=row.evidence_excerpt,
                evidence_field=row.evidence_field,
            )
        )
    return by_atomic


def run_claim_merge(
    session: Session,
    *,
    limit: int = 200,
) -> dict:
    """Merge claims for related atomic-event pairs; return summary (shadow, no persist)."""
    verdicts = session.execute(
        select(RelationVerdict).where(
            RelationVerdict.decision.in_(["related_event", "same_event"])
        ).limit(limit)
    ).scalars().all()
    if not verdicts:
        return {"pairs": 0, "merged_claims": 0, "pairs_merged": 0}

    atomic_ids = {v.left_atomic_id for v in verdicts} | {v.right_atomic_id for v in verdicts}
    claims_by_atomic = _load_claims_for_atomics(session, atomic_ids)

    merged_total = 0
    pairs_with_claims = 0
    for verdict in verdicts:
        left_claims = claims_by_atomic.get(verdict.left_atomic_id, [])
        right_claims = claims_by_atomic.get(verdict.right_atomic_id, [])
        if not left_claims or not right_claims:
            continue
        merged = merge_related_pair(left_claims, right_claims)
        merged_total += len(merged)
        pairs_with_claims += 1

    return {
        "pairs": len(verdicts),
        "pairs_with_claims": pairs_with_claims,
        "merged_claims": merged_total,
    }
