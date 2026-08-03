"""Repository layer for M2.4 same-event Claim merging.

Only current relation-algorithm ``same_event`` verdicts are eligible. This
module returns a shadow summary; formal writes remain behind the explicit,
transactional promotion command.
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from ai_security_hot.models.semantic_tables import (
    AtomicEvent,
    ExtractedClaim,
)
from ai_security_hot.semantic.claim_merge import SourceClaim, merge_claims

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
    """Merge each current same-event component once; return a shadow summary."""
    from ai_security_hot.semantic.promotion import load_same_event_components

    components = load_same_event_components(session, limit=limit)
    if not components:
        return {"components": 0, "components_with_claims": 0, "merged_claims": 0}

    atomic_ids = {value for component in components for value in component.atomic_ids}
    claims_by_atomic = _load_claims_for_atomics(session, atomic_ids)
    merged_total = 0
    components_with_claims = 0
    for component in components:
        source_claims = [
            claim
            for atomic_id in component.atomic_ids
            for claim in claims_by_atomic.get(atomic_id, [])
        ]
        if not source_claims:
            continue
        merged_total += len(merge_claims(source_claims))
        components_with_claims += 1

    return {
        "components": len(components),
        "components_with_claims": components_with_claims,
        "merged_claims": merged_total,
    }
