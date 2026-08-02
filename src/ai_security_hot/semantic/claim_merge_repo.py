"""Repository layer for M2.4 claim merging (shadow → formal Claim, controlled).

Reads related atomic-event pairs from relation_verdicts, loads their extracted
claims, merges them, and persists the merged claims onto the formal Event that
owns those atomic events' documents. The promotion path (B2) decides WHEN a
merged claim becomes a formal Event's claim.
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
from ai_security_hot.semantic.claim_merge import MergedClaim, SourceClaim, merge_related_pair

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


def persist_merged_claims(
    session: Session,
    event_id: int,
    merged_claims: list[MergedClaim],
) -> int:
    """Persist merged claims onto a formal Event via the existing upsert path."""
    from ai_security_hot.storage.event_repository import upsert_manual_claim

    written = 0
    for mc in merged_claims:
        upsert_manual_claim(
            session,
            event_id,
            claim_key=mc.claim_key,
            claim_type=mc.claim_type,
            text=mc.text,
            status="unverified",
            evidence=[
                {
                    "document_id": doc_id,
                    "stance": mc.stance,
                    "evidence_level": None,
                    "excerpt": mc.text[:500],
                }
                for doc_id in mc.sources
            ],
            confidence=mc.confidence,
            normalized_value=mc.normalized_value,
        )
        written += 1
    return written
