"""Controlled shadow→formal event promotion (M2.4, B2).

Synthesizes an EventDraft from a related atomic-event pair's merged claims and
applies a promotion gate. Defaults to SHADOW (dry-run) — it previews the event
without writing to the formal ``events`` table. Only an explicit ``apply=True``
call materializes it, and that path reuses the existing versioned
``_apply_event_draft_local`` so any promotion/retraction is auditable.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ai_security_hot.events.intelligence import EventDraft, EventMembership

# Promotion gate: a related pair promotes only when it has enough distinct
# source documents AND enough merged claims.
PROMOTE_MIN_DOCUMENTS = 2
PROMOTE_MIN_CLAIMS = 1


class PromotionPreview:
    """A candidate formal event ready for review, before materialization."""

    def __init__(
        self,
        *,
        fingerprint: str,
        title: str,
        summary: str,
        event_type: str,
        topic: str,
        category: str,
        score: int,
        evidence_level: str,
        first_seen_at: datetime | None,
        last_seen_at: datetime | None,
        document_ids: list[int],
        merged_claim_count: int,
        gated: bool,
        reason: str,
    ) -> None:
        self.fingerprint = fingerprint
        self.title = title
        self.summary = summary
        self.event_type = event_type
        self.topic = topic
        self.category = category
        self.score = score
        self.evidence_level = evidence_level
        self.first_seen_at = first_seen_at
        self.last_seen_at = last_seen_at
        self.document_ids = document_ids
        self.merged_claim_count = merged_claim_count
        self.gated = gated
        self.reason = reason

    def to_event_draft(self) -> EventDraft:
        memberships = tuple(
            EventMembership(
                document_id=doc_id,
                evidence_level=self.evidence_level,
                relation_reason="semantic_promotion",
            )
            for doc_id in self.document_ids
        )
        return EventDraft(
            fingerprint=self.fingerprint,
            event_type=self.event_type,
            topic=self.topic,
            category=self.category,
            title=self.title,
            summary=self.summary,
            status="detected",
            score=self.score,
            evidence_level=self.evidence_level,
            first_seen_at=self.first_seen_at,
            last_seen_at=self.last_seen_at,
            memberships=memberships,
        )

    def as_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "title": self.title,
            "event_type": self.event_type,
            "topic": self.topic,
            "category": self.category,
            "score": self.score,
            "document_ids": self.document_ids,
            "merged_claim_count": self.merged_claim_count,
            "gated": self.gated,
            "reason": self.reason,
        }


def build_promotion_preview(
    *,
    fingerprint: str,
    title: str,
    summary: str,
    event_type: str,
    topic: str,
    category: str,
    document_ids: list[int],
    merged_claim_count: int,
    first_seen_at: datetime | None = None,
    last_seen_at: datetime | None = None,
    min_documents: int = PROMOTE_MIN_DOCUMENTS,
    min_claims: int = PROMOTE_MIN_CLAIMS,
) -> PromotionPreview:
    """Build a promotion preview; gate decides whether it may materialize."""
    distinct_docs = len(set(document_ids))
    score = min(100, 40 + 15 * distinct_docs + 10 * min(merged_claim_count, 4))
    gated = distinct_docs >= min_documents and merged_claim_count >= min_claims
    reason = (
        "gate_met"
        if gated
        else f"gate_not_met: docs={distinct_docs}/{min_documents} "
        f"claims={merged_claim_count}/{min_claims}"
    )
    evidence_level = "B" if distinct_docs >= 2 else "C"
    return PromotionPreview(
        fingerprint=fingerprint,
        title=title,
        summary=summary,
        event_type=event_type,
        topic=topic,
        category=category,
        score=score,
        evidence_level=evidence_level,
        first_seen_at=first_seen_at or datetime.now(UTC),
        last_seen_at=last_seen_at or datetime.now(UTC),
        document_ids=sorted(set(document_ids)),
        merged_claim_count=merged_claim_count,
        gated=gated,
        reason=reason,
    )
