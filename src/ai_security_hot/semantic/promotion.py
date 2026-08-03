"""Controlled shadow→formal event promotion (M2.4, B2).

Synthesizes an EventDraft from a related atomic-event pair's merged claims and
applies a promotion gate. It is SHADOW (dry-run) only: it previews the event
without writing to the formal ``events`` table. The formal apply path is not
implemented yet — promotion is disabled by default and requires an explicit
design + gate before any shadow result can touch production events.
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


def apply_promotion(
    session, preview: PromotionPreview, merged_claims, *, algorithm_version: str = "promotion-v1"
):
    """Atomically materialize a gated preview; identical retries are no-ops."""
    import json
    from hashlib import sha256

    from sqlalchemy import delete, select

    from ai_security_hot.models.semantic_tables import SemanticPromotion
    from ai_security_hot.models.tables import (
        Claim,
        ClaimEvidence,
        Event,
        EventDocument,
        EventVersion,
    )

    if not preview.gated:
        raise ValueError(preview.reason)
    draft = {
        **preview.as_dict(),
        "summary": preview.summary,
        "evidence_level": preview.evidence_level,
        "first_seen_at": preview.first_seen_at.isoformat(),
        "last_seen_at": preview.last_seen_at.isoformat(),
    }
    claims_payload = [
        {
            "claim_key": c.claim_key,
            "claim_type": c.claim_type,
            "normalized_value": c.normalized_value,
            "text": c.text,
            "sources": c.sources,
            "confidence": c.confidence,
            "status": c.status,
            "conflicts_with": c.conflicts_with,
        }
        for c in merged_claims
    ]
    draft_hash = sha256(
        json.dumps(
            {"draft": draft, "claims": claims_payload}, sort_keys=True, ensure_ascii=False
        ).encode()
    ).hexdigest()
    component_key = sha256(preview.fingerprint.encode()).hexdigest()
    promotion = session.execute(
        select(SemanticPromotion)
        .where(
            SemanticPromotion.component_key == component_key,
            SemanticPromotion.algorithm_version == algorithm_version,
        )
        .with_for_update()
    ).scalar_one_or_none()
    if promotion and promotion.status == "applied" and promotion.draft_hash == draft_hash:
        return promotion, False
    if promotion is None:
        promotion = SemanticPromotion(
            component_key=component_key,
            algorithm_version=algorithm_version,
            draft_hash=draft_hash,
            status="prepared",
            atomic_ids=[],
            document_ids=preview.document_ids,
            draft=draft,
            claims=claims_payload,
        )
        session.add(promotion)
        session.flush()
    elif promotion.status == "applied":
        raise RuntimeError(
            "promotion component already applied with different content; rollback first"
        )
    event = session.execute(
        select(Event).where(Event.fingerprint == preview.fingerprint).with_for_update()
    ).scalar_one_or_none()
    if event is None:
        event = Event(
            fingerprint=preview.fingerprint,
            current_version=0,
            cluster_version=algorithm_version,
            title=preview.title,
        )
        session.add(event)
        session.flush()
    event.event_type = preview.event_type
    event.topic = preview.topic
    event.category = preview.category
    event.title = preview.title
    event.summary = preview.summary
    event.status = "detected"
    event.score = preview.score
    event.evidence_level = preview.evidence_level
    event.first_seen_at = preview.first_seen_at
    event.last_seen_at = preview.last_seen_at
    event.cluster_version = algorithm_version
    event.current_version += 1
    event.updated_at = datetime.now(UTC)
    session.execute(delete(EventDocument).where(EventDocument.event_id == event.id))
    for doc_id in preview.document_ids:
        session.add(
            EventDocument(
                event_id=event.id,
                document_id=doc_id,
                stance="support",
                evidence_level=preview.evidence_level,
                relation_reason="semantic_promotion",
            )
        )
    old_claims = list(
        session.execute(
            select(Claim).where(Claim.event_id == event.id, Claim.claim_key.like("merged:%"))
        ).scalars()
    )
    for claim in old_claims:
        session.delete(claim)
    session.flush()
    for item in merged_claims:
        claim = Claim(
            event_id=event.id,
            claim_key=item.claim_key,
            claim_type=item.claim_type,
            text=item.text,
            normalized_value=item.normalized_value,
            status=item.status,
            confidence=item.confidence,
        )
        session.add(claim)
        session.flush()
        for doc_id in item.sources:
            session.add(
                ClaimEvidence(
                    claim_id=claim.id,
                    document_id=doc_id,
                    stance="support",
                    evidence_level=preview.evidence_level,
                )
            )
    snapshot = {
        "fingerprint": event.fingerprint,
        "status": event.status,
        "title": event.title,
        "document_ids": preview.document_ids,
        "claim_keys": [c.claim_key for c in merged_claims],
    }
    session.add(
        EventVersion(
            event_id=event.id,
            version=event.current_version,
            change_type="semantic_promotion",
            algorithm_version=algorithm_version,
            snapshot=snapshot,
            diff={"promotion_id": promotion.id},
        )
    )
    promotion.draft_hash = draft_hash
    promotion.document_ids = preview.document_ids
    promotion.draft = draft
    promotion.claims = claims_payload
    promotion.status = "applied"
    promotion.event_id = event.id
    promotion.event_version = event.current_version
    promotion.applied_at = datetime.now(UTC)
    promotion.rolled_back_at = None
    promotion.updated_at = datetime.now(UTC)
    session.flush()
    return promotion, True


def rollback_promotion(session, promotion_id: int):
    """Rollback only the exact event version written by this promotion."""
    from sqlalchemy import select

    from ai_security_hot.models.semantic_tables import SemanticPromotion
    from ai_security_hot.models.tables import Event, EventVersion

    promotion = session.execute(
        select(SemanticPromotion).where(SemanticPromotion.id == promotion_id).with_for_update()
    ).scalar_one()
    if promotion.status == "rolled_back":
        return promotion, False
    if promotion.status != "applied" or promotion.event_id is None:
        raise RuntimeError("promotion is not applied")
    event = session.execute(
        select(Event).where(Event.id == promotion.event_id).with_for_update()
    ).scalar_one()
    if event.current_version != promotion.event_version:
        raise RuntimeError("event changed after promotion; refusing unsafe rollback")
    event.status = "superseded"
    event.current_version += 1
    event.updated_at = datetime.now(UTC)
    session.add(
        EventVersion(
            event_id=event.id,
            version=event.current_version,
            change_type="semantic_rollback",
            algorithm_version=promotion.algorithm_version,
            snapshot={"fingerprint": event.fingerprint, "status": event.status},
            diff={"promotion_id": promotion.id},
        )
    )
    promotion.status = "rolled_back"
    promotion.rolled_back_at = datetime.now(UTC)
    promotion.updated_at = datetime.now(UTC)
    session.flush()
    return promotion, True
