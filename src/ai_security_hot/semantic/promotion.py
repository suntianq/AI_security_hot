"""Controlled shadow→formal event promotion (M2.4).

Builds stable connected components from versioned ``same_event`` verdicts.
Preview is the default; explicit apply materializes a complete versioned Event
graph transactionally, and rollback restores the exact pre-promotion state.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ai_security_hot.events.intelligence import EventDraft, EventMembership
from ai_security_hot.semantic.versions import PROMOTION_VERSION, RELATION_COMPONENT_VERSION

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
        first_seen_at: datetime,
        last_seen_at: datetime,
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


def load_same_event_components(session, *, limit: int = 1000):
    """Load complete current materialized components without scanning the edge graph."""
    from ai_security_hot.semantic.components import load_active_components

    return load_active_components(session, limit=limit)


def _event_state(session, event) -> dict | None:
    """Serialize the complete mutable event graph used for rollback and EventVersion."""
    from sqlalchemy import select

    from ai_security_hot.models.tables import Claim, ClaimEvidence, EventDocument

    if event is None:
        return None
    documents = [
        {
            "document_id": int(row.document_id),
            "stance": row.stance,
            "evidence_level": row.evidence_level,
            "relation_reason": row.relation_reason,
        }
        for row in session.execute(
            select(EventDocument).where(EventDocument.event_id == event.id)
        ).scalars()
    ]
    claims = []
    for claim in session.execute(select(Claim).where(Claim.event_id == event.id)).scalars():
        evidence = [
            {
                "document_id": int(row.document_id),
                "stance": row.stance,
                "evidence_level": row.evidence_level,
                "excerpt": row.excerpt,
            }
            for row in session.execute(
                select(ClaimEvidence).where(ClaimEvidence.claim_id == claim.id)
            ).scalars()
        ]
        claims.append(
            {
                "claim_key": claim.claim_key,
                "claim_type": claim.claim_type,
                "text": claim.text,
                "normalized_value": claim.normalized_value,
                "status": claim.status,
                "confidence": claim.confidence,
                "evidence": evidence,
            }
        )
    return {
        "fingerprint": event.fingerprint,
        "event_type": event.event_type,
        "topic": event.topic,
        "category": event.category,
        "title": event.title,
        "summary": event.summary,
        "status": event.status,
        "score": event.score,
        "evidence_level": event.evidence_level,
        "cluster_version": event.cluster_version,
        "first_seen_at": event.first_seen_at.isoformat() if event.first_seen_at else None,
        "last_seen_at": event.last_seen_at.isoformat() if event.last_seen_at else None,
        "documents": documents,
        "claims": claims,
    }


def _restore_event_state(session, event, state: dict) -> None:
    from sqlalchemy import delete, select

    from ai_security_hot.models.tables import Claim, ClaimEvidence, EventDocument

    for field in (
        "event_type",
        "topic",
        "category",
        "title",
        "summary",
        "status",
        "score",
        "evidence_level",
        "cluster_version",
    ):
        setattr(event, field, state.get(field))
    event.first_seen_at = (
        datetime.fromisoformat(state["first_seen_at"]) if state.get("first_seen_at") else None
    )
    event.last_seen_at = (
        datetime.fromisoformat(state["last_seen_at"]) if state.get("last_seen_at") else None
    )
    session.execute(delete(EventDocument).where(EventDocument.event_id == event.id))
    for row in state.get("documents", []):
        session.add(EventDocument(event_id=event.id, **row))
    claim_ids = list(session.execute(select(Claim.id).where(Claim.event_id == event.id)).scalars())
    if claim_ids:
        session.execute(delete(ClaimEvidence).where(ClaimEvidence.claim_id.in_(claim_ids)))
    session.execute(delete(Claim).where(Claim.event_id == event.id))
    session.flush()
    for row in state.get("claims", []):
        claim_data = dict(row)
        evidence = claim_data.pop("evidence", [])
        claim = Claim(event_id=event.id, **claim_data)
        session.add(claim)
        session.flush()
        for item in evidence:
            session.add(ClaimEvidence(claim_id=claim.id, **item))


def apply_promotion(
    session,
    preview: PromotionPreview,
    merged_claims,
    *,
    atomic_ids: list[int],
    relation_component_id: int,
    component_key: str,
    component_revision: int,
    algorithm_version: str = PROMOTION_VERSION,
):
    """Atomically materialize one stable same-event component with full rollback state."""
    import json
    from hashlib import sha256

    from sqlalchemy import delete, select, text

    from ai_security_hot.models.semantic_tables import (
        SemanticPromotion,
        SemanticRelationComponent,
        SemanticRelationMembership,
    )
    from ai_security_hot.models.tables import (
        Claim,
        ClaimEvidence,
        Event,
        EventDocument,
        EventVersion,
    )

    if not preview.gated:
        raise ValueError(preview.reason)
    relation_component = session.execute(
        select(SemanticRelationComponent)
        .where(
            SemanticRelationComponent.id == relation_component_id,
            SemanticRelationComponent.component_key == component_key,
            SemanticRelationComponent.algorithm_version == RELATION_COMPONENT_VERSION,
        )
        .with_for_update()
    ).scalar_one_or_none()
    if (
        relation_component is None
        or relation_component.status != "active"
        or int(relation_component.revision) != component_revision
    ):
        raise RuntimeError("relation component changed; regenerate the promotion preview")
    active_atomic_ids = sorted(
        int(value)
        for value in session.execute(
            select(SemanticRelationMembership.atomic_event_id).where(
                SemanticRelationMembership.component_id == relation_component_id,
                SemanticRelationMembership.active.is_(True),
            )
        ).scalars()
    )
    if active_atomic_ids != sorted(set(atomic_ids)):
        raise RuntimeError("relation component membership changed; regenerate the preview")
    draft = {
        **preview.as_dict(),
        "summary": preview.summary,
        "evidence_level": preview.evidence_level,
        "first_seen_at": preview.first_seen_at.isoformat(),
        "last_seen_at": preview.last_seen_at.isoformat(),
    }
    claims_payload = [
        {
            "claim_key": item.claim_key,
            "claim_type": item.claim_type,
            "normalized_value": item.normalized_value,
            "text": item.text,
            "sources": item.sources,
            "confidence": item.confidence,
            "status": item.status,
            "conflicts_with": item.conflicts_with,
        }
        for item in merged_claims
    ]
    draft_hash = sha256(
        json.dumps(
            {
                "draft": draft,
                "claims": claims_payload,
                "atomic_ids": atomic_ids,
                "component_revision": component_revision,
            },
            sort_keys=True,
            ensure_ascii=False,
        ).encode()
    ).hexdigest()
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"semantic-promotion:{component_key}:{algorithm_version}"},
    )
    promotion = session.execute(
        select(SemanticPromotion)
        .where(
            SemanticPromotion.component_key == component_key,
            SemanticPromotion.algorithm_version == algorithm_version,
            SemanticPromotion.component_revision == component_revision,
        )
        .with_for_update()
    ).scalar_one_or_none()
    if promotion and promotion.status == "applied" and promotion.draft_hash == draft_hash:
        return promotion, False
    if promotion and promotion.status == "applied":
        raise RuntimeError("promotion component changed; rollback the applied revision first")
    event = session.execute(
        select(Event).where(Event.fingerprint == preview.fingerprint).with_for_update()
    ).scalar_one_or_none()
    created_event = event is None
    before_state = _event_state(session, event)
    if event is None:
        event = Event(
            fingerprint=preview.fingerprint,
            current_version=0,
            cluster_version=algorithm_version,
            title=preview.title,
        )
        session.add(event)
        session.flush()
    if promotion is None:
        promotion = SemanticPromotion(
            component_key=component_key,
            algorithm_version=algorithm_version,
            relation_component_id=relation_component_id,
            component_revision=component_revision,
            draft_hash=draft_hash,
            status="prepared",
            atomic_ids=atomic_ids,
            document_ids=preview.document_ids,
            draft=draft,
            claims=claims_payload,
        )
        session.add(promotion)
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
    for document_id in preview.document_ids:
        session.add(
            EventDocument(
                event_id=event.id,
                document_id=document_id,
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
    claim_by_key = {item.claim_key: item for item in merged_claims}
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
        support_docs = set(item.sources)
        contradict_docs = {
            document_id
            for conflict_key in item.conflicts_with
            for document_id in claim_by_key.get(conflict_key, item).sources
        } - support_docs
        for document_id in sorted(support_docs):
            session.add(
                ClaimEvidence(
                    claim_id=claim.id,
                    document_id=document_id,
                    stance="support",
                    evidence_level=preview.evidence_level,
                )
            )
        for document_id in sorted(contradict_docs):
            session.add(
                ClaimEvidence(
                    claim_id=claim.id,
                    document_id=document_id,
                    stance="contradict",
                    evidence_level=preview.evidence_level,
                )
            )
    session.flush()
    after_state = _event_state(session, event)
    session.add(
        EventVersion(
            event_id=event.id,
            version=event.current_version,
            change_type="semantic_promotion",
            algorithm_version=algorithm_version,
            snapshot=after_state or {},
            diff={"promotion_id": promotion.id, "before": before_state},
        )
    )
    promotion.draft_hash = draft_hash
    promotion.atomic_ids = atomic_ids
    promotion.document_ids = preview.document_ids
    promotion.draft = draft
    promotion.claims = claims_payload
    promotion.before_state = before_state
    promotion.created_event = created_event
    promotion.status = "applied"
    promotion.event_id = event.id
    promotion.event_version = event.current_version
    promotion.applied_at = datetime.now(UTC)
    promotion.rolled_back_at = None
    promotion.updated_at = datetime.now(UTC)
    session.flush()
    return promotion, True


def rollback_promotion(session, promotion_id: int):
    """Restore the exact pre-promotion graph, or supersede a newly created event."""
    from sqlalchemy import select, text

    from ai_security_hot.models.semantic_tables import SemanticPromotion
    from ai_security_hot.models.tables import Event, EventVersion

    promotion = session.execute(
        select(SemanticPromotion).where(SemanticPromotion.id == promotion_id).with_for_update()
    ).scalar_one()
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"semantic-promotion:{promotion.component_key}:{promotion.algorithm_version}"},
    )
    if promotion.status == "rolled_back":
        return promotion, False
    if promotion.status != "applied" or promotion.event_id is None:
        raise RuntimeError("promotion is not applied")
    event = session.execute(
        select(Event).where(Event.id == promotion.event_id).with_for_update()
    ).scalar_one()
    if event.current_version != promotion.event_version:
        raise RuntimeError("event changed after promotion; refusing unsafe rollback")
    if promotion.created_event:
        event.status = "superseded"
    elif promotion.before_state is not None:
        _restore_event_state(session, event, dict(promotion.before_state))
    else:
        raise RuntimeError("promotion has no rollback state")
    event.current_version += 1
    event.updated_at = datetime.now(UTC)
    session.flush()
    after_state = _event_state(session, event)
    session.add(
        EventVersion(
            event_id=event.id,
            version=event.current_version,
            change_type="semantic_rollback",
            algorithm_version=promotion.algorithm_version,
            snapshot=after_state or {},
            diff={"promotion_id": promotion.id},
        )
    )
    promotion.status = "rolled_back"
    promotion.rolled_back_at = datetime.now(UTC)
    promotion.updated_at = datetime.now(UTC)
    session.flush()
    return promotion, True
