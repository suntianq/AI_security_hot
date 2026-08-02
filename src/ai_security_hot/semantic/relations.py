"""Deterministic relation adjudication between atomic events (M2.3).

Pure, DB-free logic mirroring ``events/intelligence.py``: it works on the
values passed in, so the same rule set can be replayed and tested offline.
Decisions are shadow-only — they never mutate materialized Events.

Decision ladder:
  - identical fingerprint (event_type+subject+action+object+time)  -> same_event
  - shared strong entity + close time window                        -> related_event
  - otherwise                                                       -> different_event
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

# Time window (days) within which two docs sharing an entity are "related".
RELATED_WINDOW_DAYS = 30


@dataclass(frozen=True)
class RelationVerdict:
    left_atomic_id: int
    right_atomic_id: int
    decision: str  # same_event | related_event | different_event
    confidence: float
    reason: str
    shared_entity: str | None = None


@dataclass(frozen=True)
class AtomicEventRef:
    """Minimal atomic-event identity for adjudication."""

    id: int
    document_id: int
    fingerprint: str
    subject: str
    action: str
    object: str | None
    time_text: str | None
    published_at: datetime | None


def adjudicate(
    left: AtomicEventRef,
    right: AtomicEventRef,
    *,
    shared_entities: set[str] | None = None,
    window_days: int = RELATED_WINDOW_DAYS,
) -> RelationVerdict:
    """Adjudicate whether two atomic events refer to the same/related/different
    real-world event. Deterministic and replayable."""
    # Same fingerprint → same atomic event (subject+action+object+time equal).
    if left.fingerprint == right.fingerprint:
        return RelationVerdict(
            left_atomic_id=left.id,
            right_atomic_id=right.id,
            decision="same_event",
            confidence=0.95,
            reason="identical_atomic_fingerprint",
        )

    # Both derive from the same document → not a cross-document relation.
    if left.document_id == right.document_id:
        return RelationVerdict(
            left_atomic_id=left.id,
            right_atomic_id=right.id,
            decision="different_event",
            confidence=0.9,
            reason="same_document",
        )

    # Shared strong entity + close time → related.
    shared = shared_entities or set()
    if shared:
        time_close = _times_close(left.published_at, right.published_at, window_days)
        if time_close:
            return RelationVerdict(
                left_atomic_id=left.id,
                right_atomic_id=right.id,
                decision="related_event",
                confidence=0.7,
                reason="shared_entity_and_time",
                shared_entity=sorted(shared)[0],
            )

    return RelationVerdict(
        left_atomic_id=left.id,
        right_atomic_id=right.id,
        decision="different_event",
        confidence=0.6,
        reason="no_supporting_signal",
    )


def _times_close(
    left: datetime | None,
    right: datetime | None,
    window_days: int,
) -> bool:
    if left is None or right is None:
        return False  # unknown time → don't assert relatedness on time alone
    return abs((left - right).total_seconds()) <= timedelta(days=window_days).total_seconds()
