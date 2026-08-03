"""Claim merging for related atomic events (M2.4, shadow).

Groups ExtractedClaims from atomic events judged same/related by M2.3 into
unified claims keyed by (claim_type, normalized_value). Each source document
becomes evidence with a stance. Pure merging logic is DB-free; the repository
layer reads/writes the formal Claim tables via the existing upsert path.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from hashlib import sha256


@dataclass(frozen=True)
class SourceClaim:
    atomic_event_id: int
    document_id: int
    claim_type: str
    text: str
    normalized_value: dict
    confidence: float
    evidence_excerpt: str
    evidence_field: str


@dataclass
class MergedClaim:
    claim_type: str
    normalized_value: dict
    text: str  # representative text (highest-confidence source)
    sources: list[int] = field(default_factory=list)  # document ids
    confidences: list[float] = field(default_factory=list)
    stance: str = "support"
    confidence: float = 0.0
    status: str = "supported"
    conflicts_with: list[str] = field(default_factory=list)

    @property
    def claim_key(self) -> str:
        """Deterministic key: sha256 of (type, normalized_value)."""
        payload = json.dumps(
            {"claim_type": self.claim_type, "normalized_value": self.normalized_value},
            sort_keys=True,
            ensure_ascii=False,
        )
        return f"merged:{sha256(payload.encode()).hexdigest()[:32]}"

    @property
    def document_count(self) -> int:
        return len(self.sources)


def merge_claims(claims: list[SourceClaim]) -> list[MergedClaim]:
    """Group source claims by (claim_type, normalized_value) into merged claims."""
    groups: dict[tuple[str, str], list[SourceClaim]] = {}
    for claim in claims:
        key = (claim.claim_type, json.dumps(claim.normalized_value, sort_keys=True))
        groups.setdefault(key, []).append(claim)

    merged: list[MergedClaim] = []
    for _key, group in groups.items():
        group.sort(key=lambda c: c.confidence, reverse=True)
        best = group[0]
        document_ids = sorted({c.document_id for c in group})
        confidences = [c.confidence for c in group]
        avg_conf = sum(confidences) / len(confidences)
        # Confidence measures certainty, not polarity. Same propositions always support.
        stance = "support"
        merged.append(
            MergedClaim(
                claim_type=best.claim_type,
                normalized_value=best.normalized_value,
                text=best.text,
                sources=document_ids,
                confidences=confidences,
                stance=stance,
                confidence=round(avg_conf, 3),
            )
        )
    # Contradiction requires proposition-level incompatible values, never a
    # confidence spread. Restrict automatic conflicts to explicit booleans and
    # known positive/negative scalar pairs to avoid inventing exclusivity.
    opposites = {
        ("exploited", "not_exploited"),
        ("affected", "unaffected"),
        ("patched", "unpatched"),
        ("confirmed", "denied"),
        ("active", "inactive"),
    }
    for index, left in enumerate(merged):
        for right in merged[index + 1 :]:
            if (
                left.claim_type != right.claim_type
                or left.normalized_value == right.normalized_value
            ):
                continue
            conflict = False
            for key in set(left.normalized_value) & set(right.normalized_value):
                lv, rv = left.normalized_value[key], right.normalized_value[key]
                if isinstance(lv, bool) and isinstance(rv, bool) and lv != rv:
                    conflict = True
                pair = (str(lv).casefold(), str(rv).casefold())
                if pair in opposites or pair[::-1] in opposites:
                    conflict = True
            if conflict:
                left.status = right.status = "disputed"
                left.conflicts_with.append(right.claim_key)
                right.conflicts_with.append(left.claim_key)
    return merged


def merge_related_pair(
    left_claims: list[SourceClaim], right_claims: list[SourceClaim]
) -> list[MergedClaim]:
    """Merge claims from two atomic events in a related pair."""
    return merge_claims(left_claims + right_claims)
