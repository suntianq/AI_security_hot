"""Strict value objects for document-level semantic enrichment.

These objects are model-provider independent.  Model output is untrusted until
it validates against these schemas; persistence keeps the original Document
immutable and stores only versioned derived records.
"""

from __future__ import annotations

import re
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Version of the semantic ontology (enum domains). Bumping this invalidates
# cached enrichments / execution versions so older outputs are not re-used.
ONTO_VERSION = "semantic-onto-v1"

ContentType = Literal[
    "news",
    "research",
    "release",
    "advisory",
    "incident",
    "opinion",
    "other",
]
EntityType = Literal[
    "company",
    "organization",
    "person",
    "product",
    "model",
    "model_version",
    "package",
    "repository",
    "vulnerability",
    "ai_component",
    "threat_actor",
    "campaign",
    "location",
    "benchmark",
    "other",
]
AtomicEventType = Literal[
    "release",
    "research",
    "vulnerability",
    "incident",
    "attack",
    "policy",
    "partnership",
    "funding",
    "acquisition",
    "benchmark",
    "other",
]
ClaimType = Literal[
    "actor",
    "action",
    "object",
    "time",
    "impact",
    "affected_product",
    "exploitation",
    "remediation",
    "status",
    "other",
]


class StrictSemanticModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class EvidenceQuote(StrictSemanticModel):
    """A short verbatim excerpt that must be traceable to title/body text."""

    text: str = Field(min_length=1, max_length=1200)


class ExtractedEntity(StrictSemanticModel):
    entity_type: EntityType
    name: str = Field(min_length=1, max_length=300)
    canonical_name: str | None = Field(max_length=300)
    version: str | None = Field(max_length=128)
    role: str | None = Field(max_length=64)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: EvidenceQuote


class ExtractedClaim(StrictSemanticModel):
    claim_type: ClaimType
    text: str = Field(min_length=1, max_length=1600)
    normalized_value: dict
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: EvidenceQuote


class AtomicEventExtraction(StrictSemanticModel):
    """One subject-action-object occurrence described by a document."""

    event_type: AtomicEventType
    subject: str = Field(min_length=1, max_length=500)
    action: str = Field(min_length=1, max_length=500)
    object: str | None = Field(max_length=500)
    time_text: str | None = Field(max_length=300)
    location: str | None = Field(max_length=300)
    summary: str = Field(min_length=1, max_length=1600)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[EvidenceQuote] = Field(min_length=1, max_length=6)
    entities: list[ExtractedEntity] = Field(max_length=40)
    claims: list[ExtractedClaim] = Field(max_length=30)


class DocumentSemanticOutput(StrictSemanticModel):
    """Validated result of the document semantic-enrichment task."""

    relevant: bool
    relevance_confidence: float = Field(ge=0.0, le=1.0)
    relevance_reason: str = Field(min_length=1, max_length=1000)
    content_type: ContentType
    summary: str = Field(min_length=1, max_length=1600)
    entities: list[ExtractedEntity] = Field(max_length=50)
    atomic_events: list[AtomicEventExtraction] = Field(max_length=12)
    ontology_version: str  # required — emitted by the model, folded into execution_version

    @model_validator(mode="after")
    def irrelevant_documents_have_no_events(self) -> DocumentSemanticOutput:
        if not self.relevant and self.atomic_events:
            raise ValueError("irrelevant documents must not emit atomic_events")
        return self


class EvidenceLocation(StrictSemanticModel):
    field: Literal["title", "body", "unknown"]
    start: int | None = Field(default=None, ge=0)
    end: int | None = Field(default=None, ge=0)


_SPACE_RE = re.compile(r"\s+")


def locate_evidence(title: str, body: str | None, quote: str) -> EvidenceLocation:
    """Locate an exact model quote without inventing a fuzzy evidence span.

    Whitespace-normalized matching is deliberately not converted back into
    offsets because doing so could point at the wrong characters.  A quote that
    is not exact remains auditable as ``unknown`` and can be rejected by a
    later quality gate.
    """

    needle = quote.strip()
    for field, value in (("title", title), ("body", body or "")):
        start = value.find(needle)
        if start >= 0:
            return EvidenceLocation(
                field=cast(Literal["title", "body"], field),
                start=start,
                end=start + len(needle),
            )
    return EvidenceLocation(field="unknown")


def canonical_entity_text(value: str) -> str:
    """Conservative normalization used before hashing an entity identity."""

    return _SPACE_RE.sub(" ", value).strip().casefold()
