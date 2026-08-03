"""ORM tables for versioned semantic enrichment.

Kept in a separate module so the M2.1 deterministic event tables remain easy
to reason about. Importing this module registers the tables on ``Base.metadata``.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.schema import UniqueConstraint
from sqlalchemy.sql import func

from ai_security_hot.models.base import Base


class SemanticWorkItem(Base):
    """Durable, leased work for a versioned semantic task."""

    __tablename__ = "semantic_work_items"
    __table_args__ = (
        UniqueConstraint(
            "subject_type",
            "subject_id",
            "task",
            "execution_version",
            name="uq_semantic_work_execution",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    subject_type: Mapped[str] = mapped_column(String(32), index=True)
    subject_id: Mapped[int] = mapped_column(BigInteger, index=True)
    task: Mapped[str] = mapped_column(String(32), index=True)
    task_version: Mapped[str] = mapped_column(String(64))
    execution_version: Mapped[str] = mapped_column(String(32), index=True)
    mode: Mapped[str] = mapped_column(String(16), default="shadow", server_default="shadow")
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    lease_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    lease_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    next_retry_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # M2.2.1 stabilization: bounded retry + failure audit
    max_attempts: Mapped[int] = mapped_column(Integer, default=5, server_default="5")
    last_finish_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_usage: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    # reproducible experiment batch (M2.2.1 1d)
    batch_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DocumentEnrichment(Base):
    """Immutable validated semantic output for one Document and execution."""

    __tablename__ = "document_enrichments"
    __table_args__ = (
        UniqueConstraint("work_item_id", name="uq_document_enrichment_work"),
        UniqueConstraint(
            "document_id",
            "execution_version",
            "input_hash",
            name="uq_document_enrichment_execution_input",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    work_item_id: Mapped[int | None] = mapped_column(
        ForeignKey("semantic_work_items.id", ondelete="SET NULL"), nullable=True
    )
    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), index=True
    )
    enrichment_version: Mapped[str] = mapped_column(String(64), index=True)
    execution_version: Mapped[str] = mapped_column(String(32), index=True)
    mode: Mapped[str] = mapped_column(String(16), default="shadow", server_default="shadow")
    input_hash: Mapped[str] = mapped_column(String(64), index=True)
    provider: Mapped[str] = mapped_column(String(64))
    model: Mapped[str] = mapped_column(String(128))
    prompt_version: Mapped[str] = mapped_column(String(64))
    relevant: Mapped[bool] = mapped_column(Boolean, index=True)
    relevance_confidence: Mapped[float] = mapped_column(Float)
    content_type: Mapped[str] = mapped_column(String(32), index=True)
    summary: Mapped[str] = mapped_column(Text)
    output: Mapped[dict] = mapped_column(JSONB)
    # M2.2.1 stabilization: failure audit + reproducible batch
    raw_response: Mapped[str | None] = mapped_column(Text, nullable=True)  # redacted
    finish_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    usage: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    batch_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SemanticEntity(Base):
    """Canonical entity identity shared by extracted mentions."""

    __tablename__ = "semantic_entities"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    canonical_key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    entity_type: Mapped[str] = mapped_column(String(32), index=True)
    canonical_name: Mapped[str] = mapped_column(String(300), index=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    aliases: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AtomicEvent(Base):
    """One extracted occurrence; shadow rows do not alter materialized Event."""

    __tablename__ = "atomic_events"
    __table_args__ = (UniqueConstraint("enrichment_id", "ordinal", name="uq_atomic_event_ordinal"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    enrichment_id: Mapped[int] = mapped_column(
        ForeignKey("document_enrichments.id", ondelete="CASCADE"), index=True
    )
    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), index=True
    )
    ordinal: Mapped[int] = mapped_column(Integer)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    subject: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text)
    object: Mapped[str | None] = mapped_column(Text, nullable=True)
    time_text: Mapped[str | None] = mapped_column(String(300), nullable=True)
    location: Mapped[str | None] = mapped_column(String(300), nullable=True)
    summary: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float)
    evidence: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    mode: Mapped[str] = mapped_column(String(16), default="shadow", server_default="shadow")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class EntityMention(Base):
    __tablename__ = "entity_mentions"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    entity_id: Mapped[int] = mapped_column(
        ForeignKey("semantic_entities.id", ondelete="CASCADE"), index=True
    )
    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), index=True
    )
    enrichment_id: Mapped[int] = mapped_column(
        ForeignKey("document_enrichments.id", ondelete="CASCADE"), index=True
    )
    atomic_event_id: Mapped[int | None] = mapped_column(
        ForeignKey("atomic_events.id", ondelete="CASCADE"), nullable=True, index=True
    )
    mention_text: Mapped[str] = mapped_column(String(300))
    role: Mapped[str | None] = mapped_column(String(64), nullable=True)
    confidence: Mapped[float] = mapped_column(Float)
    evidence_excerpt: Mapped[str] = mapped_column(Text)
    evidence_field: Mapped[str] = mapped_column(String(16), default="unknown")
    evidence_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ExtractedClaim(Base):
    """A pre-cluster claim tied to an atomic event and exact source evidence."""

    __tablename__ = "extracted_claims"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    atomic_event_id: Mapped[int] = mapped_column(
        ForeignKey("atomic_events.id", ondelete="CASCADE"), index=True
    )
    claim_type: Mapped[str] = mapped_column(String(32), index=True)
    text: Mapped[str] = mapped_column(Text)
    normalized_value: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    confidence: Mapped[float] = mapped_column(Float)
    evidence_excerpt: Mapped[str] = mapped_column(Text)
    evidence_field: Mapped[str] = mapped_column(String(16), default="unknown")
    evidence_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RelationVerdict(Base):
    """Shadow cross-document relation verdict (M2.3); never mutates Events."""

    __tablename__ = "relation_verdicts"
    __table_args__ = (
        UniqueConstraint("left_atomic_id", "right_atomic_id", name="uq_relation_pair"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    left_atomic_id: Mapped[int] = mapped_column(
        ForeignKey("atomic_events.id", ondelete="CASCADE"), index=True
    )
    right_atomic_id: Mapped[int] = mapped_column(
        ForeignKey("atomic_events.id", ondelete="CASCADE"), index=True
    )
    decision: Mapped[str] = mapped_column(String(24), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    reason: Mapped[str] = mapped_column(String(64))
    shared_entity: Mapped[str | None] = mapped_column(String(64), nullable=True)
    algorithm_version: Mapped[str] = mapped_column(String(32), default="relation-v1")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SemanticModelAttempt(Base):
    __tablename__ = "semantic_model_attempts"
    __table_args__ = (
        UniqueConstraint(
            "work_item_id", "work_attempt", "call_ordinal", name="uq_semantic_model_attempt"
        ),
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    work_item_id: Mapped[int] = mapped_column(
        ForeignKey("semantic_work_items.id", ondelete="CASCADE"), index=True
    )
    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), index=True
    )
    work_attempt: Mapped[int] = mapped_column(Integer)
    call_ordinal: Mapped[int] = mapped_column(Integer)
    phase: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(24))
    raw_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    usage: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    finish_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    validation_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    provider_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RelationScanState(Base):
    __tablename__ = "relation_scan_states"
    algorithm_version: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_atomic_id: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RelationCandidate(Base):
    __tablename__ = "relation_candidates"
    __table_args__ = (
        CheckConstraint("left_atomic_id < right_atomic_id", name="ck_relation_candidate_order"),
        UniqueConstraint(
            "left_atomic_id",
            "right_atomic_id",
            "algorithm_version",
            name="uq_relation_candidate_version",
        ),
        Index("ix_relation_candidate_claim", "status", "next_retry_at", "lease_until"),
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    left_atomic_id: Mapped[int] = mapped_column(
        ForeignKey("atomic_events.id", ondelete="CASCADE"), index=True
    )
    right_atomic_id: Mapped[int] = mapped_column(
        ForeignKey("atomic_events.id", ondelete="CASCADE"), index=True
    )
    shared_entity: Mapped[str] = mapped_column(String(64))
    algorithm_version: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    max_attempts: Mapped[int] = mapped_column(Integer, default=5, server_default="5")
    lease_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SemanticPromotion(Base):
    __tablename__ = "semantic_promotions"
    __table_args__ = (
        UniqueConstraint(
            "component_key", "algorithm_version", name="uq_semantic_promotion_component"
        ),
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    component_key: Mapped[str] = mapped_column(String(64))
    algorithm_version: Mapped[str] = mapped_column(String(32))
    draft_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="prepared")
    event_id: Mapped[int | None] = mapped_column(
        ForeignKey("events.id", ondelete="SET NULL"), nullable=True, index=True
    )
    event_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    atomic_ids: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    document_ids: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    draft: Mapped[dict] = mapped_column(JSONB)
    claims: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
