"""SQLAlchemy ORM tables — MVP §8 minimal data model + plan-confirmed forward fields.

Forward fields brought into the M0 initial schema (user-confirmed, to avoid a
later migration):
  - source_endpoints.egress_route   (plan 修正 3)
  - raw_items.stage / stage_lease_until  (plan 修正 1)
  - raw_items.blob_ref              (plan 修正 5)
  - documents.parse_quality         (plan 修正 4)
"""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ai_security_hot.domain.enums import PipelineStage
from ai_security_hot.models.base import Base


class Source(Base):
    __tablename__ = "sources"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(256))
    trust_tier: Mapped[str] = mapped_column(String(1))
    language: Mapped[str | None] = mapped_column(String(16), nullable=True)
    org: Mapped[str | None] = mapped_column(String(256), nullable=True)

    endpoints: Mapped[list[SourceEndpoint]] = relationship(back_populates="source")


class SourceEndpoint(Base):
    __tablename__ = "source_endpoints"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.id"))
    connector: Mapped[str] = mapped_column(String(32))
    parser: Mapped[str | None] = mapped_column(String(64), nullable=True)
    url: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(default=True)
    state_version: Mapped[str] = mapped_column(String(32), default="1")
    replacement_endpoint_id: Mapped[str | None] = mapped_column(
        ForeignKey("source_endpoints.id", ondelete="SET NULL"), nullable=True
    )
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    priority: Mapped[str] = mapped_column(String(4), default="P1")
    trust_tier: Mapped[str] = mapped_column(String(1), default="B")
    language: Mapped[str | None] = mapped_column(String(16), nullable=True)
    egress_route: Mapped[str] = mapped_column(String(32), default="direct")  # plan 修正 3
    policy: Mapped[dict] = mapped_column(JSONB, default=dict)  # schedule/fetch/topics/...

    # checkpoint + health (MVP 6.1)
    etag: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_modified: Mapped[str | None] = mapped_column(Text, nullable=True)
    cursor: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="active")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # scheduling — DB is the single source of truth (plan 修正 5)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_token: Mapped[str | None] = mapped_column(String(64), nullable=True)

    source: Mapped[Source] = relationship(back_populates="endpoints")


class FetchRun(Base):
    __tablename__ = "fetch_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("source_endpoints.id"))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), default="running")
    items_fetched: Mapped[int] = mapped_column(Integer, default=0)
    items_new: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class RawItem(Base):
    __tablename__ = "raw_items"
    __table_args__ = (
        # One immutable row per source-side content version. Revisions keep
        # the same native id but carry a new content hash.
        UniqueConstraint(
            "endpoint_id",
            "native_id",
            "content_hash",
            name="uq_raw_endpoint_native_content",
        ),
        UniqueConstraint(
            "endpoint_id",
            "canonical_url",
            "published_at",
            "content_hash",
            name="uq_raw_endpoint_url_pub_content",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("source_endpoints.id"))
    source_id: Mapped[str] = mapped_column(String(128))
    native_id: Mapped[str] = mapped_column(String(512))
    request_url: Mapped[str] = mapped_column(Text)
    final_url: Mapped[str] = mapped_column(Text)
    http_status: Mapped[int] = mapped_column(Integer)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    language: Mapped[str | None] = mapped_column(String(16), nullable=True)
    content_hash: Mapped[str] = mapped_column(String(64))
    blob_ref: Mapped[str | None] = mapped_column(Text, nullable=True)  # plan 修正 5
    raw_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    canonical_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    connector_version: Mapped[str] = mapped_column(String(32), default="")
    parser_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    operation: Mapped[str] = mapped_column(String(16), default="upsert")

    # stage state machine (plan 修正 1)
    stage: Mapped[str] = mapped_column(String(16), default=PipelineStage.FETCHED.value, index=True)
    stage_lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stage_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class SourceRecord(Base):
    """Current membership of a mutable source record; RawItem remains history."""

    __tablename__ = "source_records"
    __table_args__ = (UniqueConstraint("endpoint_id", "native_id", name="uq_source_record_native"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("source_endpoints.id"), index=True)
    native_id: Mapped[str] = mapped_column(String(512))
    current_raw_item_id: Mapped[int] = mapped_column(ForeignKey("raw_items.id"))
    content_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="active", index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    raw_item_id: Mapped[int] = mapped_column(ForeignKey("raw_items.id"), unique=True)
    endpoint_id: Mapped[str] = mapped_column(String(128))
    title_original: Mapped[str] = mapped_column(Text)
    title_zh: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    canonical_url: Mapped[str] = mapped_column(Text)
    author: Mapped[str | None] = mapped_column(String(256), nullable=True)
    org: Mapped[str | None] = mapped_column(String(256), nullable=True)
    published_at_utc: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    language: Mapped[str | None] = mapped_column(String(16), nullable=True)
    identifiers: Mapped[dict] = mapped_column(JSONB, default=dict)  # cve/ghsa/cnvd/cwe
    entities: Mapped[dict] = mapped_column(JSONB, default=dict)
    parse_quality: Mapped[float] = mapped_column(Float, default=0.0)  # plan 修正 4
    source_status: Mapped[str] = mapped_column(String(16), default="active", index=True)
    source_status_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    record_status: Mapped[str] = mapped_column(
        String(16), default="published", server_default="published", index=True
    )
    record_status_raw: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # --- M1.1 classification (multi-label) + provenance ---
    tech_directions: Mapped[list] = mapped_column(
        JSONB, default=list, server_default="[]"
    )  # cve or a subset of the five news/research topic labels
    company_models: Mapped[list] = mapped_column(
        JSONB, default=list, server_default="[]"
    )  # subset of 15
    classified_event_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    classify_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    classify_method: Mapped[str | None] = mapped_column(String(16), nullable=True)  # rule/llm
    classify_model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    classify_prompt_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    classify_rule_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    classify_input_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    classified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    classify_lease_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True
    )
    classify_lease_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    classify_next_retry_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True
    )
    classify_attempts: Mapped[int] = mapped_column(Integer, default=0)
    classify_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # --- M2 event intelligence: versioned, non-destructive dedup ---
    near_dup_of: Mapped[int | None] = mapped_column(
        ForeignKey("documents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    duplicate_kind: Mapped[str | None] = mapped_column(String(24), nullable=True)
    duplicate_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    dedupe_version: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    deduped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cluster_version: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    clustered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dedupe_component_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "duplicate_components.id",
            name="fk_documents_dedupe_component",
            ondelete="SET NULL",
            use_alter=True,
        ),
        nullable=True,
        index=True,
    )


class DuplicateComponent(Base):
    """Stable identity for a duplicate component even when its master changes."""

    __tablename__ = "duplicate_components"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    master_document_id: Mapped[int | None] = mapped_column(
        ForeignKey("documents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    algorithm_version: Mapped[str] = mapped_column(String(32), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DocumentSignature(Base):
    __tablename__ = "document_signatures"

    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True
    )
    signature_version: Mapped[str] = mapped_column(String(32), index=True)
    url_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    title_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    simhash: Mapped[str | None] = mapped_column(String(16), nullable=True)
    minhash: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true", index=True)
    indexed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DocumentIdentity(Base):
    __tablename__ = "document_identities"
    __table_args__ = (
        UniqueConstraint("document_id", "kind", "fingerprint", name="uq_document_identity"),
        Index(
            "ix_document_identities_lookup",
            "kind",
            "fingerprint",
            "document_id",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(256))
    event_key: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DocumentBlockToken(Base):
    __tablename__ = "document_block_tokens"
    __table_args__ = (Index("ix_document_block_tokens_token", "token", "document_id"),)

    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True
    )
    token: Mapped[str] = mapped_column(String(96), primary_key=True)


class DocumentBlockTokenStat(Base):
    __tablename__ = "document_block_token_stats"
    __table_args__ = (
        CheckConstraint("active_document_count > 0", name="ck_block_token_positive_count"),
    )

    token: Mapped[str] = mapped_column(String(96), primary_key=True)
    active_document_count: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class M2Run(Base):
    __tablename__ = "m2_runs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    stage: Mapped[str] = mapped_column(String(16), index=True)
    mode: Mapped[str] = mapped_column(String(16))
    algorithm_version: Mapped[str] = mapped_column(String(32))
    trigger: Mapped[str] = mapped_column(String(32), default="scheduler")
    status: Mapped[str] = mapped_column(String(16), default="running", index=True)
    input_count: Mapped[int] = mapped_column(Integer, default=0)
    candidate_count: Mapped[int] = mapped_column(Integer, default=0)
    affected_count: Mapped[int] = mapped_column(Integer, default=0)
    stats: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class M2WorkItem(Base):
    __tablename__ = "m2_work_items"
    __table_args__ = (
        Index(
            "uq_m2_work_items_pending",
            "document_id",
            "stage",
            unique=True,
            postgresql_where=text("status = 'pending'"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    document_id: Mapped[int | None] = mapped_column(
        ForeignKey("documents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    component_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True, index=True)
    stage: Mapped[str] = mapped_column(String(16), index=True)
    reason: Mapped[str] = mapped_column(String(64))
    algorithm_version: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    run_id: Mapped[int | None] = mapped_column(
        ForeignKey("m2_runs.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CandidateReview(Base):
    __tablename__ = "candidate_reviews"
    __table_args__ = (
        CheckConstraint("left_document_id < right_document_id", name="ck_candidate_pair_order"),
        UniqueConstraint(
            "left_document_id",
            "right_document_id",
            "algorithm_version",
            name="uq_candidate_review_pair_version",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    left_document_id: Mapped[int] = mapped_column(ForeignKey("documents.id"), index=True)
    right_document_id: Mapped[int] = mapped_column(ForeignKey("documents.id"), index=True)
    candidate_kind: Mapped[str] = mapped_column(String(32))
    score: Mapped[float] = mapped_column(Float)
    features: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    conflict_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    algorithm_version: Mapped[str] = mapped_column(String(32), index=True)
    reviewer: Mapped[str | None] = mapped_column(String(128), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    fingerprint: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    event_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    topic: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # "vuln_db" for structured vulnerability feeds (NVD/KEV), "general" otherwise.
    category: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    title: Mapped[str] = mapped_column(Text)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="detected")
    score: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    evidence_level: Mapped[str | None] = mapped_column(String(1), nullable=True)
    cluster_version: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    current_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class EventDocument(Base):
    __tablename__ = "event_documents"
    __table_args__ = (UniqueConstraint("event_id", "document_id", name="uq_event_document"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"))
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id"))
    stance: Mapped[str] = mapped_column(String(16), default="support")
    evidence_level: Mapped[str | None] = mapped_column(String(1), nullable=True)
    relation_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)


class EventVersion(Base):
    """Immutable event snapshot emitted for every material state change."""

    __tablename__ = "event_versions"
    __table_args__ = (UniqueConstraint("event_id", "version", name="uq_event_version"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    change_type: Mapped[str] = mapped_column(String(32))
    algorithm_version: Mapped[str] = mapped_column(String(32))
    snapshot: Mapped[dict] = mapped_column(JSONB)
    diff: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Claim(Base):
    __tablename__ = "claims"
    __table_args__ = (UniqueConstraint("event_id", "claim_key", name="uq_event_claim"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="CASCADE"), index=True)
    claim_key: Mapped[str] = mapped_column(String(160))
    claim_type: Mapped[str] = mapped_column(String(32), index=True)
    text: Mapped[str] = mapped_column(Text)
    normalized_value: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    status: Mapped[str] = mapped_column(String(16), default="unverified", index=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ClaimEvidence(Base):
    __tablename__ = "claim_evidence"
    __table_args__ = (
        UniqueConstraint("claim_id", "document_id", "stance", name="uq_claim_document_stance"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    claim_id: Mapped[int] = mapped_column(ForeignKey("claims.id", ondelete="CASCADE"), index=True)
    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), index=True
    )
    stance: Mapped[str] = mapped_column(String(16), default="support")
    evidence_level: Mapped[str | None] = mapped_column(String(1), nullable=True)
    excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ModelCache(Base):
    """Reusable validated model output. Secrets and raw HTTP are never stored."""

    __tablename__ = "model_cache"
    __table_args__ = (
        UniqueConstraint(
            "task",
            "provider",
            "model",
            "prompt_version",
            "input_hash",
            name="uq_model_cache_key",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    task: Mapped[str] = mapped_column(String(32))
    provider: Mapped[str] = mapped_column(String(64))
    model: Mapped[str] = mapped_column(String(128))
    prompt_version: Mapped[str] = mapped_column(String(64))
    input_hash: Mapped[str] = mapped_column(String(64))
    output: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class ModelRun(Base):
    """Generic model-task audit row, including cache hits and fallbacks."""

    __tablename__ = "model_runs"
    __table_args__ = (
        Index(
            "ix_model_runs_subject_task_created",
            "subject_type",
            "subject_id",
            "task",
            "created_at",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id"), index=True)
    subject_type: Mapped[str] = mapped_column(
        String(32), default="document", server_default="document"
    )
    subject_id: Mapped[int] = mapped_column(BigInteger)
    task: Mapped[str] = mapped_column(String(32))
    provider: Mapped[str] = mapped_column(String(64))
    model: Mapped[str] = mapped_column(String(128))
    prompt_version: Mapped[str] = mapped_column(String(64))
    input_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24), index=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    usage: Mapped[dict] = mapped_column(JSONB, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DeliveryRun(Base):
    __tablename__ = "delivery_runs"
    __table_args__ = (
        UniqueConstraint("channel", "target", "payload_hash", name="uq_delivery_idempotency"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    channel: Mapped[str] = mapped_column(String(32))
    target: Mapped[str] = mapped_column(String(256))
    payload_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DailyHotspotSnapshot(Base):
    __tablename__ = "daily_hotspot_snapshots"
    __table_args__ = (
        UniqueConstraint(
            "natural_date", "timezone", "category", "revision", name="uq_daily_snapshot_revision"
        ),
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    natural_date: Mapped[date] = mapped_column(Date, index=True)
    timezone: Mapped[str] = mapped_column(String(64))
    category: Mapped[str] = mapped_column(String(16), default="all")
    revision: Mapped[int] = mapped_column(Integer)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    content_hash: Mapped[str] = mapped_column(String(64))
    item_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DailyHotspotItem(Base):
    __tablename__ = "daily_hotspot_items"
    __table_args__ = (UniqueConstraint("snapshot_id", "rank", name="uq_daily_snapshot_rank"),)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(
        ForeignKey("daily_hotspot_snapshots.id", ondelete="CASCADE"), index=True
    )
    rank: Mapped[int] = mapped_column(Integer)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id", ondelete="RESTRICT"), index=True)
    event_version: Mapped[int] = mapped_column(Integer)
    score: Mapped[int] = mapped_column(Integer)
    payload: Mapped[dict] = mapped_column(JSONB)


class DailyArchive(Base):
    """Frozen daily content archive (hotspots + module timelines) for history."""

    __tablename__ = "daily_archives"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    natural_date: Mapped[date] = mapped_column(Date, unique=True, index=True)
    content_hash: Mapped[str] = mapped_column(String(64))
    # Full build_overview payload frozen at generation time.
    payload: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
