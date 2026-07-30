"""SQLAlchemy ORM tables — MVP §8 minimal data model + plan-confirmed forward fields.

Forward fields brought into the M0 initial schema (user-confirmed, to avoid a
later migration):
  - source_endpoints.egress_route   (plan 修正 3)
  - raw_items.stage / stage_lease_until  (plan 修正 1)
  - raw_items.blob_ref              (plan 修正 5)
  - documents.parse_quality         (plan 修正 4)
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
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
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

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
            "endpoint_id", "canonical_url", "published_at", "content_hash",
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

    # stage state machine (plan 修正 1)
    stage: Mapped[str] = mapped_column(String(16), default=PipelineStage.FETCHED.value, index=True)
    stage_lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stage_error: Mapped[str | None] = mapped_column(Text, nullable=True)


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
    # --- M1.2 dedup (forward field, populated later) ---
    near_dup_of: Mapped[int | None] = mapped_column(BigInteger, nullable=True)


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    topic: Mapped[str | None] = mapped_column(String(32), nullable=True)
    title: Mapped[str] = mapped_column(Text)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="detected")
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    current_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class EventDocument(Base):
    __tablename__ = "event_documents"
    __table_args__ = (UniqueConstraint("event_id", "document_id", name="uq_event_document"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"))
    document_id: Mapped[int] = mapped_column(ForeignKey("documents.id"))
    stance: Mapped[str] = mapped_column(String(16), default="support")
    evidence_level: Mapped[str | None] = mapped_column(String(1), nullable=True)


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
