"""M2.2 shadow semantic enrichment foundation

Revision ID: 2b6d8f4a1c90
Revises: 9c4e7a2b1d60
Create Date: 2026-07-31
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "2b6d8f4a1c90"
down_revision: str | None = "9c4e7a2b1d60"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "model_runs",
        sa.Column("subject_type", sa.String(32), server_default="document", nullable=False),
    )
    op.add_column("model_runs", sa.Column("subject_id", sa.BigInteger()))
    op.execute(sa.text("UPDATE model_runs SET subject_id = document_id"))
    op.alter_column("model_runs", "subject_id", existing_type=sa.BigInteger(), nullable=False)
    op.create_index(
        "ix_model_runs_subject_task_created",
        "model_runs",
        ["subject_type", "subject_id", "task", "created_at"],
    )

    op.create_table(
        "semantic_work_items",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("subject_type", sa.String(32), nullable=False),
        sa.Column("subject_id", sa.BigInteger(), nullable=False),
        sa.Column("task", sa.String(32), nullable=False),
        sa.Column("task_version", sa.String(64), nullable=False),
        sa.Column("execution_version", sa.String(32), nullable=False),
        sa.Column("mode", sa.String(16), server_default="shadow", nullable=False),
        sa.Column("status", sa.String(16), server_default="pending", nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("lease_until", sa.DateTime(timezone=True)),
        sa.Column("lease_token", sa.String(64)),
        sa.Column("next_retry_at", sa.DateTime(timezone=True)),
        sa.Column("error", sa.Text()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "subject_type",
            "subject_id",
            "task",
            "execution_version",
            name="uq_semantic_work_execution",
        ),
    )
    op.create_index("ix_semantic_work_items_subject_type", "semantic_work_items", ["subject_type"])
    op.create_index("ix_semantic_work_items_subject_id", "semantic_work_items", ["subject_id"])
    op.create_index("ix_semantic_work_items_task", "semantic_work_items", ["task"])
    op.create_index(
        "ix_semantic_work_items_execution_version",
        "semantic_work_items",
        ["execution_version"],
    )
    op.create_index("ix_semantic_work_items_status", "semantic_work_items", ["status"])
    op.create_index("ix_semantic_work_items_lease_until", "semantic_work_items", ["lease_until"])
    op.create_index(
        "ix_semantic_work_items_next_retry_at", "semantic_work_items", ["next_retry_at"]
    )

    op.create_table(
        "document_enrichments",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("work_item_id", sa.BigInteger()),
        sa.Column("document_id", sa.BigInteger(), nullable=False),
        sa.Column("enrichment_version", sa.String(64), nullable=False),
        sa.Column("execution_version", sa.String(32), nullable=False),
        sa.Column("mode", sa.String(16), server_default="shadow", nullable=False),
        sa.Column("input_hash", sa.String(64), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("prompt_version", sa.String(64), nullable=False),
        sa.Column("relevant", sa.Boolean(), nullable=False),
        sa.Column("relevance_confidence", sa.Float(), nullable=False),
        sa.Column("content_type", sa.String(32), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("output", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["document_id"], ["documents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["work_item_id"], ["semantic_work_items.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("work_item_id", name="uq_document_enrichment_work"),
        sa.UniqueConstraint(
            "document_id",
            "execution_version",
            "input_hash",
            name="uq_document_enrichment_execution_input",
        ),
    )
    op.create_index("ix_document_enrichments_document_id", "document_enrichments", ["document_id"])
    op.create_index(
        "ix_document_enrichments_enrichment_version",
        "document_enrichments",
        ["enrichment_version"],
    )
    op.create_index(
        "ix_document_enrichments_execution_version",
        "document_enrichments",
        ["execution_version"],
    )
    op.create_index("ix_document_enrichments_input_hash", "document_enrichments", ["input_hash"])
    op.create_index("ix_document_enrichments_relevant", "document_enrichments", ["relevant"])
    op.create_index(
        "ix_document_enrichments_content_type", "document_enrichments", ["content_type"]
    )

    op.create_table(
        "semantic_entities",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("canonical_key", sa.String(64), nullable=False),
        sa.Column("entity_type", sa.String(32), nullable=False),
        sa.Column("canonical_name", sa.String(300), nullable=False),
        sa.Column("version", sa.String(128)),
        sa.Column("aliases", postgresql.JSONB(), server_default="[]", nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_semantic_entities_canonical_key",
        "semantic_entities",
        ["canonical_key"],
        unique=True,
    )
    op.create_index("ix_semantic_entities_entity_type", "semantic_entities", ["entity_type"])
    op.create_index("ix_semantic_entities_canonical_name", "semantic_entities", ["canonical_name"])

    op.create_table(
        "atomic_events",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("enrichment_id", sa.BigInteger(), nullable=False),
        sa.Column("document_id", sa.BigInteger(), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("object", sa.Text()),
        sa.Column("time_text", sa.String(300)),
        sa.Column("location", sa.String(300)),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence", postgresql.JSONB(), server_default="[]", nullable=False),
        sa.Column("mode", sa.String(16), server_default="shadow", nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["document_id"], ["documents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["enrichment_id"], ["document_enrichments.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("enrichment_id", "ordinal", name="uq_atomic_event_ordinal"),
    )
    op.create_index("ix_atomic_events_enrichment_id", "atomic_events", ["enrichment_id"])
    op.create_index("ix_atomic_events_document_id", "atomic_events", ["document_id"])
    op.create_index("ix_atomic_events_fingerprint", "atomic_events", ["fingerprint"])
    op.create_index("ix_atomic_events_event_type", "atomic_events", ["event_type"])

    op.create_table(
        "entity_mentions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("entity_id", sa.BigInteger(), nullable=False),
        sa.Column("document_id", sa.BigInteger(), nullable=False),
        sa.Column("enrichment_id", sa.BigInteger(), nullable=False),
        sa.Column("atomic_event_id", sa.BigInteger()),
        sa.Column("mention_text", sa.String(300), nullable=False),
        sa.Column("role", sa.String(64)),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence_excerpt", sa.Text(), nullable=False),
        sa.Column("evidence_field", sa.String(16), server_default="unknown", nullable=False),
        sa.Column("evidence_start", sa.Integer()),
        sa.Column("evidence_end", sa.Integer()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["atomic_event_id"], ["atomic_events.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["document_id"], ["documents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["enrichment_id"], ["document_enrichments.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["entity_id"], ["semantic_entities.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_entity_mentions_entity_id", "entity_mentions", ["entity_id"])
    op.create_index("ix_entity_mentions_document_id", "entity_mentions", ["document_id"])
    op.create_index("ix_entity_mentions_enrichment_id", "entity_mentions", ["enrichment_id"])
    op.create_index("ix_entity_mentions_atomic_event_id", "entity_mentions", ["atomic_event_id"])

    op.create_table(
        "extracted_claims",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("atomic_event_id", sa.BigInteger(), nullable=False),
        sa.Column("claim_type", sa.String(32), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("normalized_value", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence_excerpt", sa.Text(), nullable=False),
        sa.Column("evidence_field", sa.String(16), server_default="unknown", nullable=False),
        sa.Column("evidence_start", sa.Integer()),
        sa.Column("evidence_end", sa.Integer()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["atomic_event_id"], ["atomic_events.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_extracted_claims_atomic_event_id", "extracted_claims", ["atomic_event_id"])
    op.create_index("ix_extracted_claims_claim_type", "extracted_claims", ["claim_type"])


def downgrade() -> None:
    op.drop_index("ix_extracted_claims_claim_type", table_name="extracted_claims")
    op.drop_index("ix_extracted_claims_atomic_event_id", table_name="extracted_claims")
    op.drop_table("extracted_claims")
    op.drop_index("ix_entity_mentions_atomic_event_id", table_name="entity_mentions")
    op.drop_index("ix_entity_mentions_enrichment_id", table_name="entity_mentions")
    op.drop_index("ix_entity_mentions_document_id", table_name="entity_mentions")
    op.drop_index("ix_entity_mentions_entity_id", table_name="entity_mentions")
    op.drop_table("entity_mentions")
    op.drop_index("ix_atomic_events_event_type", table_name="atomic_events")
    op.drop_index("ix_atomic_events_fingerprint", table_name="atomic_events")
    op.drop_index("ix_atomic_events_document_id", table_name="atomic_events")
    op.drop_index("ix_atomic_events_enrichment_id", table_name="atomic_events")
    op.drop_table("atomic_events")
    op.drop_index("ix_semantic_entities_canonical_name", table_name="semantic_entities")
    op.drop_index("ix_semantic_entities_entity_type", table_name="semantic_entities")
    op.drop_index("ix_semantic_entities_canonical_key", table_name="semantic_entities")
    op.drop_table("semantic_entities")
    op.drop_index("ix_document_enrichments_content_type", table_name="document_enrichments")
    op.drop_index("ix_document_enrichments_relevant", table_name="document_enrichments")
    op.drop_index("ix_document_enrichments_input_hash", table_name="document_enrichments")
    op.drop_index("ix_document_enrichments_execution_version", table_name="document_enrichments")
    op.drop_index("ix_document_enrichments_enrichment_version", table_name="document_enrichments")
    op.drop_index("ix_document_enrichments_document_id", table_name="document_enrichments")
    op.drop_table("document_enrichments")
    op.drop_index("ix_semantic_work_items_next_retry_at", table_name="semantic_work_items")
    op.drop_index("ix_semantic_work_items_lease_until", table_name="semantic_work_items")
    op.drop_index("ix_semantic_work_items_status", table_name="semantic_work_items")
    op.drop_index("ix_semantic_work_items_execution_version", table_name="semantic_work_items")
    op.drop_index("ix_semantic_work_items_task", table_name="semantic_work_items")
    op.drop_index("ix_semantic_work_items_subject_id", table_name="semantic_work_items")
    op.drop_index("ix_semantic_work_items_subject_type", table_name="semantic_work_items")
    op.drop_table("semantic_work_items")
    op.drop_index("ix_model_runs_subject_task_created", table_name="model_runs")
    op.drop_column("model_runs", "subject_id")
    op.drop_column("model_runs", "subject_type")
