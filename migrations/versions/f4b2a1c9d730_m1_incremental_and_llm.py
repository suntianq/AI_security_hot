"""M1 incremental source ledger and auditable LLM classification

Revision ID: f4b2a1c9d730
Revises: e71a2c9d4f10
Create Date: 2026-07-30
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "f4b2a1c9d730"
down_revision: str | None = "e71a2c9d4f10"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "source_endpoints",
        sa.Column("state_version", sa.String(32), server_default="1", nullable=False),
    )
    op.add_column(
        "raw_items",
        sa.Column("operation", sa.String(16), server_default="upsert", nullable=False),
    )
    op.add_column(
        "documents",
        sa.Column("source_status", sa.String(16), server_default="active", nullable=False),
    )
    op.add_column("documents", sa.Column("withdrawn_at", sa.DateTime(timezone=True)))
    op.add_column("documents", sa.Column("classify_lease_until", sa.DateTime(timezone=True)))
    op.add_column("documents", sa.Column("classify_next_retry_at", sa.DateTime(timezone=True)))
    op.add_column(
        "documents",
        sa.Column("classify_attempts", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column("documents", sa.Column("classify_error", sa.Text()))
    op.create_index("ix_documents_source_status", "documents", ["source_status"])
    op.create_index("ix_documents_classify_lease_until", "documents", ["classify_lease_until"])
    op.create_index("ix_documents_classify_next_retry_at", "documents", ["classify_next_retry_at"])
    op.create_index("ix_source_endpoints_next_run_at", "source_endpoints", ["next_run_at"])

    # Only the newest immutable revision is current after introducing lifecycle
    # state. Mark older versions superseded and force one M2 reconciliation.
    op.execute(
        sa.text("""
        WITH ranked AS (
            SELECT id,
                   ROW_NUMBER() OVER (
                       PARTITION BY endpoint_id, native_id ORDER BY id DESC
                   ) AS revision_rank,
                   FIRST_VALUE(fetched_at) OVER (
                       PARTITION BY endpoint_id, native_id ORDER BY id DESC
                   ) AS newest_fetched_at
            FROM raw_items
        )
        UPDATE documents AS d
        SET source_status = 'superseded',
            withdrawn_at = ranked.newest_fetched_at,
            near_dup_of = NULL,
            duplicate_kind = NULL,
            duplicate_score = NULL,
            dedupe_version = 'dedupe-v1',
            cluster_version = NULL
        FROM ranked
        WHERE d.raw_item_id = ranked.id
          AND ranked.revision_rank > 1
    """)
    )

    # Lifecycle filtering can change duplicate masters even when the active
    # row itself was not revised. Force one full active-set M2 replay.
    op.execute(
        sa.text(
            "UPDATE documents SET dedupe_version = NULL, cluster_version = NULL "
            "WHERE source_status = 'active'"
        )
    )

    op.create_table(
        "source_records",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("endpoint_id", sa.String(128), nullable=False),
        sa.Column("native_id", sa.String(512), nullable=False),
        sa.Column("current_raw_item_id", sa.BigInteger(), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), server_default="active", nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("withdrawn_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["endpoint_id"], ["source_endpoints.id"]),
        sa.ForeignKeyConstraint(["current_raw_item_id"], ["raw_items.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("endpoint_id", "native_id", name="uq_source_record_native"),
    )
    op.create_index("ix_source_records_endpoint_id", "source_records", ["endpoint_id"])
    op.create_index("ix_source_records_status", "source_records", ["status"])
    op.execute(
        sa.text("""
        INSERT INTO source_records
            (endpoint_id, native_id, current_raw_item_id, content_hash, status,
             first_seen_at, last_seen_at)
        SELECT latest.endpoint_id, latest.native_id, latest.id, latest.content_hash,
               'active', history.first_seen_at, history.last_seen_at
        FROM (
            SELECT DISTINCT ON (endpoint_id, native_id)
                   id, endpoint_id, native_id, content_hash
            FROM raw_items
            ORDER BY endpoint_id, native_id, id DESC
        ) AS latest
        JOIN (
            SELECT endpoint_id, native_id,
                   MIN(fetched_at) AS first_seen_at,
                   MAX(fetched_at) AS last_seen_at
            FROM raw_items
            GROUP BY endpoint_id, native_id
        ) AS history
          ON history.endpoint_id = latest.endpoint_id
         AND history.native_id = latest.native_id
    """)
    )

    op.create_table(
        "model_cache",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("task", sa.String(32), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("prompt_version", sa.String(64), nullable=False),
        sa.Column("input_hash", sa.String(64), nullable=False),
        sa.Column("output", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "last_used_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "task",
            "provider",
            "model",
            "prompt_version",
            "input_hash",
            name="uq_model_cache_key",
        ),
    )
    op.create_table(
        "model_runs",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("document_id", sa.BigInteger(), nullable=False),
        sa.Column("task", sa.String(32), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("prompt_version", sa.String(64), nullable=False),
        sa.Column("input_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("latency_ms", sa.Integer()),
        sa.Column("usage", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("error", sa.Text()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["document_id"], ["documents.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_model_runs_document_id", "model_runs", ["document_id"])
    op.create_index("ix_model_runs_status", "model_runs", ["status"])


def downgrade() -> None:
    op.drop_index("ix_model_runs_status", table_name="model_runs")
    op.drop_index("ix_model_runs_document_id", table_name="model_runs")
    op.drop_table("model_runs")
    op.drop_table("model_cache")
    op.drop_index("ix_source_records_status", table_name="source_records")
    op.drop_index("ix_source_records_endpoint_id", table_name="source_records")
    op.drop_table("source_records")
    op.drop_index("ix_source_endpoints_next_run_at", table_name="source_endpoints")
    op.drop_index("ix_documents_classify_next_retry_at", table_name="documents")
    op.drop_index("ix_documents_classify_lease_until", table_name="documents")
    op.drop_index("ix_documents_source_status", table_name="documents")
    op.drop_column("documents", "classify_error")
    op.drop_column("documents", "classify_attempts")
    op.drop_column("documents", "classify_next_retry_at")
    op.drop_column("documents", "classify_lease_until")
    op.drop_column("documents", "withdrawn_at")
    op.drop_column("documents", "source_status")
    op.drop_column("raw_items", "operation")
    op.drop_column("source_endpoints", "state_version")
