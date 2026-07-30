"""document visibility, upstream status and endpoint retirement

Revision ID: d7c4b8e1a950
Revises: c91e7a4d2b60
Create Date: 2026-07-30
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "d7c4b8e1a950"
down_revision: str | None = "c91e7a4d2b60"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "source_endpoints",
        sa.Column("replacement_endpoint_id", sa.String(128), nullable=True),
    )
    op.add_column(
        "source_endpoints",
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_source_endpoint_replacement",
        "source_endpoints",
        "source_endpoints",
        ["replacement_endpoint_id"],
        ["id"],
        ondelete="SET NULL",
    )

    op.add_column(
        "documents",
        sa.Column("source_status_reason", sa.String(256), nullable=True),
    )
    op.add_column(
        "documents",
        sa.Column(
            "record_status",
            sa.String(16),
            server_default="published",
            nullable=False,
        ),
    )
    op.add_column(
        "documents",
        sa.Column("record_status_raw", sa.String(64), nullable=True),
    )
    op.create_index("ix_documents_record_status", "documents", ["record_status"])

    # Preserve the exact NVD status while normalizing only non-current states.
    op.execute(
        sa.text(
            """
            UPDATE documents AS d
            SET record_status_raw = r.raw_text::jsonb ->> 'vulnStatus',
                record_status = CASE
                    WHEN LOWER(COALESCE(r.raw_text::jsonb ->> 'vulnStatus', '')) = 'rejected'
                        THEN 'rejected'
                    WHEN LOWER(COALESCE(r.raw_text::jsonb ->> 'vulnStatus', '')) = 'withdrawn'
                        THEN 'withdrawn'
                    WHEN COALESCE(r.raw_text::jsonb ->> 'vulnStatus', '') = ''
                        THEN 'unknown'
                    ELSE 'published'
                END
            FROM raw_items AS r
            WHERE d.raw_item_id = r.id
              AND d.endpoint_id = 'nvd-recent'
            """
        )
    )

    # The old RSS is retained as evidence but the dedicated API is now the
    # authoritative AI HOT endpoint. No RawItem or Document is deleted.
    op.execute(
        sa.text(
            """
            UPDATE source_endpoints
            SET enabled = FALSE,
                status = 'retired',
                replacement_endpoint_id = 'aihot-selected-api',
                retired_at = NOW(),
                lease_until = NULL,
                lease_token = NULL
            WHERE id = 'aihot-selected-rss'
            """
        )
    )
    op.execute(
        sa.text(
            """
            UPDATE source_records
            SET status = 'retired', withdrawn_at = NOW()
            WHERE endpoint_id = 'aihot-selected-rss' AND status = 'active'
            """
        )
    )
    op.execute(
        sa.text(
            """
            UPDATE documents
            SET source_status = 'retired',
                source_status_reason = 'endpoint_replaced:aihot-selected-api',
                withdrawn_at = NOW(),
                classify_lease_until = NULL,
                classify_lease_token = NULL,
                near_dup_of = NULL,
                duplicate_kind = NULL,
                duplicate_score = NULL,
                dedupe_version = 'dedupe-v1',
                cluster_version = NULL
            WHERE endpoint_id = 'aihot-selected-rss'
              AND source_status = 'active'
            """
        )
    )

    # Rejected/withdrawn records and a retired endpoint leave the current M2
    # corpus. Rebuild active components once so duplicate masters/events cannot
    # continue referencing them.
    op.execute(
        sa.text(
            """
            UPDATE documents
            SET classify_lease_until = NULL,
                classify_lease_token = NULL,
                near_dup_of = NULL,
                duplicate_kind = NULL,
                duplicate_score = NULL,
                dedupe_version = 'dedupe-v1',
                cluster_version = NULL
            WHERE record_status IN ('rejected', 'withdrawn')
            """
        )
    )
    op.execute(
        sa.text(
            "UPDATE documents SET dedupe_version = NULL, cluster_version = NULL "
            "WHERE source_status = 'active' "
            "AND record_status NOT IN ('rejected', 'withdrawn')"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            """
            UPDATE documents
            SET source_status = 'active',
                source_status_reason = NULL,
                withdrawn_at = NULL,
                dedupe_version = NULL,
                cluster_version = NULL
            WHERE source_status = 'retired'
              AND source_status_reason = 'endpoint_replaced:aihot-selected-api'
            """
        )
    )
    op.execute(
        sa.text(
            "UPDATE source_records SET status = 'active', withdrawn_at = NULL "
            "WHERE endpoint_id = 'aihot-selected-rss' AND status = 'retired'"
        )
    )
    op.execute(
        sa.text(
            """
            UPDATE source_endpoints
            SET status = 'paused', replacement_endpoint_id = NULL, retired_at = NULL
            WHERE id = 'aihot-selected-rss'
            """
        )
    )
    op.drop_index("ix_documents_record_status", table_name="documents")
    op.drop_column("documents", "record_status_raw")
    op.drop_column("documents", "record_status")
    op.drop_column("documents", "source_status_reason")
    op.drop_constraint("fk_source_endpoint_replacement", "source_endpoints", type_="foreignkey")
    op.drop_column("source_endpoints", "retired_at")
    op.drop_column("source_endpoints", "replacement_endpoint_id")
