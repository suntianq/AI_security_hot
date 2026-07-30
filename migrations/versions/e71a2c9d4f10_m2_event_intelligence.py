"""m2 event intelligence

Revision ID: e71a2c9d4f10
Revises: c3e1d7a4b902
Create Date: 2026-07-30
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "e71a2c9d4f10"
down_revision: str | None = "c3e1d7a4b902"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_foreign_key(
        "fk_documents_near_dup_of_documents",
        "documents",
        "documents",
        ["near_dup_of"],
        ["id"],
        ondelete="SET NULL",
    )
    op.add_column("documents", sa.Column("duplicate_kind", sa.String(24), nullable=True))
    op.add_column("documents", sa.Column("duplicate_score", sa.Float(), nullable=True))
    op.add_column("documents", sa.Column("dedupe_version", sa.String(32), nullable=True))
    op.add_column("documents", sa.Column("deduped_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("documents", sa.Column("cluster_version", sa.String(32), nullable=True))
    op.add_column("documents", sa.Column("clustered_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_documents_near_dup_of", "documents", ["near_dup_of"])
    op.create_index("ix_documents_dedupe_version", "documents", ["dedupe_version"])
    op.create_index("ix_documents_cluster_version", "documents", ["cluster_version"])

    op.add_column("events", sa.Column("fingerprint", sa.String(160), nullable=True))
    op.execute(sa.text("UPDATE events SET fingerprint = 'legacy:' || id::text"))
    op.alter_column("events", "fingerprint", nullable=False)
    op.add_column("events", sa.Column("evidence_level", sa.String(1), nullable=True))
    op.add_column("events", sa.Column("cluster_version", sa.String(32), nullable=True))
    op.add_column("events", sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("events", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "events",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_events_fingerprint", "events", ["fingerprint"], unique=True)
    op.create_index("ix_events_score", "events", ["score"])
    op.create_index("ix_events_cluster_version", "events", ["cluster_version"])
    op.create_index("ix_events_last_seen_at", "events", ["last_seen_at"])

    op.add_column(
        "event_documents", sa.Column("relation_reason", sa.String(32), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("event_documents", "relation_reason")

    op.drop_index("ix_events_last_seen_at", table_name="events")
    op.drop_index("ix_events_cluster_version", table_name="events")
    op.drop_index("ix_events_score", table_name="events")
    op.drop_index("ix_events_fingerprint", table_name="events")
    op.drop_column("events", "updated_at")
    op.drop_column("events", "last_seen_at")
    op.drop_column("events", "first_seen_at")
    op.drop_column("events", "cluster_version")
    op.drop_column("events", "evidence_level")
    op.drop_column("events", "fingerprint")

    op.drop_index("ix_documents_cluster_version", table_name="documents")
    op.drop_index("ix_documents_dedupe_version", table_name="documents")
    op.drop_index("ix_documents_near_dup_of", table_name="documents")
    op.drop_column("documents", "clustered_at")
    op.drop_column("documents", "cluster_version")
    op.drop_column("documents", "deduped_at")
    op.drop_column("documents", "dedupe_version")
    op.drop_column("documents", "duplicate_score")
    op.drop_column("documents", "duplicate_kind")
    op.drop_constraint(
        "fk_documents_near_dup_of_documents", "documents", type_="foreignkey"
    )
