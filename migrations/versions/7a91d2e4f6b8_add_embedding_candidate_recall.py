"""add embedding candidate recall

Revision ID: 7a91d2e4f6b8
Revises: 6f23c8a1d4b7
Create Date: 2026-08-03
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "7a91d2e4f6b8"
down_revision: str | None = "6f23c8a1d4b7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "atomic_event_embeddings",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("work_item_id", sa.BigInteger(), nullable=True),
        sa.Column("atomic_event_id", sa.BigInteger(), nullable=False),
        sa.Column("task_version", sa.String(length=64), nullable=False),
        sa.Column("execution_version", sa.String(length=32), nullable=False),
        sa.Column("input_hash", sa.String(length=64), nullable=False),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("model", sa.String(length=200), nullable=False),
        sa.Column("dimensions", sa.Integer(), nullable=False),
        sa.Column("vector", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("norm", sa.Float(), nullable=False),
        sa.Column(
            "usage",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["atomic_event_id"], ["atomic_events.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["work_item_id"], ["semantic_work_items.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "atomic_event_id",
            "execution_version",
            name="uq_atomic_event_embedding_execution",
        ),
        sa.UniqueConstraint("work_item_id"),
    )
    op.create_index(
        "ix_atomic_event_embeddings_atomic_event_id",
        "atomic_event_embeddings",
        ["atomic_event_id"],
    )
    op.create_index(
        "ix_atomic_event_embeddings_execution_version",
        "atomic_event_embeddings",
        ["execution_version"],
    )
    op.create_index(
        "ix_atomic_event_embeddings_input_hash",
        "atomic_event_embeddings",
        ["input_hash"],
    )
    op.create_index(
        "ix_atomic_event_embedding_execution_id",
        "atomic_event_embeddings",
        ["execution_version", "id"],
    )

    op.create_table(
        "embedding_recall_states",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("recall_version", sa.String(length=32), nullable=False),
        sa.Column("embedding_execution_version", sa.String(length=32), nullable=False),
        sa.Column("last_embedding_id", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "recall_version",
            "embedding_execution_version",
            name="uq_embedding_recall_state_version",
        ),
    )

    op.alter_column(
        "relation_candidates",
        "shared_entity",
        existing_type=sa.String(length=64),
        nullable=True,
    )
    op.add_column("relation_candidates", sa.Column("embedding_score", sa.Float(), nullable=True))
    op.add_column(
        "relation_candidates",
        sa.Column("embedding_version", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "relation_candidates",
        sa.Column("hard_conflict", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("relation_candidates", "hard_conflict")
    op.drop_column("relation_candidates", "embedding_version")
    op.drop_column("relation_candidates", "embedding_score")
    op.execute(
        "UPDATE relation_candidates SET shared_entity = 'legacy:unknown' "
        "WHERE shared_entity IS NULL"
    )
    op.alter_column(
        "relation_candidates",
        "shared_entity",
        existing_type=sa.String(length=64),
        nullable=False,
    )

    op.drop_table("embedding_recall_states")
    op.drop_index("ix_atomic_event_embedding_execution_id", table_name="atomic_event_embeddings")
    op.drop_index("ix_atomic_event_embeddings_input_hash", table_name="atomic_event_embeddings")
    op.drop_index(
        "ix_atomic_event_embeddings_execution_version", table_name="atomic_event_embeddings"
    )
    op.drop_index(
        "ix_atomic_event_embeddings_atomic_event_id", table_name="atomic_event_embeddings"
    )
    op.drop_table("atomic_event_embeddings")
