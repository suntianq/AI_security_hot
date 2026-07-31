"""persist current-document counts for M2 blocking-token buckets

Revision ID: 9c4e7a2b1d60
Revises: f8a1c2d3e4b5
Create Date: 2026-07-31
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "9c4e7a2b1d60"
down_revision: str | None = "f8a1c2d3e4b5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "document_block_token_stats",
        sa.Column("token", sa.String(96), nullable=False),
        sa.Column("active_document_count", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.CheckConstraint("active_document_count > 0", name="ck_block_token_positive_count"),
        sa.PrimaryKeyConstraint("token"),
    )
    op.execute(
        sa.text(
            """
            INSERT INTO document_block_token_stats
                (token, active_document_count, updated_at)
            SELECT tokens.token, COUNT(*), now()
            FROM document_block_tokens AS tokens
            JOIN documents ON documents.id = tokens.document_id
            WHERE documents.source_status = 'active'
              AND documents.record_status NOT IN ('rejected', 'withdrawn')
            GROUP BY tokens.token
            """
        )
    )


def downgrade() -> None:
    op.drop_table("document_block_token_stats")
