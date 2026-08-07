"""daily content archives

Revision ID: 1e8573435eb2
Revises: 7a91d2e4f6b8
Create Date: 2026-08-07 10:36:36.322994
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = '1e8573435eb2'
down_revision: str | None = '7a91d2e4f6b8'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "daily_archives",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("natural_date", sa.Date(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_daily_archives_natural_date", "daily_archives", ["natural_date"], unique=True
    )


def downgrade() -> None:
    op.drop_index("ix_daily_archives_natural_date", table_name="daily_archives")
    op.drop_table("daily_archives")
