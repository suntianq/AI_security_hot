"""endpoint lease fencing token

Revision ID: a8d6e4c2b190
Revises: f4b2a1c9d730
Create Date: 2026-07-30
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "a8d6e4c2b190"
down_revision: str | None = "f4b2a1c9d730"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "source_endpoints",
        sa.Column("lease_token", sa.String(64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("source_endpoints", "lease_token")
