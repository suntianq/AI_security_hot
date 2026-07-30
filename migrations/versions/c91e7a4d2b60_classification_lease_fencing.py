"""classification lease fencing token

Revision ID: c91e7a4d2b60
Revises: a8d6e4c2b190
Create Date: 2026-07-30
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "c91e7a4d2b60"
down_revision: str | None = "a8d6e4c2b190"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "documents",
        sa.Column("classify_lease_token", sa.String(64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("documents", "classify_lease_token")
