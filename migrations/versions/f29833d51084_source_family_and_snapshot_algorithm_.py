"""source_family and snapshot algorithm_version

Revision ID: f29833d51084
Revises: 1e8573435eb2
Create Date: 2026-08-08 16:53:50.511662
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = 'f29833d51084'
down_revision: str | None = '1e8573435eb2'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("sources", sa.Column("source_family", sa.String(128), nullable=True))
    op.add_column("sources", sa.Column("origin_source", sa.String(128), nullable=True))
    # Backfill: each existing source defaults to being its own family, so
    # legacy rows behave as before until a family is declared in sources.yaml.
    op.execute("UPDATE sources SET source_family = id WHERE source_family IS NULL")
    op.add_column(
        "daily_hotspot_snapshots",
        sa.Column("algorithm_version", sa.String(32), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("daily_hotspot_snapshots", "algorithm_version")
    op.drop_column("sources", "origin_source")
    op.drop_column("sources", "source_family")
