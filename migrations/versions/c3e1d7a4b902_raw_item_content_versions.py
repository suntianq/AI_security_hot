"""raw item content versions

Revision ID: c3e1d7a4b902
Revises: a9baeb84971f
Create Date: 2026-07-29
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "c3e1d7a4b902"
down_revision: str | None = "a9baeb84971f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint("uq_raw_endpoint_native", "raw_items", type_="unique")
    op.drop_constraint("uq_raw_endpoint_url_pub", "raw_items", type_="unique")
    op.create_unique_constraint(
        "uq_raw_endpoint_native_content",
        "raw_items",
        ["endpoint_id", "native_id", "content_hash"],
    )
    op.create_unique_constraint(
        "uq_raw_endpoint_url_pub_content",
        "raw_items",
        ["endpoint_id", "canonical_url", "published_at", "content_hash"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_raw_endpoint_url_pub_content", "raw_items", type_="unique")
    op.drop_constraint("uq_raw_endpoint_native_content", "raw_items", type_="unique")
    op.create_unique_constraint(
        "uq_raw_endpoint_native",
        "raw_items",
        ["endpoint_id", "native_id"],
    )
    op.create_unique_constraint(
        "uq_raw_endpoint_url_pub",
        "raw_items",
        ["endpoint_id", "canonical_url", "published_at"],
    )
