"""persist semantic relation components

Revision ID: 6f23c8a1d4b7
Revises: 0e349c4eaa2e
Create Date: 2026-08-03
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "6f23c8a1d4b7"
down_revision: str | None = "0e349c4eaa2e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "semantic_relation_components",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("component_key", sa.String(length=64), nullable=False),
        sa.Column("algorithm_version", sa.String(length=32), nullable=False),
        sa.Column("revision", sa.Integer(), server_default="1", nullable=False),
        sa.Column("status", sa.String(length=16), server_default="active", nullable=False),
        sa.Column("member_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_semantic_relation_components_component_key",
        "semantic_relation_components",
        ["component_key"],
        unique=True,
    )
    op.create_index(
        "ix_semantic_relation_components_algorithm_version",
        "semantic_relation_components",
        ["algorithm_version"],
    )
    op.create_index(
        "ix_semantic_relation_component_active",
        "semantic_relation_components",
        ["algorithm_version", "status", "updated_at"],
    )

    op.create_table(
        "semantic_relation_memberships",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("component_id", sa.BigInteger(), nullable=False),
        sa.Column("atomic_event_id", sa.BigInteger(), nullable=False),
        sa.Column("algorithm_version", sa.String(length=32), nullable=False),
        sa.Column("active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column(
            "added_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["component_id"],
            ["semantic_relation_components.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["atomic_event_id"],
            ["atomic_events.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_semantic_relation_memberships_component_id",
        "semantic_relation_memberships",
        ["component_id"],
    )
    op.create_index(
        "ix_semantic_relation_memberships_atomic_event_id",
        "semantic_relation_memberships",
        ["atomic_event_id"],
    )
    op.create_index(
        "ix_semantic_relation_memberships_algorithm_version",
        "semantic_relation_memberships",
        ["algorithm_version"],
    )
    op.create_index(
        "ix_semantic_relation_membership_component_active",
        "semantic_relation_memberships",
        ["component_id", "active"],
    )
    op.create_index(
        "uq_semantic_relation_membership_active",
        "semantic_relation_memberships",
        ["atomic_event_id", "algorithm_version"],
        unique=True,
        postgresql_where=sa.text("active"),
    )

    op.create_table(
        "semantic_component_work_items",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("seed_atomic_id", sa.BigInteger(), nullable=False),
        sa.Column("algorithm_version", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="pending", nullable=False),
        sa.Column("requested_generation", sa.Integer(), server_default="1", nullable=False),
        sa.Column("completed_generation", sa.Integer(), server_default="0", nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("max_attempts", sa.Integer(), server_default="5", nullable=False),
        sa.Column("reason", sa.String(length=64), nullable=False),
        sa.Column("lease_token", sa.String(length=64), nullable=True),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["seed_atomic_id"],
            ["atomic_events.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "seed_atomic_id",
            "algorithm_version",
            name="uq_semantic_component_work_seed",
        ),
    )
    op.create_index(
        "ix_semantic_component_work_items_seed_atomic_id",
        "semantic_component_work_items",
        ["seed_atomic_id"],
    )
    op.create_index(
        "ix_semantic_component_work_items_algorithm_version",
        "semantic_component_work_items",
        ["algorithm_version"],
    )
    op.create_index(
        "ix_semantic_component_work_claim",
        "semantic_component_work_items",
        ["status", "next_retry_at", "lease_until"],
    )

    op.drop_constraint(
        "uq_semantic_promotion_component",
        "semantic_promotions",
        type_="unique",
    )
    op.add_column(
        "semantic_promotions",
        sa.Column("relation_component_id", sa.BigInteger(), nullable=True),
    )
    op.add_column(
        "semantic_promotions",
        sa.Column("component_revision", sa.Integer(), server_default="1", nullable=False),
    )
    op.create_foreign_key(
        "fk_semantic_promotions_relation_component_id",
        "semantic_promotions",
        "semantic_relation_components",
        ["relation_component_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_semantic_promotions_relation_component_id",
        "semantic_promotions",
        ["relation_component_id"],
    )
    op.create_unique_constraint(
        "uq_semantic_promotion_component_revision",
        "semantic_promotions",
        ["component_key", "algorithm_version", "component_revision"],
    )

    op.get_bind().execute(
        sa.text(
            """
            INSERT INTO semantic_component_work_items
                (seed_atomic_id, algorithm_version, status, requested_generation,
                 completed_generation, attempts, max_attempts, reason)
            SELECT DISTINCT atomic_id, :component_version, :pending, 1, 0, 0, 5,
                   :backfill_reason
            FROM (
                SELECT left_atomic_id AS atomic_id
                FROM relation_verdicts
                WHERE decision = :same_event AND algorithm_version = :relation_version
                UNION
                SELECT right_atomic_id AS atomic_id
                FROM relation_verdicts
                WHERE decision = :same_event AND algorithm_version = :relation_version
            ) AS seeds
            ON CONFLICT (seed_atomic_id, algorithm_version) DO NOTHING
            """
        ),
        {
            "component_version": "relation-component-v1",
            "pending": "pending",
            "backfill_reason": "migration_backfill",
            "same_event": "same_event",
            "relation_version": "relation-v2",
        },
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_semantic_promotion_component_revision",
        "semantic_promotions",
        type_="unique",
    )
    op.drop_index(
        "ix_semantic_promotions_relation_component_id",
        table_name="semantic_promotions",
    )
    op.drop_constraint(
        "fk_semantic_promotions_relation_component_id",
        "semantic_promotions",
        type_="foreignkey",
    )
    op.drop_column("semantic_promotions", "component_revision")
    op.drop_column("semantic_promotions", "relation_component_id")
    op.create_unique_constraint(
        "uq_semantic_promotion_component",
        "semantic_promotions",
        ["component_key", "algorithm_version"],
    )

    op.drop_index(
        "ix_semantic_component_work_claim",
        table_name="semantic_component_work_items",
    )
    op.drop_index(
        "ix_semantic_component_work_items_algorithm_version",
        table_name="semantic_component_work_items",
    )
    op.drop_index(
        "ix_semantic_component_work_items_seed_atomic_id",
        table_name="semantic_component_work_items",
    )
    op.drop_table("semantic_component_work_items")

    op.drop_index(
        "uq_semantic_relation_membership_active",
        table_name="semantic_relation_memberships",
    )
    op.drop_index(
        "ix_semantic_relation_membership_component_active",
        table_name="semantic_relation_memberships",
    )
    op.drop_index(
        "ix_semantic_relation_memberships_algorithm_version",
        table_name="semantic_relation_memberships",
    )
    op.drop_index(
        "ix_semantic_relation_memberships_atomic_event_id",
        table_name="semantic_relation_memberships",
    )
    op.drop_index(
        "ix_semantic_relation_memberships_component_id",
        table_name="semantic_relation_memberships",
    )
    op.drop_table("semantic_relation_memberships")

    op.drop_index(
        "ix_semantic_relation_component_active",
        table_name="semantic_relation_components",
    )
    op.drop_index(
        "ix_semantic_relation_components_algorithm_version",
        table_name="semantic_relation_components",
    )
    op.drop_index(
        "ix_semantic_relation_components_component_key",
        table_name="semantic_relation_components",
    )
    op.drop_table("semantic_relation_components")
