"""m2.1 incremental event intelligence foundations

Revision ID: f8a1c2d3e4b5
Revises: d7c4b8e1a950
Create Date: 2026-07-31
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "f8a1c2d3e4b5"
down_revision: str | None = "d7c4b8e1a950"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "duplicate_components",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("master_document_id", sa.BigInteger(), nullable=True),
        sa.Column("algorithm_version", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["master_document_id"], ["documents.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_duplicate_components_master_document_id",
        "duplicate_components",
        ["master_document_id"],
    )
    op.create_index(
        "ix_duplicate_components_algorithm_version",
        "duplicate_components",
        ["algorithm_version"],
    )
    op.add_column("documents", sa.Column("dedupe_component_id", sa.BigInteger()))
    op.create_foreign_key(
        "fk_documents_dedupe_component",
        "documents",
        "duplicate_components",
        ["dedupe_component_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_documents_dedupe_component_id", "documents", ["dedupe_component_id"])

    # Preserve M2.0 component membership and give it a stable identity. New
    # incremental runs may change the master without changing this component ID.
    op.execute(
        sa.text(
            """
            INSERT INTO duplicate_components (id, master_document_id, algorithm_version)
            SELECT DISTINCT COALESCE(near_dup_of, id), COALESCE(near_dup_of, id),
                            COALESCE(dedupe_version, 'dedupe-v1')
            FROM documents
            WHERE dedupe_version IS NOT NULL
            ON CONFLICT (id) DO NOTHING
            """
        )
    )
    op.execute(
        sa.text(
            """
            UPDATE documents
            SET dedupe_component_id = COALESCE(near_dup_of, id)
            WHERE dedupe_version IS NOT NULL
            """
        )
    )
    op.execute(
        sa.text(
            """
            SELECT setval(
                pg_get_serial_sequence('duplicate_components', 'id'),
                GREATEST(COALESCE((SELECT MAX(id) FROM duplicate_components), 1), 1),
                EXISTS (SELECT 1 FROM duplicate_components)
            )
            """
        )
    )

    op.create_table(
        "document_signatures",
        sa.Column("document_id", sa.BigInteger(), nullable=False),
        sa.Column("signature_version", sa.String(32), nullable=False),
        sa.Column("url_hash", sa.String(64)),
        sa.Column("title_hash", sa.String(64)),
        sa.Column("content_hash", sa.String(64)),
        sa.Column("simhash", sa.String(16)),
        sa.Column(
            "minhash",
            postgresql.JSONB(),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("indexed_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["document_id"], ["documents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("document_id"),
    )
    for column in ("signature_version", "url_hash", "title_hash", "content_hash", "active"):
        op.create_index(f"ix_document_signatures_{column}", "document_signatures", [column])

    op.create_table(
        "document_identities",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("document_id", sa.BigInteger(), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(256), nullable=False),
        sa.Column("event_key", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["document_id"], ["documents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("document_id", "kind", "fingerprint", name="uq_document_identity"),
    )
    op.create_index("ix_document_identities_document_id", "document_identities", ["document_id"])
    op.create_index(
        "ix_document_identities_lookup",
        "document_identities",
        ["kind", "fingerprint", "document_id"],
    )

    op.create_table(
        "document_block_tokens",
        sa.Column("document_id", sa.BigInteger(), nullable=False),
        sa.Column("token", sa.String(96), nullable=False),
        sa.ForeignKeyConstraint(["document_id"], ["documents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("document_id", "token"),
    )
    op.create_index(
        "ix_document_block_tokens_token",
        "document_block_tokens",
        ["token", "document_id"],
    )

    op.create_table(
        "m2_runs",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("stage", sa.String(16), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("algorithm_version", sa.String(32), nullable=False),
        sa.Column("trigger", sa.String(32), server_default="scheduler", nullable=False),
        sa.Column("status", sa.String(16), server_default="running", nullable=False),
        sa.Column("input_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("candidate_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("affected_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "stats",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("error", sa.Text()),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_m2_runs_stage", "m2_runs", ["stage"])
    op.create_index("ix_m2_runs_status", "m2_runs", ["status"])

    op.create_table(
        "m2_work_items",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("document_id", sa.BigInteger()),
        sa.Column("component_id", sa.BigInteger()),
        sa.Column("stage", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(64), nullable=False),
        sa.Column("algorithm_version", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), server_default="pending", nullable=False),
        sa.Column("run_id", sa.BigInteger()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["document_id"], ["documents.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["run_id"], ["m2_runs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("document_id", "component_id", "stage", "status"):
        op.create_index(f"ix_m2_work_items_{column}", "m2_work_items", [column])
    op.create_index(
        "uq_m2_work_items_pending",
        "m2_work_items",
        ["document_id", "stage"],
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
    )

    op.create_table(
        "candidate_reviews",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("left_document_id", sa.BigInteger(), nullable=False),
        sa.Column("right_document_id", sa.BigInteger(), nullable=False),
        sa.Column("candidate_kind", sa.String(32), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column(
            "features",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("conflict_reason", sa.String(64)),
        sa.Column("status", sa.String(16), server_default="pending", nullable=False),
        sa.Column("algorithm_version", sa.String(32), nullable=False),
        sa.Column("reviewer", sa.String(128)),
        sa.Column("notes", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("left_document_id < right_document_id", name="ck_candidate_pair_order"),
        sa.ForeignKeyConstraint(["left_document_id"], ["documents.id"]),
        sa.ForeignKeyConstraint(["right_document_id"], ["documents.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "left_document_id",
            "right_document_id",
            "algorithm_version",
            name="uq_candidate_review_pair_version",
        ),
    )
    op.create_index("ix_candidate_reviews_status", "candidate_reviews", ["status"])
    op.create_index(
        "ix_candidate_reviews_algorithm_version", "candidate_reviews", ["algorithm_version"]
    )

    op.create_table(
        "event_versions",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("event_id", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("change_type", sa.String(32), nullable=False),
        sa.Column("algorithm_version", sa.String(32), nullable=False),
        sa.Column("snapshot", postgresql.JSONB(), nullable=False),
        sa.Column(
            "diff",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["event_id"], ["events.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id", "version", name="uq_event_version"),
    )
    op.create_index("ix_event_versions_event_id", "event_versions", ["event_id"])

    # M2.0 had only Event.current_version, so earlier transitions cannot be
    # reconstructed honestly. Preserve one explicit baseline for every legacy
    # event before v2 replay starts; future EventVersion rows then form a
    # continuous audit trail from this known state forward.
    op.execute(
        sa.text(
            """
            INSERT INTO event_versions
                (event_id, version, change_type, algorithm_version, snapshot, diff)
            SELECT
                events.id,
                events.current_version,
                'baseline_import',
                COALESCE(events.cluster_version, 'legacy'),
                jsonb_build_object(
                    'id', events.id,
                    'fingerprint', events.fingerprint,
                    'event_type', events.event_type,
                    'topic', events.topic,
                    'title', events.title,
                    'summary', events.summary,
                    'status', events.status,
                    'score', events.score,
                    'evidence_level', events.evidence_level,
                    'cluster_version', events.cluster_version,
                    'first_seen_at', events.first_seen_at,
                    'last_seen_at', events.last_seen_at,
                    'evidence', COALESCE(
                        (
                            SELECT jsonb_agg(
                                jsonb_build_object(
                                    'document_id', evidence.document_id,
                                    'evidence_level', evidence.evidence_level,
                                    'relation_reason', evidence.relation_reason
                                )
                                ORDER BY evidence.document_id
                            )
                            FROM event_documents AS evidence
                            WHERE evidence.event_id = events.id
                        ),
                        '[]'::jsonb
                    ),
                    'claims', '[]'::jsonb
                ),
                jsonb_build_object(
                    'baseline_import', true,
                    'historical_versions_unavailable',
                    GREATEST(events.current_version - 1, 0)
                )
            FROM events
            WHERE NOT EXISTS (
                SELECT 1 FROM event_versions
                WHERE event_versions.event_id = events.id
            )
            """
        )
    )

    op.create_table(
        "claims",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("event_id", sa.BigInteger(), nullable=False),
        sa.Column("claim_key", sa.String(160), nullable=False),
        sa.Column("claim_type", sa.String(32), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column(
            "normalized_value",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("status", sa.String(16), server_default="unverified", nullable=False),
        sa.Column("confidence", sa.Float()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["event_id"], ["events.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id", "claim_key", name="uq_event_claim"),
    )
    op.create_index("ix_claims_event_id", "claims", ["event_id"])
    op.create_index("ix_claims_claim_type", "claims", ["claim_type"])
    op.create_index("ix_claims_status", "claims", ["status"])

    op.create_table(
        "claim_evidence",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("claim_id", sa.BigInteger(), nullable=False),
        sa.Column("document_id", sa.BigInteger(), nullable=False),
        sa.Column("stance", sa.String(16), server_default="support", nullable=False),
        sa.Column("evidence_level", sa.String(1)),
        sa.Column("excerpt", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["claim_id"], ["claims.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["document_id"], ["documents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("claim_id", "document_id", "stance", name="uq_claim_document_stance"),
    )
    op.create_index("ix_claim_evidence_claim_id", "claim_evidence", ["claim_id"])
    op.create_index("ix_claim_evidence_document_id", "claim_evidence", ["document_id"])


def downgrade() -> None:
    op.drop_table("claim_evidence")
    op.drop_table("claims")
    op.drop_table("event_versions")
    op.drop_table("candidate_reviews")
    op.drop_table("m2_work_items")
    op.drop_table("m2_runs")
    op.drop_table("document_block_tokens")
    op.drop_table("document_identities")
    op.drop_table("document_signatures")
    op.drop_index("ix_documents_dedupe_component_id", table_name="documents")
    op.drop_constraint("fk_documents_dedupe_component", "documents", type_="foreignkey")
    op.drop_column("documents", "dedupe_component_id")
    op.drop_table("duplicate_components")
