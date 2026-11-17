"""initial schema: every models/ table, plus the ledger-mutation-rejection
trigger (design C, docs/gates/slice0-plan.md Section 3.10).

Revision ID: 0001_initial
Revises:
Create Date: 2026-11-17
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "orgs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("email", sa.String(320), nullable=False, unique=True),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_org_id", "users", ["org_id"])

    op.create_table(
        "api_keys",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "org_id", sa.String(36), sa.ForeignKey("orgs.id"), nullable=False
        ),
        sa.Column("hashed_key", sa.String(128), nullable=False, unique=True),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_api_keys_org_id", "api_keys", ["org_id"])

    op.create_table(
        "engagements",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("profile", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("targets", sa.JSON(), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("authorization", sa.JSON(), nullable=False),
        sa.Column("identities", sa.JSON(), nullable=False),
        sa.Column("ownership_rules", sa.JSON(), nullable=False),
        sa.Column("asset_tags", sa.JSON(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.String(1024), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_engagements_org_id", "engagements", ["org_id"])

    op.create_table(
        "scans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column(
            "engagement_id", sa.String(36), sa.ForeignKey("engagements.id"), nullable=False
        ),
        sa.Column("stages", sa.JSON(), nullable=False),
        sa.Column("options", sa.JSON(), nullable=False),
        sa.Column("schedule", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scans_org_id", "scans", ["org_id"])
    op.create_index("ix_scans_engagement_id", "scans", ["engagement_id"])

    op.create_table(
        "findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column(
            "engagement_id", sa.String(36), sa.ForeignKey("engagements.id"), nullable=False
        ),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("cwe", sa.String(32), nullable=True),
        sa.Column("taxonomy", sa.JSON(), nullable=False),
        sa.Column("owasp_api", sa.String(64), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="candidate"),
        sa.Column("severity", sa.String(16), nullable=True),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("cvss", sa.JSON(), nullable=False),
        sa.Column("priority", sa.JSON(), nullable=False),
        sa.Column("source_adapter", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_findings_org_id", "findings", ["org_id"])
    op.create_index("ix_findings_engagement_id", "findings", ["engagement_id"])

    op.create_table(
        "evidence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column(
            "engagement_id", sa.String(36), sa.ForeignKey("engagements.id"), nullable=False
        ),
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("redacted_excerpt", sa.String(4096), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("identity_label", sa.String(128), nullable=True),
        sa.Column("expected", sa.String(2048), nullable=True),
        sa.Column("observed", sa.String(2048), nullable=True),
        sa.Column("policy_version", sa.String(128), nullable=False),
        sa.Column("adapter", sa.JSON(), nullable=False),
        sa.Column("ledger_chain", sa.String(255), nullable=False),
        sa.Column("ledger_seq", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_evidence_org_id", "evidence", ["org_id"])
    op.create_index("ix_evidence_engagement_id", "evidence", ["engagement_id"])
    op.create_index("ix_evidence_finding_id", "evidence", ["finding_id"])

    # --- Ledger tables (D1, design C / Section 3.10) ---
    op.create_table(
        "ledger_entries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("chain_id", sa.String(255), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(255), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("record_hash", sa.String(64), nullable=False),
        # SEC-5: a second, independent backstop for the chain_heads-lock
        # fork-prevention guarantee -- a duplicate (chain_id, seq) from a
        # lock bug raises IntegrityError instead of silently forking.
        sa.UniqueConstraint("chain_id", "seq", name="uq_ledger_entries_chain_id_seq"),
    )
    op.create_index("ix_ledger_entries_chain_id", "ledger_entries", ["chain_id"])

    # chain_heads: the lock target for D1's per-chain serialization
    # (resolves the SELECT ... FOR UPDATE-requires-UPDATE privilege
    # contradiction without granting UPDATE on ledger_entries itself).
    op.create_table(
        "chain_heads",
        sa.Column("chain_id", sa.String(255), primary_key=True),
        sa.Column("seq", sa.Integer(), nullable=False, server_default="-1"),
        sa.Column("head_hash", sa.String(64), nullable=False),
    )

    op.create_table(
        "checkpoints",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("chain_id", sa.String(255), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("head_hash", sa.String(64), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signature", sa.String(256), nullable=False),
    )
    op.create_index("ix_checkpoints_chain_id", "checkpoints", ["chain_id"])

    op.create_table(
        "idempotency_keys",
        sa.Column("key", sa.String(255), primary_key=True),
        sa.Column("org_id", sa.String(36), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("response_body", sa.JSON(), nullable=False),
        sa.Column("response_status", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_idempotency_keys_org_id", "idempotency_keys", ["org_id"])

    # --- Defense-in-depth mutation-rejection trigger (design C, Section
    # 3.10): fires regardless of role, including vulnscope_migrator (the
    # owner role) by default, satisfying the "even for the owner role"
    # requirement with no extra grant/revoke mechanism. ENABLE ALWAYS
    # TRIGGER (fixes INFRA-5) makes it hold even under
    # session_replication_role = replica.
    op.execute(
        """
        CREATE FUNCTION reject_ledger_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'ledger_entries/checkpoints are append-only; % is not permitted', TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )

    op.execute(
        """
        CREATE TRIGGER ledger_entries_no_mutate
            BEFORE UPDATE OR DELETE ON ledger_entries
            FOR EACH ROW EXECUTE FUNCTION reject_ledger_mutation();
        """
    )
    op.execute(
        "ALTER TABLE ledger_entries ENABLE ALWAYS TRIGGER ledger_entries_no_mutate;"
    )

    op.execute(
        """
        CREATE TRIGGER ledger_entries_no_truncate
            BEFORE TRUNCATE ON ledger_entries
            FOR EACH STATEMENT EXECUTE FUNCTION reject_ledger_mutation();
        """
    )
    op.execute(
        "ALTER TABLE ledger_entries ENABLE ALWAYS TRIGGER ledger_entries_no_truncate;"
    )

    op.execute(
        """
        CREATE TRIGGER checkpoints_no_mutate
            BEFORE UPDATE OR DELETE ON checkpoints
            FOR EACH ROW EXECUTE FUNCTION reject_ledger_mutation();
        """
    )
    op.execute(
        "ALTER TABLE checkpoints ENABLE ALWAYS TRIGGER checkpoints_no_mutate;"
    )

    op.execute(
        """
        CREATE TRIGGER checkpoints_no_truncate
            BEFORE TRUNCATE ON checkpoints
            FOR EACH STATEMENT EXECUTE FUNCTION reject_ledger_mutation();
        """
    )
    op.execute(
        "ALTER TABLE checkpoints ENABLE ALWAYS TRIGGER checkpoints_no_truncate;"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS checkpoints_no_truncate ON checkpoints;")
    op.execute("DROP TRIGGER IF EXISTS checkpoints_no_mutate ON checkpoints;")
    op.execute("DROP TRIGGER IF EXISTS ledger_entries_no_truncate ON ledger_entries;")
    op.execute("DROP TRIGGER IF EXISTS ledger_entries_no_mutate ON ledger_entries;")
    op.execute("DROP FUNCTION IF EXISTS reject_ledger_mutation();")

    op.drop_table("idempotency_keys")
    op.drop_table("checkpoints")
    op.drop_table("chain_heads")
    op.drop_table("ledger_entries")
    op.drop_table("evidence")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("engagements")
    op.drop_table("api_keys")
    op.drop_table("users")
    op.drop_table("orgs")
