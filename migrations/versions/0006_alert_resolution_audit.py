"""Add alert resolution and account audit history.

Revision ID: 0006_alert_resolution_audit
Revises: 0005_activity_ownership
Create Date: 2026-10-21
"""
import sqlalchemy as sa
from alembic import op

revision = "0006_alert_resolution_audit"
down_revision = "0005_activity_ownership"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if op.get_bind().dialect.name == "sqlite":
        # SQLite must not rebuild alerts: response_actions, runs, and quarantine
        # records have foreign keys that point to it.
        op.execute("ALTER TABLE alerts ADD COLUMN resolved_at DATETIME")
    else:
        with op.batch_alter_table("alerts") as batch:
            batch.add_column(sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_action", table_name="audit_logs")
    op.drop_index("ix_audit_logs_user_id", table_name="audit_logs")
    op.drop_table("audit_logs")
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("alerts") as batch:
            batch.drop_column("resolved_at")
    else:
        with op.batch_alter_table("alerts") as batch:
            batch.drop_column("resolved_at")
