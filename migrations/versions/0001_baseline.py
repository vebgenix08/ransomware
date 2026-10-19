"""Baseline schema matching the pre-migration RansomShield database.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-10-19

Existing installations are stamped at this revision by ``create_app`` so that
revision 0002 applies on top without recreating or dropping any data.
"""
import sqlalchemy as sa
from alembic import op

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("full_name", sa.String(100), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "monitoring_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("details", sa.String(500), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_monitoring_events_event_type", "monitoring_events", ["event_type"])
    op.create_index("ix_monitoring_events_created_at", "monitoring_events", ["created_at"])

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("title", sa.String(150), nullable=False),
        sa.Column("details", sa.String(500), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("acknowledged", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"])

    op.create_table(
        "response_actions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id"), nullable=False, unique=True),
        sa.Column("completed", sa.Boolean(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
    )

    op.create_table(
        "analysis_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("kind", sa.String(30), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id"), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("analysis_runs")
    op.drop_table("response_actions")
    op.drop_table("alerts")
    op.drop_index("ix_monitoring_events_created_at", table_name="monitoring_events")
    op.drop_index("ix_monitoring_events_event_type", table_name="monitoring_events")
    op.drop_table("monitoring_events")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
