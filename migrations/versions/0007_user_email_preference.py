"""Add a per-account email notification preference.

Revision ID: 0007_user_email_preference
Revises: 0006_alert_resolution_audit
Create Date: 2026-10-21
"""
import sqlalchemy as sa
from alembic import op

revision = "0007_user_email_preference"
down_revision = "0006_alert_resolution_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("email_notifications_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
    )


def downgrade() -> None:
    op.drop_column("users", "email_notifications_enabled")
