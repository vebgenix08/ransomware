"""Store monitored file changes as structured event data.

Revision ID: 0008_event_file_activity
Revises: 0007_user_email_preference
Create Date: 2026-10-21
"""
import sqlalchemy as sa
from alembic import op

revision = "0008_event_file_activity"
down_revision = "0007_user_email_preference"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("monitoring_events") as batch:
        batch.add_column(sa.Column("file_activity", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("monitoring_events") as batch:
        batch.drop_column("file_activity")
