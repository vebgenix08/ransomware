"""Event identity and collector source for monitoring events.

Revision ID: 0003_events
Revises: 0002_evidence
Create Date: 2026-10-19
"""
import sqlalchemy as sa
from alembic import op

revision = "0003_events"
down_revision = "0002_evidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("monitoring_events") as batch:
        batch.add_column(sa.Column("event_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("source", sa.String(20), nullable=False, server_default="poll"))
        batch.create_unique_constraint("uq_monitoring_events_event_id", ["event_id"])


def downgrade() -> None:
    with op.batch_alter_table("monitoring_events") as batch:
        batch.drop_constraint("uq_monitoring_events_event_id", type_="unique")
        batch.drop_column("source")
        batch.drop_column("event_id")
