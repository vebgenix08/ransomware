"""Assign monitoring events and alerts to an account.

Revision ID: 0005_activity_ownership
Revises: 0004_firebase_identity
Create Date: 2026-10-20
"""
import sqlalchemy as sa
from alembic import op

revision = "0005_activity_ownership"
down_revision = "0004_firebase_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("monitoring_events") as batch:
        batch.add_column(sa.Column("user_id", sa.Integer(), nullable=True))
        batch.create_foreign_key("fk_monitoring_events_user_id_users", "users", ["user_id"], ["id"])
        batch.create_index("ix_monitoring_events_user_id", ["user_id"])
    with op.batch_alter_table("alerts") as batch:
        batch.add_column(sa.Column("user_id", sa.Integer(), nullable=True))
        batch.create_foreign_key("fk_alerts_user_id_users", "users", ["user_id"], ["id"])
        batch.create_index("ix_alerts_user_id", ["user_id"])
    # Preserve account-owned dataset incidents created before ownership was explicit.
    op.execute(sa.text("""
        UPDATE alerts SET user_id = (
            SELECT analysis_runs.user_id FROM analysis_runs WHERE analysis_runs.alert_id = alerts.id
        )
        WHERE user_id IS NULL AND EXISTS (
            SELECT 1 FROM analysis_runs WHERE analysis_runs.alert_id = alerts.id
        )
    """))


def downgrade() -> None:
    with op.batch_alter_table("alerts") as batch:
        batch.drop_index("ix_alerts_user_id")
        batch.drop_constraint("fk_alerts_user_id_users", type_="foreignkey")
        batch.drop_column("user_id")
    with op.batch_alter_table("monitoring_events") as batch:
        batch.drop_index("ix_monitoring_events_user_id")
        batch.drop_constraint("fk_monitoring_events_user_id_users", type_="foreignkey")
        batch.drop_column("user_id")
