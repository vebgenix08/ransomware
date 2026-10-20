"""Add an optional Firebase identity link to local user records.

Revision ID: 0004_firebase_identity
Revises: 0003_events
Create Date: 2026-10-20
"""
import sqlalchemy as sa
from alembic import op

revision = "0004_firebase_identity"
down_revision = "0003_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("firebase_uid", sa.String(128), nullable=True))
        batch.create_index("ix_users_firebase_uid", ["firebase_uid"], unique=True)


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_index("ix_users_firebase_uid")
        batch.drop_column("firebase_uid")
