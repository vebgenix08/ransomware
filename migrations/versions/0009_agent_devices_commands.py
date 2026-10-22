"""Add endpoint device presence and explicit remote response commands.

Revision ID: 0009_agent_devices_commands
Revises: 0008_event_file_activity
"""
from alembic import op
import sqlalchemy as sa


revision = "0009_agent_devices_commands"
down_revision = "0008_event_file_activity"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "agent_devices",
        sa.Column("device_id", sa.String(length=36), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("label", sa.String(length=64), nullable=False),
        sa.Column("folder_name", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("agent_version", sa.String(length=30), nullable=False, server_default=""),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_agent_devices_user_id", "agent_devices", ["user_id"])
    op.create_index("ix_agent_devices_last_seen_at", "agent_devices", ["last_seen_at"])
    op.create_table(
        "agent_commands",
        sa.Column("command_id", sa.String(length=36), primary_key=True),
        sa.Column("device_id", sa.String(length=36), sa.ForeignKey("agent_devices.device_id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("action", sa.String(length=20), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_agent_commands_device_id", "agent_commands", ["device_id"])
    op.create_index("ix_agent_commands_user_id", "agent_commands", ["user_id"])
    op.create_index("ix_agent_commands_status", "agent_commands", ["status"])
    op.create_index("ix_agent_commands_created_at", "agent_commands", ["created_at"])


def downgrade():
    op.drop_table("agent_commands")
    op.drop_table("agent_devices")
