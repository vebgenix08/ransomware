"""Evidence, quarantine recovery, downloads and model registry.

Revision ID: 0002_evidence
Revises: 0001_baseline
Create Date: 2026-10-19
"""
import sqlalchemy as sa
from alembic import op

revision = "0002_evidence"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("alerts") as batch:
        batch.add_column(sa.Column("model_version", sa.String(80), nullable=True))
        batch.add_column(sa.Column("rule_trace", sa.JSON(), nullable=True))

    op.create_table(
        "quarantine_items",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id"), nullable=False),
        sa.Column("original_path", sa.String(512), nullable=False),
        sa.Column("quarantine_path", sa.String(512), nullable=False, unique=True),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("quarantined_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("restored_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_quarantine_items_alert_id", "quarantine_items", ["alert_id"])

    op.create_table(
        "download_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("release_version", sa.String(50), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("downloaded_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_download_log_user_id", "download_log", ["user_id"])
    op.create_index("ix_download_log_downloaded_at", "download_log", ["downloaded_at"])

    op.create_table(
        "model_registry",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("model_type", sa.String(60), nullable=False),
        sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column("artifact_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("feature_schema", sa.JSON(), nullable=False),
        sa.Column("decision_threshold", sa.Float(), nullable=False),
        sa.Column("trained_at", sa.String(40), nullable=True),
        sa.Column("metrics", sa.JSON(), nullable=False),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_model_registry_model_type", "model_registry", ["model_type"])


def downgrade() -> None:
    op.drop_index("ix_model_registry_model_type", table_name="model_registry")
    op.drop_table("model_registry")
    op.drop_index("ix_download_log_downloaded_at", table_name="download_log")
    op.drop_index("ix_download_log_user_id", table_name="download_log")
    op.drop_table("download_log")
    op.drop_index("ix_quarantine_items_alert_id", table_name="quarantine_items")
    op.drop_table("quarantine_items")
    with op.batch_alter_table("alerts") as batch:
        batch.drop_column("rule_trace")
        batch.drop_column("model_version")
