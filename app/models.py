from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db


def utc_isoformat(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    firebase_uid = db.Column(db.String(128), unique=True, nullable=True, index=True)
    email_notifications_enabled = db.Column(db.Boolean, nullable=False, default=True, server_default="1")
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class MonitoringEvent(db.Model):
    __tablename__ = "monitoring_events"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    event_id = db.Column(db.String(36), nullable=True, unique=True)
    event_type = db.Column(db.String(50), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, default="info")
    details = db.Column(db.String(500), nullable=False)
    file_activity = db.Column(db.JSON, nullable=True)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    source = db.Column(db.String(20), nullable=False, default="poll")
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "details": self.details,
            "file_activity": self.file_activity or [],
            "risk_score": self.risk_score,
            "source": self.source,
            "created_at": utc_isoformat(self.created_at),
        }


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    title = db.Column(db.String(150), nullable=False)
    details = db.Column(db.String(500), nullable=False)
    severity = db.Column(db.String(20), nullable=False, default="medium")
    risk_score = db.Column(db.Integer, nullable=False)
    acknowledged = db.Column(db.Boolean, nullable=False, default=False)
    resolved_at = db.Column(db.DateTime(timezone=True), nullable=True)
    model_version = db.Column(db.String(80), nullable=True)
    rule_trace = db.Column(db.JSON, nullable=True)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "details": self.details,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "acknowledged": self.acknowledged,
            "resolved_at": utc_isoformat(self.resolved_at) if self.resolved_at else None,
            "model_version": self.model_version,
            "rule_trace": self.rule_trace or [],
            "response": next((item.to_dict() for item in self.responses), None),
            "created_at": utc_isoformat(self.created_at),
        }


class ResponseAction(db.Model):
    __tablename__ = "response_actions"
    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"), nullable=False, unique=True)
    completed = db.Column(db.Boolean, nullable=False, default=False)
    result = db.Column(db.JSON, nullable=False)
    alert = db.relationship("Alert", backref="responses")

    def to_dict(self):
        return {"id": self.id, "completed": self.completed, **self.result}


class AuditLog(db.Model):
    """Account-scoped record of security-relevant user and workflow actions."""

    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    action = db.Column(db.String(80), nullable=False, index=True)
    details = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False,
                            default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self) -> dict:
        return {"id": self.id, "action": self.action, "details": self.details or {},
                "created_at": utc_isoformat(self.created_at)}


class AnalysisRun(db.Model):
    __tablename__ = "analysis_runs"
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    kind = db.Column(db.String(30), nullable=False)
    status = db.Column(db.String(30), nullable=False, default="running")
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    result = db.Column(db.JSON, nullable=False, default=dict)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"))
    alert = db.relationship("Alert")

    def to_dict(self):
        return {"id": self.id, "kind": self.kind, "status": self.status,
                "created_at": utc_isoformat(self.created_at), "result": self.result,
                "incident": self.alert.to_dict() if self.alert else None}


class QuarantineItem(db.Model):
    """One file moved to quarantine, with enough detail to restore it safely."""

    __tablename__ = "quarantine_items"

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"), nullable=False, index=True)
    original_path = db.Column(db.String(512), nullable=False)
    quarantine_path = db.Column(db.String(512), nullable=False, unique=True)
    sha256 = db.Column(db.String(64), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False, default=0)
    quarantined_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    restored_at = db.Column(db.DateTime(timezone=True), nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "original_path": self.original_path,
            "quarantine_path": self.quarantine_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "quarantined_at": utc_isoformat(self.quarantined_at),
            "restored_at": utc_isoformat(self.restored_at) if self.restored_at else None,
        }


class DownloadLog(db.Model):
    """Audit record for every authenticated release download."""

    __tablename__ = "download_log"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    release_version = db.Column(db.String(50), nullable=False, default="")
    filename = db.Column(db.String(255), nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    downloaded_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "release_version": self.release_version,
            "filename": self.filename,
            "sha256": self.sha256,
            "downloaded_at": utc_isoformat(self.downloaded_at),
        }


class ModelRegistry(db.Model):
    """Version and integrity record for each model artifact actually loaded."""

    __tablename__ = "model_registry"

    id = db.Column(db.Integer, primary_key=True)
    model_type = db.Column(db.String(60), nullable=False, index=True)
    display_name = db.Column(db.String(120), nullable=False)
    artifact_sha256 = db.Column(db.String(64), nullable=False, unique=True)
    feature_schema = db.Column(db.JSON, nullable=False, default=list)
    decision_threshold = db.Column(db.Float, nullable=False)
    trained_at = db.Column(db.String(40), nullable=True)
    metrics = db.Column(db.JSON, nullable=False, default=dict)
    registered_at = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "model_type": self.model_type,
            "display_name": self.display_name,
            "artifact_sha256": self.artifact_sha256,
            "feature_schema": self.feature_schema,
            "decision_threshold": self.decision_threshold,
            "trained_at": self.trained_at,
            "metrics": self.metrics,
            "registered_at": utc_isoformat(self.registered_at),
        }
