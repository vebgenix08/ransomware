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
    event_type = db.Column(db.String(50), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, default="info")
    details = db.Column(db.String(500), nullable=False)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event_type": self.event_type,
            "severity": self.severity,
            "details": self.details,
            "risk_score": self.risk_score,
            "created_at": utc_isoformat(self.created_at),
        }


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    details = db.Column(db.String(500), nullable=False)
    severity = db.Column(db.String(20), nullable=False, default="medium")
    risk_score = db.Column(db.Integer, nullable=False)
    acknowledged = db.Column(db.Boolean, nullable=False, default=False)
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
