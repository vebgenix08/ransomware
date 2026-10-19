import os
from pathlib import Path
from typing import Optional

from flask import Flask
from dotenv import load_dotenv

from .extensions import csrf, db, login_manager
from .monitor import MonitoringService


def create_app(test_config: Optional[dict] = None) -> Flask:
    """Create and configure the RansomShield Flask application."""
    load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False, interpolate=False)
    app = Flask(__name__, instance_relative_config=True)

    database_path = Path(app.instance_path) / "ransomshield.db"
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-this-secret-key"),
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{database_path.as_posix()}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=5 * 1024 * 1024,
        RUNS_PATH=str(Path(app.instance_path) / "runs"),
        AUTO_QUARANTINE=os.environ.get("AUTO_QUARANTINE", "true").lower() == "true",
        QUARANTINE_PATH=str(Path(app.instance_path) / "quarantine"),
        RESPONSE_WEBHOOK_URL=os.environ.get("RESPONSE_WEBHOOK_URL", ""),
        RESPONSE_EMAIL_TO=os.environ.get("RESPONSE_EMAIL_TO", ""),
        RESPONSE_EMAIL_FROM=os.environ.get("RESPONSE_EMAIL_FROM", ""),
        SMTP_HOST=os.environ.get("SMTP_HOST", ""),
        SMTP_PORT=int(os.environ.get("SMTP_PORT", "587")),
        SMTP_USERNAME=os.environ.get("SMTP_USERNAME", ""),
        SMTP_PASSWORD=os.environ.get("SMTP_PASSWORD", ""),
        SMTP_SECURITY=os.environ.get("SMTP_SECURITY", "starttls").lower(),
    )

    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    MonitoringService().init_app(app)

    from .routes import main
    from .auth import auth
    from .api import api

    app.register_blueprint(main)
    app.register_blueprint(auth)
    app.register_blueprint(api)

    with app.app_context():
        db.create_all()

    return app
