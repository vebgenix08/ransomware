import os
import secrets
from pathlib import Path
from typing import Optional

from flask import Flask
from dotenv import load_dotenv
from sqlalchemy import event
from sqlalchemy.engine import Engine

from .extensions import csrf, db, login_manager, migrate
from .monitor import MonitoringService
from .silrad_prepare import SilradPreparation

DEV_SECRET = "dev-only-change-this-secret-key"


def _configure_sqlite(app: Flask) -> None:
    """Enable WAL, sane locking and foreign keys on every SQLite connection.

    The monitor thread writes while request threads read; WAL keeps readers from
    blocking the writer and busy_timeout prevents immediate 'database is locked'
    failures instead of waiting a few milliseconds.
    """
    if not app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite:"):
        return

    @event.listens_for(Engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def _run_migrations(app: Flask) -> None:
    """Bring the schema up to date without destroying an existing database."""
    from flask_migrate import stamp, upgrade
    from sqlalchemy import inspect

    with app.app_context():
        tables = set(inspect(db.engine).get_table_names())
        if "users" in tables and "alembic_version" not in tables:
            # An older install predates migrations: pin the baseline revision so
            # the next upgrade applies the later ones.
            stamp(revision="0001_baseline")
        upgrade()


def create_app(test_config: Optional[dict] = None) -> Flask:
    """Create and configure the RansomShield Flask application."""
    load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False, interpolate=False)
    app = Flask(__name__, instance_relative_config=True)

    testing = bool(test_config and test_config.get("TESTING"))
    secret_key = os.environ.get("SECRET_KEY", "")
    if not secret_key:
        if testing:
            # Ephemeral key: tests must never depend on a developer machine secret.
            secret_key = secrets.token_hex(32)
        else:
            raise RuntimeError(
                "SECRET_KEY is unset. Add a long random SECRET_KEY to .env before "
                "starting RansomShield; sessions cannot be protected without it."
            )
    if secret_key == DEV_SECRET and not testing:
        raise RuntimeError("SECRET_KEY still holds the development placeholder; replace it.")

    database_path = Path(app.instance_path) / "ransomshield.db"
    database_uri = os.environ.get("DATABASE_URL", "").strip()
    if database_uri.startswith("postgres://"):
        database_uri = "postgresql://" + database_uri[len("postgres://"):]
    if database_uri.startswith("postgresql://"):
        database_uri = "postgresql+psycopg://" + database_uri[len("postgresql://"):]
    app.config.from_mapping(
        APP_NAME=os.environ.get("APP_NAME", "RansomShield"),
        SECRET_KEY=secret_key,
        SQLALCHEMY_DATABASE_URI=database_uri or f"sqlite:///{database_path.as_posix()}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
        MAX_CONTENT_LENGTH=5 * 1024 * 1024,
        RUNS_PATH=str(Path(app.instance_path) / "runs"),
        SILRAD_DATA_DIR=os.environ.get("SILRAD_DATA_DIR", str(Path(app.instance_path) / "silrad")),
        # Fail closed: automatic quarantine is opt-in and requires validated
        # detection plus a deliberate deployment-level setting.
        AUTO_QUARANTINE=os.environ.get("AUTO_QUARANTINE", "false").lower() == "true",
        QUARANTINE_MODE=os.environ.get("QUARANTINE_MODE", "dry-run").lower(),
        QUARANTINE_PATH=str(Path(app.instance_path) / "quarantine"),
        MONITOR_TARGET_PATH=os.environ.get("MONITOR_TARGET_PATH", str(Path(app.instance_path) / "monitor_target")),
        RESPONSE_WEBHOOK_URL=os.environ.get("RESPONSE_WEBHOOK_URL", ""),
        RESPONSE_EMAIL_TO=os.environ.get("RESPONSE_EMAIL_TO", ""),
        RESPONSE_EMAIL_FROM=os.environ.get("RESPONSE_EMAIL_FROM", ""),
        SMTP_HOST=os.environ.get("SMTP_HOST", ""),
        SMTP_PORT=int(os.environ.get("SMTP_PORT", "587")),
        SMTP_USERNAME=os.environ.get("SMTP_USERNAME", ""),
        SMTP_PASSWORD=os.environ.get("SMTP_PASSWORD", ""),
        SMTP_SECURITY=os.environ.get("SMTP_SECURITY", "starttls").lower(),
        AUTH_PROVIDER=os.environ.get("AUTH_PROVIDER", "local").strip().lower(),
        FIREBASE_API_KEY=os.environ.get("FIREBASE_API_KEY", "").strip(),
        FIREBASE_AUTH_DOMAIN=os.environ.get("FIREBASE_AUTH_DOMAIN", "").strip(),
        FIREBASE_PROJECT_ID=os.environ.get("FIREBASE_PROJECT_ID", "").strip(),
        FIREBASE_MESSAGING_SENDER_ID=os.environ.get("FIREBASE_MESSAGING_SENDER_ID", "").strip(),
        FIREBASE_APP_ID=os.environ.get("FIREBASE_APP_ID", "").strip(),
        AGENT_API_TOKEN=os.environ.get("AGENT_API_TOKEN", "").strip(),
        AGENT_OWNER_EMAIL=os.environ.get("AGENT_OWNER_EMAIL", "").strip().lower(),
    )

    if test_config:
        app.config.update(test_config)

    if app.config["AUTH_PROVIDER"] not in {"local", "firebase"}:
        raise RuntimeError("AUTH_PROVIDER must be either 'local' or 'firebase'.")
    if app.config["AUTH_PROVIDER"] == "firebase":
        missing_firebase = [
            key for key in ("FIREBASE_API_KEY", "FIREBASE_AUTH_DOMAIN", "FIREBASE_PROJECT_ID",
                            "FIREBASE_MESSAGING_SENDER_ID", "FIREBASE_APP_ID")
            if not app.config.get(key)
        ]
        if missing_firebase:
            raise RuntimeError("Firebase Authentication is selected but Firebase web config is incomplete: "
                               + ", ".join(missing_firebase))

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)

    @app.context_processor
    def expose_auth_provider_config():
        return {
            "AUTH_PROVIDER": app.config["AUTH_PROVIDER"],
            "FIREBASE_WEB_CONFIG": {
                "apiKey": app.config["FIREBASE_API_KEY"],
                "authDomain": app.config["FIREBASE_AUTH_DOMAIN"],
                "projectId": app.config["FIREBASE_PROJECT_ID"],
                "messagingSenderId": app.config["FIREBASE_MESSAGING_SENDER_ID"],
                "appId": app.config["FIREBASE_APP_ID"],
            },
        }
    _configure_sqlite(app)
    MonitoringService().init_app(app)
    SilradPreparation().init_app(app)

    from .routes import main
    from .auth import auth
    from .api import api

    app.register_blueprint(main)
    app.register_blueprint(auth)
    app.register_blueprint(api)

    database_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if database_uri in ("sqlite://", "sqlite:///:memory:"):
        # In-memory databases used by tests have no migration history.
        with app.app_context():
            db.create_all()
    else:
        _run_migrations(app)

    with app.app_context():
        from .registry import register_models

        register_models(app)

    return app
