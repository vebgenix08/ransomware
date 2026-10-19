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
    app.config.from_mapping(
        SECRET_KEY=secret_key,
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{database_path.as_posix()}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true",
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
        RELEASE_PATH=str(Path(app.instance_path) / "releases"),
    )

    if test_config:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)
    _configure_sqlite(app)
    MonitoringService().init_app(app)

    from .routes import main
    from .auth import auth
    from .api import api
    from .downloads import downloads

    app.register_blueprint(main)
    app.register_blueprint(auth)
    app.register_blueprint(api)
    app.register_blueprint(downloads)

    database_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if database_uri in ("sqlite://", "sqlite:///:memory:"):
        # In-memory databases used by tests have no migration history.
        with app.app_context():
            db.create_all()
    else:
        _run_migrations(app)

    return app