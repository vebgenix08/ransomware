"""Register loaded model artifacts so detections can name their model version."""
import hashlib
import json
from pathlib import Path

from .extensions import db
from .models import ModelRegistry


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def register_artifact(app, artifact_path: Path) -> ModelRegistry | None:
    artifact_path = Path(artifact_path)
    try:
        model = json.loads(artifact_path.read_text(encoding="utf-8"))
        digest = _sha256(artifact_path)
    except (OSError, json.JSONDecodeError) as exc:
        app.logger.warning("Model artifact could not be registered: %s", exc)
        return None

    existing = ModelRegistry.query.filter_by(artifact_sha256=digest).first()
    if existing:
        return existing

    record = ModelRegistry(
        model_type=model.get("model_type", "unknown"),
        display_name=model.get("display_name", artifact_path.stem),
        artifact_sha256=digest,
        feature_schema=model.get("feature_names") or model.get("input_features") or [],
        decision_threshold=float(model.get("decision_threshold", 0.6)),
        trained_at=model.get("trained_at"),
        metrics=model.get("metrics") or {},
    )
    db.session.add(record)
    db.session.commit()
    return record


def register_models(app) -> None:
    """Record the telemetry and published-data models once per artifact hash."""
    root = Path(app.root_path) / "artifacts"
    for relative in ("behavioral_model.json", "mlran/model.json"):
        register_artifact(app, root / relative)


def model_version_label(app, artifact_path: Path) -> str:
    """Short, stable identifier shown on alerts (first 12 hex characters)."""
    record = ModelRegistry.query.filter(
        ModelRegistry.artifact_sha256 == _sha256(Path(artifact_path))
    ).first()
    if record is None:
        return "unregistered"
    return f"{record.display_name}@{record.artifact_sha256[:12]}"
