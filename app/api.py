import csv
import io
import json
import hmac
import re
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4
from pathlib import Path
from flask import Blueprint, current_app, jsonify, request, Response, abort, send_file
from flask_login import login_required, current_user
from sqlalchemy import or_
from werkzeug.datastructures import FileStorage

from .extensions import csrf, db
from .models import (Alert, MonitoringEvent, AnalysisRun, QuarantineItem, User, AuditLog,
                     AgentDevice, AgentCommand, utc_isoformat)
from .audit import record_audit
from .runs import start_run, execute


api = Blueprint("api", __name__, url_prefix="/api")


def _authenticated_agent_owner():
    token = current_app.config.get("AGENT_API_TOKEN", "")
    supplied = request.headers.get("Authorization", "").removeprefix("Bearer ")
    if not token or not hmac.compare_digest(supplied, token):
        return None, (jsonify(ok=False, message="Agent authentication failed."), 401)
    owner_email = current_app.config.get("AGENT_OWNER_EMAIL", "").strip().lower()
    owner = User.query.filter_by(email=owner_email).first() if owner_email else None
    if owner is None:
        return None, (jsonify(ok=False, message="Endpoint agent owner is not configured."), 503)
    return owner, None


def _agent_device_id(value):
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        return None


def _safe_endpoint_relative_path(value):
    path = str(value or "").replace("\\", "/")
    parts = path.split("/")
    reserved = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$", re.IGNORECASE)
    invalid = any(any(char in '<>:"|?*' for char in part) or part.endswith((" ", "."))
                  or reserved.fullmatch(part) for part in parts)
    if (not path or len(path) > 400 or path.startswith("/") or invalid
            or any(part in {"", ".", ".."} or any(ord(char) < 32 for char in part) for part in parts)):
        return None
    return path


def _upsert_agent_device(owner, body, *, event=False):
    device_id = _agent_device_id(body.get("device_id"))
    if device_id is None:
        return None, (jsonify(ok=False, message="device_id must be a UUID."), 400)
    label = str(body.get("agent", "")).strip()
    folder_name = str(body.get("folder_name", "")).strip()
    agent_version = str(body.get("agent_version", ""))[:30]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", label):
        return None, (jsonify(ok=False, message="agent must use letters, numbers, dot, dash, or underscore."), 400)
    if len(folder_name) > 255 or any(ord(char) < 32 for char in folder_name):
        return None, (jsonify(ok=False, message="folder_name is invalid."), 400)
    device = db.session.get(AgentDevice, device_id)
    if device and device.user_id != owner.id:
        return None, (jsonify(ok=False, message="This device ID belongs to another account."), 409)
    name_taken = AgentDevice.query.filter_by(user_id=owner.id, label=label).first()
    if name_taken and name_taken.device_id != device_id:
        return None, (jsonify(ok=False, message="This device label is already registered. Choose a unique label."), 409)
    now = datetime.now(timezone.utc)
    if device is None:
        device = AgentDevice(device_id=device_id, user_id=owner.id, label=label,
                             folder_name=folder_name, agent_version=agent_version,
                             first_seen_at=now, last_seen_at=now)
        db.session.add(device)
    else:
        device.label = label
        device.folder_name = folder_name
        device.agent_version = agent_version
        device.last_seen_at = now
    if event:
        device.last_event_at = now
    return device, None


@api.post("/agent/events")
@csrf.exempt
def agent_event():
    """Accept bounded file activity summaries from a trusted endpoint agent."""
    owner, error = _authenticated_agent_owner()
    if error:
        return error
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(ok=False, message="Expected a JSON event."), 400
    try:
        event_id = str(UUID(str(body.get("event_id", ""))))
    except (ValueError, TypeError, AttributeError):
        return jsonify(ok=False, message="event_id must be a UUID."), 400
    agent = str(body.get("agent", ""))[:64]
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", agent):
        return jsonify(ok=False, message="agent must use letters, numbers, dot, dash, or underscore."), 400
    operation = body.get("operation")
    if operation not in {"created", "modified", "deleted"}:
        return jsonify(ok=False, message="Unsupported file operation."), 400
    relative_path = _safe_endpoint_relative_path(body.get("path"))
    if relative_path is None:
        return jsonify(ok=False, message="path must be a safe relative path."), 400
    observed_at = datetime.now(timezone.utc)
    raw_observed_at = body.get("observed_at")
    if raw_observed_at is not None:
        if not isinstance(raw_observed_at, str):
            return jsonify(ok=False, message="observed_at must be an ISO 8601 timestamp."), 400
        try:
            parsed_observed_at = datetime.fromisoformat(raw_observed_at.replace("Z", "+00:00"))
        except ValueError:
            return jsonify(ok=False, message="observed_at must be an ISO 8601 timestamp."), 400
        if parsed_observed_at.tzinfo is None:
            return jsonify(ok=False, message="observed_at must include a timezone."), 400
        observed_at = parsed_observed_at.astimezone(timezone.utc)
        if observed_at > datetime.now(timezone.utc) + timedelta(minutes=5):
            return jsonify(ok=False, message="observed_at cannot be more than five minutes in the future."), 400
    # event_id lives on MonitoringEvent; query explicitly to make retries idempotent.
    existing = MonitoringEvent.query.filter_by(event_id=event_id).first()
    if existing:
        return jsonify(ok=True, duplicate=True), 202
    device = None
    if body.get("device_id"):
        device, error = _upsert_agent_device(owner, body, event=True)
        if error:
            return error
    db.session.add(MonitoringEvent(
        user_id=owner.id,
        event_id=event_id, event_type=f"file_{operation}", severity="info",
        details=f"Agent {agent}: {operation} {relative_path}"[:500], risk_score=0, source="agent",
        file_activity=[{"operation": operation, "path": relative_path,
                        **({"device_id": device.device_id} if device else {})}],
        created_at=observed_at,
    ))
    db.session.commit()
    burst_alert = evaluate_agent_window(agent, owner.id)
    return jsonify(ok=True, duplicate=False, evaluated=True, alert_created=burst_alert), 202


@api.get("/agent/health")
def agent_health():
    """Verify the agent token and configured owner without creating sample data."""
    owner, error = _authenticated_agent_owner()
    if error:
        return error
    return jsonify(ok=True, message="Endpoint agent is ready."), 200


@api.post("/agent/heartbeat")
@csrf.exempt
def agent_heartbeat():
    owner, error = _authenticated_agent_owner()
    if error:
        return error
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(ok=False, message="Expected a JSON heartbeat."), 400
    device, error = _upsert_agent_device(owner, body)
    if error:
        return error
    db.session.commit()
    return jsonify(ok=True, device_id=device.device_id), 200


@api.get("/agent/commands")
@csrf.exempt
def agent_commands():
    owner, error = _authenticated_agent_owner()
    if error:
        return error
    device_id = _agent_device_id(request.args.get("device_id"))
    device = db.session.get(AgentDevice, device_id) if device_id else None
    if device is None or device.user_id != owner.id:
        return jsonify(ok=False, message="Endpoint device is not registered to this account."), 404
    now = datetime.now(timezone.utc)
    device.last_seen_at = now
    expired_before = now - timedelta(minutes=10)
    stale = (AgentCommand.query.filter_by(device_id=device.device_id, user_id=owner.id, status="pending")
             .filter(AgentCommand.created_at < expired_before).all())
    for command in stale:
        command.status = "expired"
        command.result = {"message": "Command expired before the endpoint received it."}
        command.completed_at = now
    commands = (AgentCommand.query.filter_by(device_id=device.device_id, user_id=owner.id, status="pending")
                .filter(AgentCommand.created_at >= expired_before)
                .order_by(AgentCommand.created_at.asc()).limit(20).all())
    db.session.commit()
    return jsonify(ok=True, commands=[command.to_dict() for command in commands]), 200


@api.post("/agent/commands/<command_id>/result")
@csrf.exempt
def agent_command_result(command_id):
    owner, error = _authenticated_agent_owner()
    if error:
        return error
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or body.get("status") not in {"completed", "failed"}:
        return jsonify(ok=False, message="status must be completed or failed."), 400
    device_id = _agent_device_id(body.get("device_id"))
    command = db.session.get(AgentCommand, command_id)
    if not command or command.user_id != owner.id or command.device_id != device_id:
        return jsonify(ok=False, message="Command was not found for this device."), 404
    if command.status in {"completed", "failed"}:
        return jsonify(ok=True, duplicate=True, command=command.to_dict()), 200
    result = body.get("result", {})
    if not isinstance(result, dict) or len(json.dumps(result)) > 4000:
        return jsonify(ok=False, message="Command result must be an object under 4 KB."), 400
    if body["status"] == "completed":
        expected_path = (command.payload or {}).get("path")
        if command.action == "quarantine":
            key = result.get("quarantine_key", "")
            if (result.get("status") != "quarantined" or result.get("path") != expected_path
                    or type(result.get("size_bytes")) is not int or result["size_bytes"] < 0
                    or not re.fullmatch(r"[0-9a-f]{64}", str(result.get("sha256", "")))
                    or not str(key).startswith(command.command_id + "/")):
                return jsonify(ok=False, message="Completed quarantine result does not match the request."), 400
        elif command.action == "restore":
            if (result.get("status") != "restored" or result.get("path") != expected_path
                    or type(result.get("size_bytes")) is not int or result["size_bytes"] < 0
                    or not re.fullmatch(r"[0-9a-f]{64}", str(result.get("sha256", "")))):
                return jsonify(ok=False, message="Completed restore result does not match the request."), 400
        else:
            return jsonify(ok=False, message="Unsupported completed command."), 400
    elif not isinstance(result.get("message", ""), str):
        return jsonify(ok=False, message="Failed command details must be text."), 400
    command.status = body["status"]
    command.result = result
    command.completed_at = datetime.now(timezone.utc)
    device = db.session.get(AgentDevice, command.device_id)
    if device:
        device.last_seen_at = command.completed_at
    db.session.add(AuditLog(user_id=owner.id, action="endpoint_command_completed",
                            details={"device_id": command.device_id, "command_id": command.command_id,
                                     "command": command.action, "status": command.status}))
    db.session.commit()
    return jsonify(ok=True, duplicate=False, command=command.to_dict()), 200


@api.post("/browser-folder/events")
@login_required
def browser_folder_events():
    """Persist metadata-only changes reported by a user's browser folder watcher."""
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("events"), list):
        return jsonify(ok=False, message="Expected an events list."), 400
    folder_id = str(body.get("folder_id", ""))
    try:
        folder_id = str(UUID(folder_id))
    except (ValueError, TypeError, AttributeError):
        return jsonify(ok=False, message="folder_id must be a UUID."), 400
    raw_folder_name = body.get("folder_name", "Selected folder")
    if not isinstance(raw_folder_name, str):
        return jsonify(ok=False, message="folder_name must be a string."), 400
    folder_name = re.sub(r"[\x00-\x1f\x7f]", "", raw_folder_name).strip()[:30] or "Selected folder"
    batch = body["events"]
    if not batch or len(batch) > 100:
        return jsonify(ok=False, message="Send between 1 and 100 events per request."), 400

    accepted = 0
    seen_ids = set()
    prepared = []
    for item in batch:
        if not isinstance(item, dict):
            return jsonify(ok=False, message="Each event must be an object."), 400
        try:
            event_id = str(UUID(str(item.get("event_id", ""))))
        except (ValueError, TypeError, AttributeError):
            return jsonify(ok=False, message="event_id must be a UUID."), 400
        operation = item.get("operation")
        raw_path = item.get("path", "")
        if not isinstance(operation, str) or operation not in {"created", "modified", "deleted"}:
            return jsonify(ok=False, message="Unsupported file operation."), 400
        if not isinstance(raw_path, str):
            return jsonify(ok=False, message="path must be a string."), 400
        relative_path = raw_path.replace("\\", "/")
        if (not relative_path or len(relative_path) > 400 or relative_path.startswith("/")
                or any(part in {"", ".", ".."} for part in relative_path.split("/"))):
            return jsonify(ok=False, message="path must be a safe relative path."), 400
        if event_id in seen_ids or MonitoringEvent.query.filter_by(event_id=event_id).first():
            continue
        seen_ids.add(event_id)
        prepared.append((event_id, operation, relative_path))

    for event_id, operation, relative_path in prepared:
        db.session.add(MonitoringEvent(
            user_id=current_user.id,
            event_id=event_id,
            event_type=f"file_{operation}",
            severity="info",
            details=f"Browser folder {folder_id} ({folder_name}): {operation} {relative_path}"[:500],
            file_activity=[{"operation": operation, "path": relative_path}],
            risk_score=0,
            source="browser",
        ))
        accepted += 1

    db.session.commit()
    alert_created = evaluate_browser_folder_window(folder_id, folder_name, current_user.id) if accepted else False
    if accepted:
        record_audit("folder_activity_received", folder=folder_name, events=accepted, alert_created=alert_created)
        db.session.commit()
    return jsonify(ok=True, accepted=accepted, alert_created=alert_created), 202


def evaluate_browser_folder_window(folder_id: str, folder_name: str, user_id: int) -> bool:
    """Apply the published rolling burst rules to one authenticated browser folder."""
    now = datetime.now(timezone.utc)
    policy = current_app.extensions["monitoring_service"].policy
    window_seconds = policy["window_seconds"]
    cutoff = now - timedelta(seconds=window_seconds)
    prefix = f"Browser folder {folder_id} ({folder_name}): "
    events = MonitoringEvent.query.filter(
        MonitoringEvent.source == "browser",
        MonitoringEvent.user_id == user_id,
        MonitoringEvent.created_at >= cutoff,
    ).all()
    paths = {"created": set(), "modified": set(), "deleted": set()}
    for event in events:
        if not event.details.startswith(prefix):
            continue
        operation = event.event_type.removeprefix("file_")
        if operation in paths:
            paths[operation].add(event.details.removeprefix(f"{prefix}{operation} "))
    created, modified, deleted = (paths[key] for key in ("created", "modified", "deleted"))
    total = len(created | modified | deleted)
    destructive = len(modified | deleted)
    if not (len(deleted) >= policy["delete_threshold"]
            or len(modified) >= policy["modify_threshold"]
            or (total >= policy["mixed_threshold"]
                and destructive >= policy["mixed_destructive_minimum"])):
        return False
    if Alert.query.filter_by(user_id=user_id, model_version="browser-folder-burst-v1").filter(
            Alert.created_at >= now - timedelta(seconds=60)).first():
        return False
    risk = min(100, round(100 * max(len(deleted) / policy["delete_threshold"],
                                   len(modified) / policy["modify_threshold"],
                                   total / policy["mixed_threshold"])))
    severe = (len(deleted) >= 2 * policy["delete_threshold"]
              or len(modified) >= 2 * policy["modify_threshold"]
              or (total >= 2 * policy["mixed_threshold"]
                  and destructive >= 2 * policy["mixed_destructive_minimum"]))
    current_app.extensions["monitoring_service"]._persist_alert(
        "Browser folder file-change burst",
        (f"Browser folder {folder_name} reported {total} distinct file changes in {window_seconds} seconds "
         f"({len(created)} created, {len(modified)} modified, {len(deleted)} deleted). "
         "Review this activity; this rule is an anomaly signal, not a malware verdict."),
        "high" if severe else "medium", max(risk, 60), created | modified | deleted,
        model_version="browser-folder-burst-v1", owner_id=user_id,
        file_activity=[
            {"path": path, "operations": [operation for operation, paths_for_operation in paths.items()
                                           if path in paths_for_operation]}
            for path in sorted(created | modified | deleted)
        ],
        extra_rule_trace=[{"signal": "selected_folder_id", "value": folder_id},
                          {"signal": "selected_folder_name", "value": folder_name}],
    )
    return True


def evaluate_agent_window(agent: str, user_id: int) -> bool:
    """Evaluate persisted agent events so separate cloud instances share state."""
    now = datetime.now(timezone.utc)
    policy = current_app.extensions["monitoring_service"].policy
    window_seconds = policy["window_seconds"]
    cutoff = now - timedelta(seconds=window_seconds)
    agent_prefix = f"Agent {agent}: "
    events = (MonitoringEvent.query.filter(
        MonitoringEvent.source == "agent",
        MonitoringEvent.user_id == user_id,
        MonitoringEvent.created_at >= cutoff,
    ).all())
    paths = {"created": set(), "modified": set(), "deleted": set()}
    for event in events:
        if not event.details.startswith(agent_prefix):
            continue
        operation = event.event_type.removeprefix("file_")
        if operation in paths:
            operation_prefix = f"{agent_prefix}{operation} "
            if event.details.startswith(operation_prefix):
                paths[operation].add(event.details.removeprefix(operation_prefix))
    created, modified, deleted = (paths[key] for key in ("created", "modified", "deleted"))
    total = len(created | modified | deleted)
    destructive = len(modified | deleted)
    burst = (len(deleted) >= policy["delete_threshold"]
             or len(modified) >= policy["modify_threshold"]
             or (total >= policy["mixed_threshold"]
                 and destructive >= policy["mixed_destructive_minimum"]))
    if not burst:
        return False
    last_alert = Alert.query.filter_by(user_id=user_id, model_version="endpoint-agent-burst-v1").filter(
        Alert.created_at >= now - timedelta(seconds=60)
    ).first()
    if last_alert:
        return False
    risk = min(100, round(100 * max(len(deleted) / policy["delete_threshold"],
                                   len(modified) / policy["modify_threshold"],
                                   total / policy["mixed_threshold"])))
    severe = (len(deleted) >= 2 * policy["delete_threshold"]
              or len(modified) >= 2 * policy["modify_threshold"]
              or (total >= 2 * policy["mixed_threshold"]
                  and destructive >= 2 * policy["mixed_destructive_minimum"]))
    monitor = current_app.extensions["monitoring_service"]
    monitor._persist_alert(
        "Remote endpoint file-change burst",
        (f"Agent {agent} reported {total} distinct file changes in {window_seconds} seconds "
         f"({len(created)} created, {len(modified)} modified, {len(deleted)} deleted). "
         "Review this activity; this rule is an anomaly signal, not a malware verdict."),
        "high" if severe else "medium", max(risk, 60), created | modified | deleted,
        model_version="endpoint-agent-burst-v1",
        owner_id=user_id,
        file_activity=[
            {"path": path, "operations": [operation for operation, paths_for_operation in paths.items()
                                           if path in paths_for_operation]}
            for path in sorted(created | modified | deleted)
        ],
    )
    return True


@api.errorhandler(413)
def upload_too_large(error):
    return jsonify(ok=False, message="Upload exceeds the 5 MB request limit."), 413


@api.get("/datasets/mlran.csv")
@login_required
def mlran_dataset():
    return send_file(Path(current_app.root_path).parent / "data/mlran/heldout.csv", as_attachment=True, download_name="mlran_heldout.csv")


@api.get("/datasets/telemetry-template.csv")
@login_required
def telemetry_template():
    from .detector import FEATURE_NAMES

    stream = io.StringIO(newline="")
    csv.writer(stream, lineterminator="\n").writerow(
        ["trace_id", "window_index", "label", *FEATURE_NAMES]
    )
    return Response(stream.getvalue(), mimetype="text/csv", headers={
        "Content-Disposition": 'attachment; filename="ransomshield-telemetry-template.csv"',
        "Cache-Control": "no-store",
    })


@api.post("/runs/mlran")
@login_required
def run_mlran():
    from .mlran import SOURCE
    path = Path(current_app.root_path).parent / "data/mlran/heldout.csv"
    with path.open("rb") as stream:
        run = execute(current_app, start_run(current_app, current_user.id, "dataset"),
                      FileStorage(stream=stream, filename="mlran_heldout.csv"), "MLRan cleaned held-out samples", SOURCE)
    record_audit("dataset_analysis", run_id=run.id, status=run.status, dataset_name="MLRan cleaned held-out samples")
    db.session.commit()
    return run_response(run)


@api.post("/runs/silrad")
@login_required
def run_silrad():
    """Evaluate only the publisher's held-out SILRAD split for this run."""
    from .silrad import SOURCE
    dataset_dir = Path(current_app.config["SILRAD_DATA_DIR"])
    model_path = dataset_dir / "incremental_metadata.json"
    test_path = dataset_dir / "fasttext-testmodel.csv"
    preparation = current_app.extensions["silrad_preparation"]
    if not model_path.is_file() or not test_path.is_file() or not preparation.status().get("ready"):
        return jsonify(ok=False, message="Prepare the RansomShield Online Benchmark on this server first."), 409
    run = start_run(current_app, current_user.id, "silrad")
    with test_path.open("rb") as stream:
        run = execute(current_app, run, FileStorage(stream=stream, filename="fasttext-testmodel.csv"),
                      "RansomShield Online Benchmark (published SILRAD data)", SOURCE)
    record_audit("dataset_analysis", run_id=run.id, status=run.status, dataset_name="RansomShield Online Benchmark (published SILRAD data)")
    db.session.commit()
    return run_response(run)


@api.get("/silrad/status")
@login_required
def silrad_status():
    return jsonify(current_app.extensions["silrad_preparation"].status())


@api.post("/silrad/prepare")
@login_required
def prepare_silrad():
    preparation = current_app.extensions["silrad_preparation"]
    started = preparation.start()
    status = preparation.status()
    if status.get("ready"):
        return jsonify(ok=True, message="RansomShield Online Benchmark is already prepared.", **status)
    if not started:
        return jsonify(ok=True, message="RansomShield Online Benchmark preparation is already running.", **status), 202
    return jsonify(ok=True, message="Preparing the RansomShield benchmark with published data.", **status), 202


def get_monitor():
    return current_app.extensions["monitoring_service"]


@api.get("/monitor/status")
@login_required
def monitor_status():
    monitor = get_monitor()
    public_model_path = Path(current_app.root_path) / "artifacts/mlran/model.json"
    telemetry_model_path = Path(current_app.root_path) / "artifacts/behavioral_model.json"
    public_model = json.loads(public_model_path.read_text(encoding="utf-8")) if public_model_path.exists() else {}
    telemetry_model = json.loads(telemetry_model_path.read_text(encoding="utf-8")) if telemetry_model_path.exists() else {}
    status = monitor.status()
    if monitor.is_running and not monitor.owned_by(current_user.id):
        status = {
            "running": False,
            "connection_state": "In use by another account" if monitor.is_running else "Stopped",
            "model_state": "Rolling burst rules",
            "target": "Not assigned to this account", "interval_seconds": status["interval_seconds"],
            "policy": status["policy"],
            "reconcile_seconds": status["reconcile_seconds"], "auto_quarantine": False,
            "cpu_percent": 0, "memory_percent": 0, "process_count": 0, "last_check": None,
            "last_successful_scan": None, "last_risk_score": 0, "monitored_files": 0,
            "dropped_events": 0, "queue_depth": 0, "collector": "poll", "last_activity": {},
        }
    status["quarantine_location"] = str(Path(current_app.config["QUARANTINE_PATH"]).resolve())
    return jsonify(
        {
            "status": status,
            "event_count": MonitoringEvent.query.filter_by(user_id=current_user.id).count(),
            "alert_count": visible_alerts().filter(Alert.resolved_at.is_(None)).count(),
            "model": {key: telemetry_model.get(key) for key in
                      ("display_name", "trained_at", "training", "metrics", "decision_threshold")},
            "live_policy": {
                "name": "Rolling file-burst rules",
                "window_seconds": status["policy"]["window_seconds"],
                "alert_thresholds": {
                    "deleted_files": status["policy"]["delete_threshold"],
                    "modified_files": status["policy"]["modify_threshold"],
                    "mixed_changes": status["policy"]["mixed_threshold"],
                    "mixed_change_minimum_modified_or_deleted": status["policy"]["mixed_destructive_minimum"],
                },
                "score_type": "heuristic activity score; not a probability",
                "automatic_quarantine": status["policy"]["auto_quarantine"],
            },
            "published_model": {key: public_model.get(key) for key in ("display_name", "trained_at", "training", "metrics", "limitations")},
        }
    )


@api.get("/devices")
@login_required
def list_devices():
    now = datetime.now(timezone.utc)
    devices = AgentDevice.query.filter_by(user_id=current_user.id).order_by(AgentDevice.last_seen_at.desc()).all()
    commands = (AgentCommand.query.filter_by(user_id=current_user.id)
                .order_by(AgentCommand.created_at.desc()).limit(500).all())
    restores = {command.payload.get("quarantine_command_id") for command in commands
                if command.action == "restore" and command.status == "completed"}
    remote_items = []
    for command in commands:
        if command.action != "quarantine":
            continue
        result = command.result or {}
        if command.status not in {"pending", "completed", "failed", "expired"}:
            continue
        if command.status == "completed" and result.get("status") != "quarantined":
            continue
        remote_items.append({
            **command.to_dict(), "restored": command.command_id in restores,
            "device_label": next((device.label for device in devices if device.device_id == command.device_id), "Endpoint"),
            "display_destination": "Local quarantine on endpoint · not uploaded to server",
        })
    return jsonify(devices=[{
        **device.to_dict(),
        "status": "online" if (now - device.last_seen_at.replace(tzinfo=device.last_seen_at.tzinfo or timezone.utc)).total_seconds() <= 90 else "offline",
        "pending_commands": AgentCommand.query.filter_by(device_id=device.device_id, status="pending")
            .filter(AgentCommand.created_at >= now - timedelta(minutes=10)).count(),
    } for device in devices], quarantine=remote_items)


@api.post("/agents/<device_id>/quarantine/<int:alert_id>")
@login_required
def queue_endpoint_quarantine(device_id, alert_id):
    normalized_id = _agent_device_id(device_id)
    device = db.session.get(AgentDevice, normalized_id) if normalized_id else None
    if device is None or device.user_id != current_user.id:
        return jsonify(ok=False, message="Endpoint device not found."), 404
    alert = db.session.get(Alert, alert_id)
    check_alert_owner(alert_id)
    if not alert or alert.resolved_at is not None or alert.model_version != "endpoint-agent-burst-v1":
        return jsonify(ok=False, message="Choose an open endpoint-agent alert."), 409
    body = request.get_json(silent=True)
    path = body.get("path") if isinstance(body, dict) else None
    safe_path = _safe_endpoint_relative_path(path)
    if safe_path is None:
        return jsonify(ok=False, message="Choose a safe relative path from the alert."), 400
    signal = next((entry for entry in (alert.rule_trace or [])
                   if isinstance(entry, dict) and entry.get("signal") == "affected_files"), None)
    paths = {str(item.get("path", "")).replace("\\", "/")
             for item in (signal or {}).get("value", []) if isinstance(item, dict)}
    agent_match = re.match(r"^Agent ([A-Za-z0-9._-]{1,64}) reported", alert.details or "")
    if not agent_match or device.label != agent_match.group(1) or safe_path not in paths:
        return jsonify(ok=False, message="The selected file is not part of this endpoint alert."), 400
    evidence = next((item for item in (signal or {}).get("value", [])
                     if isinstance(item, dict) and str(item.get("path", "")).replace("\\", "/") == safe_path), {})
    if "deleted" in (evidence.get("operations") or []):
        return jsonify(ok=False, message="This alert records a deletion for the path. Deleted files cannot be quarantined safely."), 409
    last_seen = device.last_seen_at.replace(tzinfo=device.last_seen_at.tzinfo or timezone.utc)
    if (datetime.now(timezone.utc) - last_seen).total_seconds() > 90:
        return jsonify(ok=False, message="This endpoint is offline. Start its agent before requesting quarantine."), 409
    pending = AgentCommand.query.filter_by(device_id=device.device_id, action="quarantine", status="pending").all()
    if any(command.payload.get("path") == safe_path for command in pending):
        return jsonify(ok=False, message="A quarantine request for this path is already pending."), 409
    command = AgentCommand(command_id=str(uuid4()), device_id=device.device_id,
                           user_id=current_user.id, action="quarantine",
                           payload={"path": safe_path, "alert_id": alert.id})
    db.session.add(command)
    record_audit("endpoint_quarantine_requested", alert_id=alert.id,
                 device_id=device.device_id, path=safe_path)
    db.session.commit()
    return jsonify(ok=True, message="Quarantine request queued. The endpoint must be online; check its result in Devices.",
                   command=command.to_dict(), destination="Local quarantine on the selected endpoint; file contents stay on that device."), 202


@api.post("/devices/<device_id>/quarantine/<quarantine_command_id>/restore")
@login_required
def queue_endpoint_restore(device_id, quarantine_command_id):
    normalized_id = _agent_device_id(device_id)
    device = db.session.get(AgentDevice, normalized_id) if normalized_id else None
    if device is None or device.user_id != current_user.id:
        return jsonify(ok=False, message="Endpoint device not found."), 404
    item = db.session.get(AgentCommand, quarantine_command_id)
    if (not item or item.user_id != current_user.id or item.device_id != device.device_id
            or item.action != "quarantine" or item.status != "completed"
            or (item.result or {}).get("status") != "quarantined"):
        return jsonify(ok=False, message="Quarantined endpoint file not found."), 404
    commands = AgentCommand.query.filter_by(device_id=device.device_id, user_id=current_user.id, action="restore").all()
    if any(command.payload.get("quarantine_command_id") == item.command_id and command.status != "failed"
           for command in commands):
        return jsonify(ok=False, message="A restore request already exists for this item."), 409
    last_seen = device.last_seen_at.replace(tzinfo=device.last_seen_at.tzinfo or timezone.utc)
    if (datetime.now(timezone.utc) - last_seen).total_seconds() > 90:
        return jsonify(ok=False, message="This endpoint is offline. Start its agent before requesting restore."), 409
    command = AgentCommand(command_id=str(uuid4()), device_id=device.device_id, user_id=current_user.id,
                           action="restore", payload={"quarantine_command_id": item.command_id,
                                                       "quarantine_key": (item.result or {}).get("quarantine_key", ""),
                                                       "path": item.payload.get("path", ""),
                                                       "expected_sha256": (item.result or {}).get("sha256", ""),
                                                       "expected_size_bytes": (item.result or {}).get("size_bytes")})
    db.session.add(command)
    record_audit("endpoint_restore_requested", device_id=device.device_id,
                 quarantine_command_id=item.command_id)
    db.session.commit()
    return jsonify(ok=True, message="Restore request queued. Check Devices for the result.", command=command.to_dict()), 202


@api.post("/monitor/policy")
@login_required
def update_monitor_policy():
    monitor = get_monitor()
    if monitor.is_running and not monitor.owned_by(current_user.id):
        return jsonify(ok=False, message="Only the account using the server monitor can change its settings."), 409
    body = request.get_json(silent=True)
    try:
        policy = monitor.update_policy(body)
    except RuntimeError as exc:
        return jsonify(ok=False, message=str(exc)), 409
    except (TypeError, ValueError) as exc:
        return jsonify(ok=False, message=str(exc)), 422
    record_audit("monitor_policy_updated", policy=policy)
    db.session.commit()
    return jsonify(ok=True, message="Server monitor settings saved.", policy=policy)


@api.post("/monitor/policy/simulate")
@login_required
def simulate_monitor_policy():
    """Replay recent labeled file changes through proposed thresholds without saving them."""
    body = request.get_json(silent=True)
    monitor = get_monitor()
    try:
        policy = monitor.validate_policy({**(body or {}), "auto_quarantine": monitor.policy["auto_quarantine"]})
    except (TypeError, ValueError) as exc:
        return jsonify(ok=False, message=str(exc)), 422
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    rows = (MonitoringEvent.query.filter_by(user_id=current_user.id)
            .filter(MonitoringEvent.created_at >= cutoff,
                    MonitoringEvent.event_type.in_(["file_created", "file_modified", "file_deleted"]))
            .order_by(MonitoringEvent.created_at.asc()).limit(20_000).all())
    streams = {}
    for event in rows:
        if event.source == "agent":
            match = re.match(r"^Agent ([A-Za-z0-9._-]{1,64}):", event.details or "")
            stream = "agent:" + (match.group(1) if match else "unknown")
        elif event.source == "browser":
            match = re.match(r"^Browser folder ([0-9a-f-]{36})", event.details or "", re.IGNORECASE)
            stream = "browser:" + (match.group(1).lower() if match else "unknown")
        else:
            stream = "server"
        at = event.created_at.replace(tzinfo=event.created_at.tzinfo or timezone.utc).timestamp()
        activity = event.file_activity or []
        if not activity:
            operation = event.event_type.removeprefix("file_")
            detail = (event.details or "").rsplit(": ", 1)[-1]
            activity = [{"operation": operation, "path": detail}]
        bucket = streams.setdefault(stream, [])
        for change in activity:
            operation, path = change.get("operation"), change.get("path")
            if operation in {"created", "modified", "deleted"} and isinstance(path, str) and path:
                bucket.append((at, operation, path))

    candidate_count = 0
    windows_checked = 0
    for changes in streams.values():
        active = deque()
        counts = {"created": Counter(), "modified": Counter(), "deleted": Counter()}
        active_paths = Counter()
        destructive_paths = set()
        last_candidate = float("-inf")
        for at, operation, path in changes:
            active.append((at, operation, path))
            counts[operation][path] += 1
            active_paths[path] += 1
            if operation in {"modified", "deleted"}:
                destructive_paths.add(path)
            while active and active[0][0] < at - policy["window_seconds"]:
                _, old_operation, old_path = active.popleft()
                counts[old_operation][old_path] -= 1
                if counts[old_operation][old_path] <= 0:
                    del counts[old_operation][old_path]
                active_paths[old_path] -= 1
                if active_paths[old_path] <= 0:
                    del active_paths[old_path]
                if old_operation in {"modified", "deleted"} and not (
                        counts["modified"].get(old_path) or counts["deleted"].get(old_path)):
                    destructive_paths.discard(old_path)
            windows_checked += 1
            crossed = (len(counts["deleted"]) >= policy["delete_threshold"]
                       or len(counts["modified"]) >= policy["modify_threshold"]
                       or (len(active_paths) >= policy["mixed_threshold"]
                           and len(destructive_paths) >= policy["mixed_destructive_minimum"]))
            if crossed and at - last_candidate >= 60:
                candidate_count += 1
                last_candidate = at
    return jsonify(ok=True, period_hours=24, events_replayed=sum(len(items) for items in streams.values()),
                   streams=len(streams), windows_checked=windows_checked,
                   would_alert_count=candidate_count, policy=policy,
                   note="This replays saved activity only. It cannot tell false alarms from attacks because live events have no verified labels.")


@api.post("/monitor/start")
@login_required
def start_monitor():
    monitor = get_monitor()
    if monitor.is_running and not monitor.owned_by(current_user.id):
        return jsonify(ok=False, message="The shared monitor is in use by another account. Stop it from that account before starting yours."), 409
    started = monitor.start(owner_id=current_user.id)
    if not monitor.owned_by(current_user.id):
        return jsonify(ok=False, message="The monitor was claimed by another account. Refresh and try again."), 409
    record_audit("monitor_started", target="app-server folder", already_running=not started)
    db.session.commit()
    return jsonify(
        {
            "ok": True,
            "message": "Monitoring started." if started else "Monitoring is already running.",
            "status": monitor.status(),
        }
    )


@api.post("/monitor/stop")
@login_required
def stop_monitor():
    monitor = get_monitor()
    if monitor.is_running and not monitor.owned_by(current_user.id):
        return jsonify(ok=False, message="Only the account that started monitoring can stop it."), 403
    stopped = monitor.stop(owner_id=current_user.id)
    record_audit("monitor_stopped", already_stopped=not stopped)
    db.session.commit()
    return jsonify(
        {
            "ok": True,
            "message": "Monitoring stopped." if stopped else "Monitoring is already stopped.",
            "status": monitor.status(),
        }
    )


def run_response(run):
    ok = run.status == "completed"
    return jsonify(ok=ok, message=f"Run {run.id}: {run.result.get('model_prediction', run.status)}",
                   run=run.to_dict()), 200 if ok else 422


@api.post("/runs/dataset")
@login_required
def run_dataset():
    upload = request.files.get("dataset")
    if not upload or not upload.filename.lower().endswith(".csv"):
        return jsonify(ok=False, message="Select a safe .csv telemetry dataset."), 400
    name = request.form.get("dataset_name", "Uploaded telemetry")[:200]
    source = request.form.get("source", "User-provided CSV; provenance unverified")[:500]
    run = execute(current_app, start_run(current_app, current_user.id, "dataset"), upload, name, source)
    record_audit("dataset_analysis", run_id=run.id, status=run.status, dataset_name=name[:100])
    db.session.commit()
    response, code = run_response(run)
    if code != 200:
        return jsonify(ok=False, message=run.result["error"], run=run.to_dict()), code
    return response, code


@api.get("/runs")
@login_required
def list_runs():
    runs = AnalysisRun.query.filter_by(user_id=current_user.id).order_by(AnalysisRun.created_at.desc()).limit(30).all()
    # Keep polling light; detailed predictions are available on each run.
    items = []
    for run in runs:
        item = run.to_dict()
        item["result"] = {k: v for k, v in item["result"].items() if k != "predictions"}
        items.append(item)
    return jsonify(runs=items)


def owned_run(run_id):
    run = db.get_or_404(AnalysisRun, run_id)
    if run.user_id != current_user.id:
        abort(404)
    return run


@api.get("/runs/<run_id>")
@login_required
def run_details(run_id):
    return jsonify(run=owned_run(run_id).to_dict())


def csv_download(rows, filename):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    for row in rows:
        writer.writerow([("'" + str(v)) if str(v).lstrip().startswith(("=", "+", "-", "@")) else v for v in row])
    return Response(stream.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@api.get("/runs/<run_id>/report.csv")
@login_required
def run_report(run_id):
    run = owned_run(run_id)
    response = run.alert.to_dict()["response"] if run.alert else None
    rows = [["run_id", "alert_id", "timestamp", "status", "risk_score", "model_prediction", "observed_file_activity", "quarantine_results", "notification_status"],
            [run.id, run.alert_id or "", run.to_dict()["created_at"], run.status, run.result.get("risk_score", ""),
             run.result.get("model_prediction", ""), json.dumps(run.result.get("observed_file_activity", {})),
             (response or {}).get("quarantine", "incomplete" if run.status != "completed" else "not_required"), json.dumps((response or {}).get("notifications", {}))],
            [], ["evaluation_metadata", json.dumps({k:v for k,v in run.result.items() if k != "predictions"})]]
    rows.extend([[], ["trace_id", "window_index", "actual_label", "model_prediction", "probability", "observed_file_activity"]])
    for prediction in run.result.get("predictions", []):
        rows.append([prediction["trace_id"], prediction["window_index"], prediction["label"], prediction["prediction"],
                     prediction["probability"], json.dumps(prediction["observed_activity"])])
    rows.extend([[], ["file", "quarantine_result", "destination", "error"]])
    for item in (response or {}).get("files", []):
        rows.append([item["source"], item["status"], item.get("destination", ""), item.get("error", "")])
    return csv_download(rows, f"ransomshield-{run.id}.csv")


@api.get("/runs/<run_id>/predictions.csv")
@login_required
def run_predictions(run_id):
    run = owned_run(run_id)
    if run.kind != "silrad":
        abort(404)
    path = Path(current_app.config["RUNS_PATH"]) / run.id / "predictions.csv"
    if not path.is_file():
        abort(404)
    return send_file(path, as_attachment=True, download_name=f"ransomshield-silrad-{run.id}-predictions.csv",
                     mimetype="text/csv", max_age=0)


@api.get("/alerts/<int:alert_id>/report.csv")
@login_required
def incident_report(alert_id):
    alert = db.get_or_404(Alert, alert_id)
    check_alert_owner(alert_id)
    run = AnalysisRun.query.filter_by(alert_id=alert_id).first()
    if run:
        return run_report(run.id)
    return csv_download([["alert_id", "timestamp", "risk_score", "model_prediction", "observed_file_activity", "quarantine_results", "notification_status"],
                         [alert.id, alert.to_dict()["created_at"], alert.risk_score, "suspicious", alert.details,
                          json.dumps(alert.to_dict()["response"]), json.dumps((alert.to_dict()["response"] or {}).get("notifications", {}))]], f"incident-{alert.id}.csv")


@api.get("/quarantine")
@login_required
def list_quarantine():
    owned_run_alerts = db.select(AnalysisRun.alert_id).where(
        AnalysisRun.user_id == current_user.id, AnalysisRun.alert_id.isnot(None))
    owned_live_alerts = db.select(Alert.id).where(Alert.user_id == current_user.id)
    items = (QuarantineItem.query.filter(or_(QuarantineItem.alert_id.in_(owned_live_alerts),
                                            QuarantineItem.alert_id.in_(owned_run_alerts)))
             .order_by(QuarantineItem.quarantined_at.desc()).limit(100).all())
    return jsonify(items=[item.to_dict() for item in items])


@api.post("/alerts/<int:alert_id>/quarantine")
@login_required
def quarantine_alert_file_route(alert_id: int):
    alert = db.get_or_404(Alert, alert_id)
    check_alert_owner(alert_id)
    if alert.resolved_at is not None:
        return jsonify(ok=False, message="Reopen the alert before quarantining a file."), 409
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("path"), str):
        return jsonify(ok=False, message="Choose a file path listed in this alert."), 400

    from .response import quarantine_alert_file
    monitored_root = Path(current_app.config["MONITOR_TARGET_PATH"])
    try:
        item = quarantine_alert_file(current_app, alert, monitored_root, body["path"])
    except (OSError, ValueError) as exc:
        return jsonify(ok=False, message=str(exc)), 422

    monitor = get_monitor()
    monitor.note_quarantined_file(item.original_path)
    record_audit("file_quarantined", alert_id=alert.id, path=item.original_path,
                 scope="server_folder")
    db.session.commit()
    return jsonify(ok=True, message=f"Moved {item.original_path} to quarantine. You can restore it from Email & history.",
                   item=item.to_dict(), alert=alert.to_dict())


@api.post("/quarantine/<int:item_id>/restore")
@login_required
def restore_item(item_id: int):
    item = db.get_or_404(QuarantineItem, item_id)
    check_alert_owner(item.alert_id)
    from .response import restore_quarantine
    try:
        restore_quarantine(current_app, item, Path(current_app.config["MONITOR_TARGET_PATH"]))
    except (OSError, ValueError) as exc:
        return jsonify(ok=False, message=str(exc), item=item.to_dict()), 422
    return jsonify(ok=True, message=f"Restored {item.original_path}.", item=item.to_dict())


@api.get("/notifications")
@login_required
def notification_configuration():
    config = current_app.config
    email_state = "disabled for this account" if not current_user.email_notifications_enabled else (
        "configured" if (current_user.email and config["SMTP_HOST"]
        and config["RESPONSE_EMAIL_FROM"]
        and config.get("SMTP_SECURITY", "starttls") in ("starttls", "ssl")
        and (not config["SMTP_USERNAME"] or config["SMTP_PASSWORD"])) else "incomplete")
    return jsonify(webhook="configured" if current_app.config["RESPONSE_WEBHOOK_URL"] else "disabled",
                   email=email_state,
                   email_recipient="signed-in account",
                   email_enabled=current_user.email_notifications_enabled,
                   configuration="Configure SMTP_HOST, SMTP_PORT, SMTP_SECURITY, SMTP_USERNAME, SMTP_PASSWORD and RESPONSE_EMAIL_FROM in the project .env file. Alerts go to the email on the signed-in account; RESPONSE_EMAIL_TO is only a fallback for alerts without an account owner. Restart the app after changing SMTP settings. Use starttls (587) or ssl (465). Secrets are never displayed. Configured does not mean delivery verified.")


@api.post("/notifications/email")
@login_required
def update_email_notifications():
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("enabled"), bool):
        return jsonify(ok=False, message="enabled must be true or false."), 400
    current_user.email_notifications_enabled = body["enabled"]
    record_audit("settings_changed", setting="email_notifications_enabled", enabled=body["enabled"])
    db.session.commit()
    return jsonify(ok=True, enabled=current_user.email_notifications_enabled,
                   message="Email alerts enabled for this account." if body["enabled"] else "Email alerts disabled for this account.")


@api.get("/events")
@login_required
def list_events(limit_override=None):
    limit = (limit_override if limit_override is not None
             else min(max(request.args.get("limit", 10, type=int), 1), 50))
    query = MonitoringEvent.query.filter_by(user_id=current_user.id)
    source = request.args.get("source", "").strip().lower()
    if source:
        if source not in {"poll", "browser", "agent"}:
            return jsonify(ok=False, message="Unknown activity source."), 400
        query = query.filter(MonitoringEvent.source == source)
    action = request.args.get("action", "").strip().lower()
    if action:
        if action not in {"created", "modified", "deleted"}:
            return jsonify(ok=False, message="action must be created, modified, or deleted."), 400
        query = query.filter(MonitoringEvent.event_type == f"file_{action}")
    device = request.args.get("device", "").strip()
    if device:
        owned_device = AgentDevice.query.filter_by(user_id=current_user.id, device_id=device).first()
        if owned_device is None:
            return jsonify(ok=False, message="Choose a device from your account."), 404
        escaped_label = owned_device.label.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.filter(MonitoringEvent.source == "agent",
                             MonitoringEvent.details.like(f"Agent {escaped_label}: %", escape="\\"))

    def parse_time(value, name):
        if not value:
            return None
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            raise ValueError(f"{name} must be an ISO date or timestamp.")
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)

    try:
        after = parse_time(request.args.get("after"), "after")
        before = parse_time(request.args.get("before"), "before")
    except ValueError as exc:
        return jsonify(ok=False, message=str(exc)), 400
    if after:
        query = query.filter(MonitoringEvent.created_at >= after)
    if before:
        query = query.filter(MonitoringEvent.created_at <= before)
    # Browser folder events are stored one row per file so burst rules can count
    # distinct paths. Present nearby changes from one folder scan as a single
    # readable activity row, matching the server-folder monitor's UI.
    rows = query.order_by(MonitoringEvent.created_at.desc()).limit(min(limit * 100, 5000)).all()
    grouped = []
    browser_groups = {}
    browser_event = re.compile(r"^Browser folder ([0-9a-f-]{36}) \((.*?)\): ", re.IGNORECASE)

    def event_timestamp(event):
        created = event.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return created.timestamp()

    for event in reversed(rows):
        match = browser_event.match(event.details or "") if event.source == "browser" else None
        if not match:
            grouped.append(event.to_dict())
            continue

        folder_id, folder_name = match.groups()
        activity = event.file_activity or []
        if not activity:
            legacy = re.match(r"^(created|modified|deleted) (.+)$", (event.details or "")[match.end():])
            if legacy:
                activity = [{"operation": legacy.group(1), "path": legacy.group(2)}]
        timestamp = event_timestamp(event)
        key = folder_id.lower()
        current = browser_groups.get(key)
        if current is None or timestamp - current["last_timestamp"] > 2.5:
            current = {
                "id": f"browser-{key}-{event.id}",
                "event_id": None,
                "event_type": "file_activity",
                "severity": "info",
                "source": "browser",
                "risk_score": 0,
                "folder_name": folder_name,
                "created_at": utc_isoformat(event.created_at),
                "last_timestamp": timestamp,
                "file_activity": [],
                "counts": {"created": 0, "modified": 0, "deleted": 0},
            }
            browser_groups[key] = current
            grouped.append(current)
        current["last_timestamp"] = timestamp
        current["created_at"] = utc_isoformat(event.created_at)
        for change in activity:
            operation = change.get("operation")
            path = change.get("path")
            if operation not in current["counts"] or not isinstance(path, str) or not path:
                continue
            current["file_activity"].append({"operation": operation, "path": path})
            current["counts"][operation] += 1

    result = []
    for item in grouped:
        if item.get("source") == "browser" and item.get("event_type") == "file_activity":
            counts = item.pop("counts")
            item.pop("last_timestamp", None)
            item["file_activity"].sort(key=lambda change: (change["operation"], change["path"].casefold()))
            total = len(item["file_activity"])
            item["details"] = (
                f"Browser folder ({item.pop('folder_name')}): {total} changes "
                f"({counts['created']} created, {counts['modified']} modified, {counts['deleted']} deleted)."
            )
            result.append(item)
        else:
            result.append(item)
    result.sort(key=lambda item: item["created_at"], reverse=True)
    return jsonify({"events": result[:limit]})


@api.get("/events/export.csv")
@login_required
def export_events_csv():
    # Reuse the same account-scoped filters and browser-folder grouping as the UI.
    response = list_events(limit_override=5000)
    if response.status_code >= 400:
        return response
    grouped = response.get_json()
    if grouped is None or not isinstance(grouped, dict) or "events" not in grouped:
        return jsonify(ok=False, message="Could not export the selected activity."), 400
    rows = [["timestamp", "source", "action", "path", "summary", "severity"]]
    for event in grouped["events"]:
        files = event.get("file_activity") or []
        if files:
            for item in files:
                rows.append([event.get("created_at", ""), event.get("source", ""),
                             item.get("operation", ""), item.get("path", ""),
                             event.get("details", ""), event.get("severity", "")])
        else:
            rows.append([event.get("created_at", ""), event.get("source", ""),
                         event.get("event_type", ""), "", event.get("details", ""),
                         event.get("severity", "")])
    return csv_download(rows, "ransomshield-activity.csv")


@api.get("/alerts")
@login_required
def list_alerts():
    limit = min(max(request.args.get("limit", 10, type=int), 1), 50)
    query = visible_alerts()
    state = request.args.get("status", "all")
    if state == "open":
        query = query.filter(Alert.resolved_at.is_(None))
    elif state == "resolved":
        query = query.filter(Alert.resolved_at.isnot(None))
    elif state != "all":
        return jsonify(ok=False, message="status must be open, resolved, or all."), 400
    severity = request.args.get("severity")
    if severity:
        if severity not in {"low", "medium", "high", "critical"}:
            return jsonify(ok=False, message="Unknown severity filter."), 400
        query = query.filter(Alert.severity == severity)
    alerts = query.order_by(Alert.created_at.desc()).limit(limit).all()
    return jsonify({"alerts": [alert.to_dict() for alert in alerts]})


@api.post("/alerts/<int:alert_id>/acknowledge")
@login_required
def acknowledge_alert(alert_id: int):
    alert = db.get_or_404(Alert, alert_id)
    check_alert_owner(alert_id)
    alert.acknowledged = True
    record_audit("alert_acknowledged", alert_id=alert.id)
    db.session.commit()
    return jsonify({"ok": True, "alert": alert.to_dict()})


@api.post("/alerts/<int:alert_id>/resolve")
@login_required
def resolve_alert(alert_id: int):
    alert = db.get_or_404(Alert, alert_id)
    check_alert_owner(alert_id)
    if alert.resolved_at is None:
        alert.resolved_at = datetime.now(timezone.utc)
        alert.acknowledged = True
        record_audit("alert_resolved", alert_id=alert.id)
        db.session.commit()
    return jsonify(ok=True, alert=alert.to_dict())


@api.post("/alerts/<int:alert_id>/retry-email")
@login_required
def retry_alert_email(alert_id: int):
    alert = db.get_or_404(Alert, alert_id)
    check_alert_owner(alert_id)
    action = next(iter(alert.responses), None)
    if action is None:
        return jsonify(ok=False, message="This alert has no notification record to retry."), 409
    if (action.result or {}).get("notifications", {}).get("email") != "failed":
        return jsonify(ok=False, message="Email retry is available only after a failed attempt."), 409
    from .response import retry_alert_email as retry_email
    sent = retry_email(current_app, alert, action)
    record_audit("alert_email_retried", alert_id=alert.id, status="sent" if sent else "failed")
    db.session.commit()
    return jsonify(ok=sent, message="Email accepted by SMTP." if sent else "Email retry failed. Check SMTP configuration and server logs.",
                   alert=alert.to_dict()), 200 if sent else 502


@api.get("/audit")
@login_required
def list_audit():
    limit = min(max(request.args.get("limit", 50, type=int), 1), 100)
    entries = (AuditLog.query.filter_by(user_id=current_user.id)
               .order_by(AuditLog.created_at.desc()).limit(limit).all())
    return jsonify(entries=[entry.to_dict() for entry in entries])


def visible_alerts():
    owned_run_alerts = db.select(AnalysisRun.alert_id).where(
        AnalysisRun.user_id == current_user.id, AnalysisRun.alert_id.isnot(None))
    return Alert.query.filter(or_(Alert.user_id == current_user.id, Alert.id.in_(owned_run_alerts)))


def check_alert_owner(alert_id):
    alert = db.session.get(Alert, alert_id)
    run = AnalysisRun.query.filter_by(alert_id=alert_id).first()
    if not alert or (alert.user_id != current_user.id and (not run or run.user_id != current_user.id)):
        abort(404)
