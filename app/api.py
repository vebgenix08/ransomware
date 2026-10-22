import csv
import io
import json
import hmac
import re
from datetime import datetime, timedelta, timezone
from uuid import UUID
from pathlib import Path
from flask import Blueprint, current_app, jsonify, request, Response, abort, send_file
from flask_login import login_required, current_user
from sqlalchemy import or_
from werkzeug.datastructures import FileStorage

from .extensions import csrf, db
from .models import Alert, MonitoringEvent, AnalysisRun, QuarantineItem, User, AuditLog
from .audit import record_audit
from .runs import start_run, execute


api = Blueprint("api", __name__, url_prefix="/api")


@api.post("/agent/events")
@csrf.exempt
def agent_event():
    """Accept bounded file activity summaries from a trusted endpoint agent."""
    token = current_app.config.get("AGENT_API_TOKEN", "")
    supplied = request.headers.get("Authorization", "")
    supplied = supplied.removeprefix("Bearer ")
    if not token or not hmac.compare_digest(supplied, token):
        return jsonify(ok=False, message="Agent authentication failed."), 401
    owner_email = current_app.config.get("AGENT_OWNER_EMAIL", "").strip().lower()
    owner = User.query.filter_by(email=owner_email).first() if owner_email else None
    if owner is None:
        return jsonify(ok=False, message="Endpoint agent owner is not configured."), 503
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
    relative_path = str(body.get("path", "")).replace("\\", "/")
    if (not relative_path or len(relative_path) > 400 or relative_path.startswith("/")
            or any(part in {"", ".", ".."} for part in relative_path.split("/"))):
        return jsonify(ok=False, message="path must be a safe relative path."), 400
    # event_id lives on MonitoringEvent; query explicitly to make retries idempotent.
    existing = MonitoringEvent.query.filter_by(event_id=event_id).first()
    if existing:
        return jsonify(ok=True, duplicate=True), 202
    db.session.add(MonitoringEvent(
        user_id=owner.id,
        event_id=event_id, event_type=f"file_{operation}", severity="info",
        details=f"Agent {agent}: {operation} {relative_path}"[:500], risk_score=0, source="agent",
    ))
    db.session.commit()
    burst_alert = evaluate_agent_window(agent, owner.id)
    return jsonify(ok=True, duplicate=False, evaluated=True, alert_created=burst_alert), 202


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
    cutoff = now - timedelta(seconds=30)
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
    if not (len(deleted) >= 10 or len(modified) >= 20 or (total >= 30 and destructive >= 10)):
        return False
    if Alert.query.filter_by(user_id=user_id, model_version="browser-folder-burst-v1").filter(
            Alert.created_at >= now - timedelta(seconds=60)).first():
        return False
    risk = min(100, round(100 * max(len(deleted) / 10, len(modified) / 20, total / 30)))
    severe = len(deleted) >= 20 or len(modified) >= 40 or (total >= 60 and destructive >= 20)
    current_app.extensions["monitoring_service"]._persist_alert(
        "Browser folder file-change burst",
        (f"Browser folder {folder_name} reported {total} distinct file changes in 30 seconds "
         f"({len(created)} created, {len(modified)} modified, {len(deleted)} deleted). "
         "Review this activity; this rule is an anomaly signal, not a malware verdict."),
        "high" if severe else "medium", max(risk, 60), created | modified | deleted,
        model_version="browser-folder-burst-v1", owner_id=user_id,
        file_activity=[
            {"path": path, "operations": [operation for operation, paths_for_operation in paths.items()
                                           if path in paths_for_operation]}
            for path in sorted(created | modified | deleted)
        ],
    )
    return True


def evaluate_agent_window(agent: str, user_id: int) -> bool:
    """Evaluate persisted agent events so separate cloud instances share state."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=30)
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
    burst = (len(deleted) >= 10 or len(modified) >= 20
             or (total >= 30 and destructive >= 10))
    if not burst:
        return False
    last_alert = Alert.query.filter_by(user_id=user_id, model_version="endpoint-agent-burst-v1").filter(
        Alert.created_at >= now - timedelta(seconds=60)
    ).first()
    if last_alert:
        return False
    risk = min(100, round(100 * max(len(deleted) / 10, len(modified) / 20, total / 30)))
    severe = (len(deleted) >= 20 or len(modified) >= 40
              or (total >= 60 and destructive >= 20))
    monitor = current_app.extensions["monitoring_service"]
    monitor._persist_alert(
        "Remote endpoint file-change burst",
        (f"Agent {agent} reported {total} distinct file changes in 30 seconds "
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
            "reconcile_seconds": status["reconcile_seconds"], "auto_quarantine": False,
            "cpu_percent": 0, "memory_percent": 0, "process_count": 0, "last_check": None,
            "last_successful_scan": None, "last_risk_score": 0, "monitored_files": 0,
            "dropped_events": 0, "queue_depth": 0, "collector": "poll", "last_activity": {},
        }
    return jsonify(
        {
            "status": status,
            "event_count": MonitoringEvent.query.filter_by(user_id=current_user.id).count(),
            "alert_count": visible_alerts().filter(Alert.resolved_at.is_(None)).count(),
            "model": {key: telemetry_model.get(key) for key in
                      ("display_name", "trained_at", "training", "metrics", "decision_threshold")},
            "live_policy": {
                "name": "Rolling file-burst rules",
                "window_seconds": 30,
                "alert_thresholds": {
                    "deleted_files": 10,
                    "modified_files": 20,
                    "mixed_changes": 30,
                    "mixed_change_minimum_modified_or_deleted": 10,
                },
                "score_type": "heuristic activity score; not a probability",
                "automatic_quarantine": False,
            },
            "published_model": {key: public_model.get(key) for key in ("display_name", "trained_at", "training", "metrics", "limitations")},
        }
    )


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
def list_events():
    limit = min(max(request.args.get("limit", 10, type=int), 1), 50)
    events = (MonitoringEvent.query.filter_by(user_id=current_user.id)
              .order_by(MonitoringEvent.created_at.desc()).limit(limit).all())
    return jsonify({"events": [event.to_dict() for event in events]})


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
