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
from .models import Alert, MonitoringEvent, AnalysisRun, QuarantineItem, User
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
    return run_response(run)


@api.post("/runs/silrad")
@login_required
def run_silrad():
    """Evaluate only the publisher's held-out SILRAD split for this run."""
    from .silrad import SOURCE
    dataset_dir = Path(current_app.config["SILRAD_DATA_DIR"])
    model_path = dataset_dir / "metadata.json"
    test_path = dataset_dir / "fasttext-testmodel.csv"
    preparation = current_app.extensions["silrad_preparation"]
    if not model_path.is_file() or not test_path.is_file() or not preparation.status().get("ready"):
        return jsonify(ok=False, message="Prepare the SILRAD benchmark on this server first."), 409
    run = start_run(current_app, current_user.id, "silrad")
    with test_path.open("rb") as stream:
        run = execute(current_app, run, FileStorage(stream=stream, filename="fasttext-testmodel.csv"),
                      "SILRAD publisher-provided held-out test split", SOURCE)
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
        return jsonify(ok=True, message="SILRAD benchmark is already prepared.", **status)
    if not started:
        return jsonify(ok=True, message="SILRAD benchmark preparation is already running.", **status), 202
    return jsonify(ok=True, message="Preparing SILRAD data and model on this server.", **status), 202


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
    if not monitor.owned_by(current_user.id):
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
            "alert_count": visible_alerts().filter_by(acknowledged=False).count(),
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
    email_state = "disabled"
    if config["RESPONSE_EMAIL_TO"]:
        email_state = "configured" if (config["SMTP_HOST"] and config["RESPONSE_EMAIL_FROM"]
            and config.get("SMTP_SECURITY", "starttls") in ("starttls", "ssl")
            and (not config["SMTP_USERNAME"] or config["SMTP_PASSWORD"])) else "incomplete"
    return jsonify(webhook="configured" if current_app.config["RESPONSE_WEBHOOK_URL"] else "disabled",
                   email=email_state,
                   configuration="Fill SMTP_HOST, SMTP_PORT, SMTP_SECURITY, SMTP_USERNAME, SMTP_PASSWORD, RESPONSE_EMAIL_FROM and RESPONSE_EMAIL_TO in the project .env file. Restart the app and receiver. Use starttls (587) or ssl (465). Secrets are never displayed. Configured does not mean delivery verified.")


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
    alerts = visible_alerts().order_by(Alert.created_at.desc()).limit(limit).all()
    return jsonify({"alerts": [alert.to_dict() for alert in alerts]})


@api.post("/alerts/<int:alert_id>/acknowledge")
@login_required
def acknowledge_alert(alert_id: int):
    alert = db.get_or_404(Alert, alert_id)
    check_alert_owner(alert_id)
    alert.acknowledged = True
    db.session.commit()
    return jsonify({"ok": True, "alert": alert.to_dict()})


def visible_alerts():
    owned_run_alerts = db.select(AnalysisRun.alert_id).where(
        AnalysisRun.user_id == current_user.id, AnalysisRun.alert_id.isnot(None))
    return Alert.query.filter(or_(Alert.user_id == current_user.id, Alert.id.in_(owned_run_alerts)))


def check_alert_owner(alert_id):
    alert = db.session.get(Alert, alert_id)
    run = AnalysisRun.query.filter_by(alert_id=alert_id).first()
    if not alert or (alert.user_id != current_user.id and (not run or run.user_id != current_user.id)):
        abort(404)
