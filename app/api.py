import csv
import io
import json
import hashlib
from uuid import uuid4
from pathlib import Path
from flask import Blueprint, current_app, jsonify, request, Response, abort, send_file
from flask_login import login_required, current_user
from werkzeug.datastructures import FileStorage

from .extensions import db
from .models import Alert, MonitoringEvent, AnalysisRun
from .runs import start_run, execute


api = Blueprint("api", __name__, url_prefix="/api")


@api.errorhandler(413)
def upload_too_large(error):
    return jsonify(ok=False, message="Upload exceeds the 5 MB request limit."), 413


@api.get("/datasets/sample.csv")
@login_required
def sample_dataset():
    return send_file(Path(current_app.root_path).parent / "data/safe_demo.csv", as_attachment=True, download_name="safe_demo.csv")


@api.get("/datasets/mlran.csv")
@login_required
def mlran_dataset():
    return send_file(Path(current_app.root_path).parent / "data/mlran/heldout.csv", as_attachment=True, download_name="mlran_heldout.csv")


@api.post("/runs/mlran")
@login_required
def run_mlran():
    from .mlran import SOURCE
    path = Path(current_app.root_path).parent / "data/mlran/heldout.csv"
    with path.open("rb") as stream:
        run = execute(current_app, start_run(current_app, current_user.id, "dataset"),
                      FileStorage(stream=stream, filename="mlran_heldout.csv"), "MLRan cleaned held-out samples", SOURCE)
    return run_response(run)


@api.post("/runs/local-transfer")
@login_required
def local_transfer_demo():
    """Exercise sender snapshot -> inbox -> receiver using local files, not Wi-Fi."""
    from .mlran import SOURCE
    from .transfer import receive_one
    payload = (Path(current_app.root_path).parent / "data/mlran/heldout.csv").read_bytes()
    transfer_id = str(uuid4())
    inbox = Path(current_app.config["RUNS_PATH"]) / "local_transfer_inbox"
    inbox.mkdir(parents=True, exist_ok=True)
    (inbox / f"{transfer_id}.csv").write_bytes(payload)
    manifest = {"version": 1, "sha256": hashlib.sha256(payload).hexdigest(), "size_bytes": len(payload),
                "dataset_name": "MLRan — local sender/receiver demo", "source": SOURCE}
    part = inbox / f"{transfer_id}.ready.json.part"
    part.write_text(json.dumps(manifest), encoding="utf-8")
    ready = inbox / f"{transfer_id}.ready.json"
    part.replace(ready)
    run = receive_one(current_app, inbox, current_user.id, ready, transport="local_demo (no network transfer)")
    return run_response(run)


def get_monitor():
    return current_app.extensions["monitoring_service"]


@api.get("/monitor/status")
@login_required
def monitor_status():
    monitor = get_monitor()
    public_model_path = Path(current_app.root_path) / "artifacts/mlran/model.json"
    public_model = json.loads(public_model_path.read_text(encoding="utf-8")) if public_model_path.exists() else {}
    return jsonify(
        {
            "status": monitor.status(),
            "event_count": MonitoringEvent.query.count(),
            "alert_count": visible_alerts().filter_by(acknowledged=False).count(),
            "model": ({key: monitor.detector.model.get(key) for key in
                       ("display_name", "trained_at", "training", "metrics", "decision_threshold")}
                      if monitor.detector.is_ready else {"error": "Model unavailable"}),
            "published_model": {key: public_model.get(key) for key in ("display_name", "trained_at", "training", "metrics", "limitations")},
        }
    )


@api.post("/monitor/start")
@login_required
def start_monitor():
    monitor = get_monitor()
    started = monitor.start()
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
    stopped = monitor.stop()
    return jsonify(
        {
            "ok": True,
            "message": "Monitoring stopped." if stopped else "Monitoring is already stopped.",
            "status": monitor.status(),
        }
    )


@api.post("/monitor/demo")
@login_required
def run_safe_demo():
    run = execute(current_app, start_run(current_app, current_user.id, "simulation"))
    return run_response(run)


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


@api.get("/alerts/<int:alert_id>/report.csv")
@login_required
def incident_report(alert_id):
    alert = db.get_or_404(Alert, alert_id)
    run = AnalysisRun.query.filter_by(alert_id=alert_id).first()
    if run:
        return run_report(run.id)
    return csv_download([["alert_id", "timestamp", "risk_score", "model_prediction", "observed_file_activity", "quarantine_results", "notification_status"],
                         [alert.id, alert.to_dict()["created_at"], alert.risk_score, "suspicious", alert.details,
                          json.dumps(alert.to_dict()["response"]), json.dumps((alert.to_dict()["response"] or {}).get("notifications", {}))]], f"incident-{alert.id}.csv")


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
    events = MonitoringEvent.query.order_by(MonitoringEvent.created_at.desc()).limit(limit).all()
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
    hidden = db.select(AnalysisRun.alert_id).where(AnalysisRun.user_id != current_user.id, AnalysisRun.alert_id.isnot(None))
    return Alert.query.filter(Alert.id.notin_(hidden))


def check_alert_owner(alert_id):
    run = AnalysisRun.query.filter_by(alert_id=alert_id).first()
    if run and run.user_id != current_user.id:
        abort(404)
