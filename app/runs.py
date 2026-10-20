"""Persistent dataset evaluation using the frozen, schema-matched model."""
from pathlib import Path
from uuid import uuid4

from .extensions import db
from .models import Alert, AnalysisRun
from .response import respond
from .mlran import evaluate_dataset as evaluate


def start_run(app, user_id, kind):
    run = AnalysisRun(id=str(uuid4()), user_id=user_id, kind=kind, result={})
    db.session.add(run)
    db.session.commit()
    return run


def execute(app, run, upload, dataset_name="Uploaded telemetry", source="User-provided CSV; provenance unverified"):
    try:
        root = Path(app.config["RUNS_PATH"]).resolve() / run.id
        root.mkdir(parents=True, exist_ok=False)
        if run.kind == "silrad":
            from .silrad import evaluate_test
            # Use the prepared local file directly; do not copy the 70+ MB
            # public test split into every run's private working directory.
            csv_path = Path(app.instance_path) / "silrad" / "fasttext-testmodel.csv"
            report = evaluate_test(csv_path, Path(app.instance_path) / "silrad",
                                   predictions_csv=root / "predictions.csv")
            report["dataset"] = dataset_name
        else:
            csv_path = root / "input.csv"
            upload.save(csv_path)
            report = evaluate(csv_path, Path(app.root_path)/"artifacts/behavioral_model.json", dataset_name, source)
        from .models import ModelRegistry
        from .registry import _sha256
        if report.get("dataset_schema") == "silrad":
            artifact = Path(app.instance_path) / "silrad" / "xgboost.json"
            model_label = f"{report['model_name']}@{_sha256(artifact)[:12]}"
        else:
            artifact = Path(app.root_path)/("artifacts/mlran/model.json" if report.get("dataset_schema") == "mlran" else "artifacts/behavioral_model.json")
            record = ModelRegistry.query.filter_by(artifact_sha256=_sha256(artifact)).first()
            model_label = f"{record.display_name}@{record.artifact_sha256[:12]}" if record else "unregistered"
        report["model_version"] = model_label
        if run.result.get("transfer"):
            report["transfer"] = run.result["transfer"]
        if report.get("dataset_schema") == "silrad":
            suspicious_count = report["suspicious_count"]
            report["risk_score"] = round(report["max_probability"] * 100)
            report["model_prediction"] = "suspicious" if suspicious_count else "benign"
            report["observed_file_activity"] = {"sysmon_events": report["windows"],
                                                 "suspicious_events": suspicious_count}
        else:
            suspicious = [p for p in report["predictions"] if p["prediction"] == 1]
            suspicious_count = len(suspicious)
            report["risk_score"] = round(max(p["probability"] for p in report["predictions"]) * 100)
            report["model_prediction"] = "suspicious" if suspicious else "benign"
        if report.get("dataset_schema") == "mlran":
            report["observed_file_activity"] = {"samples": len(report["predictions"]),
                "samples_with_file_indicators": sum(bool(p["observed_activity"]["active_file_indicators"]) for p in report["predictions"])}
        elif report.get("dataset_schema") != "silrad":
            report["observed_file_activity"] = {name: sum(p["observed_activity"][name] for p in report["predictions"])
                                                 for name in ("created_count", "modified_count", "deleted_count", "decoy_files_touched")}
        report["quarantine_scope"] = "No files were moved from a dataset evaluation. CSV path fields are never acted on."
        if suspicious_count:
            alert = Alert(title=f"{run.kind.replace('_', ' ').title()} run flagged samples", severity="high" if report["risk_score"] >= 85 else "medium",
                          risk_score=report["risk_score"], model_version=model_label,
                          rule_trace=[{"signal": "model_probability", "value": report["risk_score"]},
                                      {"signal": "suspicious_windows", "value": suspicious_count},
                                      {"signal": "total_samples", "value": report["windows"]},
                                      {"signal": "dataset_name", "value": dataset_name},
                                      {"signal": "dataset_source", "value": source}],
                          details=f"Run {run.id}: {suspicious_count} of {report['windows']} {report.get('record_unit', 'windows')} classified suspicious by {report.get('model_name', 'TCN + XGBoost')}.")
            db.session.add(alert)
            db.session.flush()
            run.alert_id = alert.id
            run.result = report
            db.session.commit()
            # Dataset records have no trusted mapping to local files. Alert and
            # notify, but never create stand-ins or move unrelated user files.
            respond(app, alert, root, set())
        run.result = report
        run.status = "completed"
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        run.status = "failed"
        previous = dict(run.result or {})
        previous["error"] = str(exc) if isinstance(exc, (ValueError, UnicodeError)) else "Run failed; see server logs."
        run.result = previous
        db.session.commit()
        app.logger.exception("Analysis run %s failed", run.id)
    finally:
        # Multipart request bodies may be spooled to a temporary file. Release
        # the upload stream immediately after saving/evaluating it.
        upload.close()
    return run
