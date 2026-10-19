"""Persistent, isolated safe simulations and frozen-model CSV evaluation."""
import csv
from pathlib import Path
from uuid import uuid4

from .detector import FEATURE_NAMES
from .extensions import db
from .models import Alert, AnalysisRun
from .monitor import CANARY_NAMES, DISPOSABLE_NAMES, create_safe_demo_files, seed_decoy_server, take_snapshot
from .response import respond
from .mlran import evaluate_dataset as evaluate


def start_run(app, user_id, kind):
    run = AnalysisRun(id=str(uuid4()), user_id=user_id, kind=kind, result={})
    db.session.add(run)
    db.session.commit()
    return run


def execute(app, run, upload=None, dataset_name="Safe simulation", source="locally generated"):
    try:
        root = Path(app.config["RUNS_PATH"]).resolve() / run.id
        root.mkdir(parents=True, exist_ok=False)
        csv_path = root / "input.csv"
        samples = root / "test_files"
        samples.mkdir()
        affected = set()
        if upload is not None:
            upload.save(csv_path)
        else:
            seed_decoy_server(samples)
            before = take_snapshot(samples)
            create_safe_demo_files(samples, run.id)
            after = take_snapshot(samples)
            created, deleted = set(after) - set(before), set(before) - set(after)
            modified = {p for p in set(before) & set(after) if before[p] != after[p]}
            # The disposable .tmp files are removed on purpose to simulate a
            # ransomware burst; they were never quarantinable and must not be
            # reported as failed response moves.
            intentional = {path for path in deleted if path in DISPOSABLE_NAMES}
            affected = (created | modified | deleted) - intentional
            features = dict(created_count=len(created), modified_count=len(modified), deleted_count=len(deleted),
                            cpu_percent=0, memory_percent=0, process_count=0,
                            canary_accessed=int(bool(affected & CANARY_NAMES)),
                            canary_modified=int(bool(modified & CANARY_NAMES)),
                            decoy_files_touched=len(affected),
                            directories_touched=len({Path(p).parts[0] for p in affected}), operation_rate=len(affected)/2)
            with csv_path.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=["trace_id", "window_index", "label", *FEATURE_NAMES])
                writer.writeheader()
                writer.writerow(dict(trace_id=run.id, window_index=0, label=1, **features))
        report = evaluate(csv_path, Path(app.root_path)/"artifacts/behavioral_model.json", dataset_name, source)
        if run.result.get("transfer"):
            report["transfer"] = run.result["transfer"]
        suspicious = [p for p in report["predictions"] if p["prediction"] == 1]
        report["risk_score"] = round(max(p["probability"] for p in report["predictions"]) * 100)
        report["model_prediction"] = "suspicious" if suspicious else "benign"
        if report.get("dataset_schema") == "mlran":
            report["observed_file_activity"] = {"samples": len(report["predictions"]),
                "samples_with_file_indicators": sum(bool(p["observed_activity"]["active_file_indicators"]) for p in report["predictions"])}
        else:
            report["observed_file_activity"] = {name: sum(p["observed_activity"][name] for p in report["predictions"])
                                                 for name in ("created_count", "modified_count", "deleted_count", "decoy_files_touched")}
        report["quarantine_scope"] = "Generated test placeholders only; CSV paths are never acted on."
        if upload is None:
            report["limitations"].append("Controlled simulation: resource values are synthetic; file counts are observed. Not an external benchmark.")
        if suspicious:
            if upload is not None:
                for index, prediction in enumerate(suspicious):
                    name = f"window_{index:04d}.txt"
                    (samples/name).write_text(f"Harmless stand-in for CSV window {prediction['window_index']}; no executable content.\n", encoding="utf-8")
                    affected.add(name)
            alert = Alert(title=f"Suspicious {run.kind} activity", severity="high" if report["risk_score"] >= 85 else "medium",
                          risk_score=report["risk_score"], details=f"Run {run.id}: {len(suspicious)} of {report['windows']} {report.get('record_unit', 'windows')} classified suspicious by {report.get('model_name', 'TCN + XGBoost')}.")
            db.session.add(alert)
            db.session.flush()
            run.alert_id = alert.id
            run.result = report
            db.session.commit()
            respond(app, alert, samples, affected)
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
    return run
