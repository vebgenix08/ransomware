"""Consume completed SFTP CSV uploads without executing any uploaded content."""
import hashlib
import io
import json
import os
import stat
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy.exc import IntegrityError
from werkzeug.datastructures import FileStorage

from .extensions import db
from .models import AnalysisRun
from .runs import execute

MAX_CSV_BYTES = 5 * 1024 * 1024


def read_regular(path, limit):
    """Bound reads and exclude links/reparse points in the dedicated inbox."""
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("Only regular, non-linked upload files are accepted")
    if info.st_size > limit:
        raise ValueError("Upload exceeds its size limit")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino) or not stat.S_ISREG(opened.st_mode):
            raise ValueError("Upload changed while opening; resend using a new transfer ID")
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise ValueError("Upload exceeds its size limit")
    return content


def receipt(run):
    incident = run.alert.to_dict() if run.alert else None
    response = (incident or {}).get("response") or {}
    return {"transfer_id": run.id, "run_id": run.id, "status": run.status,
            "error": run.result.get("error"), "dataset_sha256": run.result.get("dataset_sha256"),
            "prediction": run.result.get("model_prediction"), "risk_score": run.result.get("risk_score"),
            "metrics": run.result.get("metrics"), "incident_id": run.alert_id,
            "quarantine_status": response.get("quarantine", "not_required" if run.status == "completed" else "incomplete"),
            "quarantined_files": sum(f["status"] == "quarantined" for f in response.get("files", [])),
            "notifications": response.get("notifications", {}),
            "report_path": f"/api/runs/{run.id}/report.csv"}


def write_receipt(inbox, run):
    target = inbox / f"{run.id}.result.json"
    temporary = inbox / f".{run.id}.{uuid4().hex}.tmp"
    # Publish atomically so Laptop 1 never downloads an incomplete JSON result.
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(receipt(run), stream, indent=2, allow_nan=False)
    os.replace(temporary, target)


def receive_one(app, inbox, user_id, manifest_path, transport="SFTP inbox"):
    inbox = Path(inbox).resolve(strict=True)
    manifest_path = Path(manifest_path)
    if manifest_path.parent.resolve() != inbox or not manifest_path.name.endswith(".ready.json"):
        raise ValueError("Manifest must be in the configured inbox")
    transfer_id = manifest_path.name.removesuffix(".ready.json")
    if str(UUID(transfer_id)) != transfer_id:
        raise ValueError("Transfer filename must contain a canonical UUID")
    run = db.session.get(AnalysisRun, transfer_id)
    if run:
        if run.user_id != user_id or run.kind != "laptop_transfer":
            raise ValueError("Transfer ID already belongs to another run")
        if run.status != "running":
            write_receipt(inbox, run)
        return run
    run = AnalysisRun(id=transfer_id, user_id=user_id, kind="laptop_transfer", result={})
    db.session.add(run)
    try:
        # The primary key also prevents two receiver processes running the same upload.
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return None
    try:
        manifest = json.loads(read_regular(manifest_path, 16 * 1024))
        if not isinstance(manifest, dict) or manifest.get("version") != 1:
            raise ValueError("Unsupported transfer manifest")
        expected_hash = manifest.get("sha256")
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            raise ValueError("Missing SHA-256 checksum")
        payload = read_regular(inbox / f"{transfer_id}.csv", MAX_CSV_BYTES)
        digest = hashlib.sha256(payload).hexdigest()
        if digest != expected_hash or manifest.get("size_bytes") != len(payload):
            raise ValueError("Transfer integrity check failed; resend using a new transfer ID")
        dataset_name = manifest.get("dataset_name", "Laptop 1 CSV")
        source = manifest.get("source", "Laptop 1; source not independently verified")
        if not isinstance(dataset_name, str) or not isinstance(source, str):
            raise ValueError("Dataset name and source must be text")
        run.result = {"transfer": {"id": transfer_id, "transport": transport,
                                   "sha256": digest, "size_bytes": len(payload), "integrity": "verified"}}
        db.session.commit()
        upload = FileStorage(stream=io.BytesIO(payload), filename="dataset.csv")
        execute(app, run, upload, dataset_name[:200], source[:500])
    except (OSError, ValueError, TypeError) as exc:
        run.status = "failed"
        run.result = {**run.result, "error": str(exc)}
        db.session.commit()
    write_receipt(inbox, run)
    return run
