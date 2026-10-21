"""Audited containment of files in the configured decoy directory."""
import hashlib
import json
import os
import smtplib
import ssl
import stat
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from urllib.request import Request, urlopen

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.attributes import flag_modified

from .extensions import db
from .models import QuarantineItem, ResponseAction


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _format_alert_email(alert, result, app_name: str) -> tuple[str, str]:
    """Build a readable email and explain whether the alert is dataset or live."""
    trace = {item.get("signal"): item.get("value") for item in (alert.rule_trace or [])}
    model_version = alert.model_version or ""
    files_moved = sum(item.get("status") == "quarantined" for item in result.get("files", []))
    lines = ["RansomShield notification", f"Application: {app_name}", "", alert.title, "", f"Severity: {alert.severity.title()}"]

    if "suspicious_windows" in trace:
        count = trace.get("suspicious_windows", "unknown")
        total = trace.get("total_samples", "unknown")
        dataset = trace.get("dataset_name")
        source = trace.get("dataset_source")
        lines.extend([
            "Analysis type: Offline CSV dataset evaluation",
            f"Records flagged by the model: {count} of {total}",
            f"Dataset: {dataset}" if dataset else f"Model: {model_version}",
            f"Source: {source}" if source else None,
            f"Highest per-record model score: {alert.risk_score}/100",
            "This result describes rows in the evaluated CSV. It does not mean a monitored computer is infected.",
        ])
        if alert.details:
            lines.append(f"Run details: {alert.details}")
    elif model_version.startswith(("rolling-file-burst", "browser-folder-burst", "endpoint-agent-burst")):
        lines.extend([
            "Analysis type: Live monitored-folder activity",
            "A rolling file-change rule crossed its review threshold.",
            f"Activity score: {alert.risk_score}/100 (heuristic, not a probability)",
            alert.details,
            "This is an activity anomaly for review, not confirmation of malware.",
        ])
    else:
        lines.extend([f"Details: {alert.details}", f"Model or rule: {model_version or 'Not specified'}"])

    lines.extend([
        f"Alert ID: {alert.id}",
        f"Files moved to quarantine: {files_moved}",
        "Review this alert and its CSV report in the RansomShield dashboard.",
    ])
    if not files_moved:
        lines.append("No files were moved to quarantine.")

    if "suspicious_windows" in trace:
        subject = f"{app_name}: dataset analysis flagged records (alert #{alert.id})"
    elif model_version.startswith(("rolling-file-burst", "browser-folder-burst", "endpoint-agent-burst")):
        subject = f"{app_name}: file activity burst for review (alert #{alert.id})"
    else:
        subject = f"{app_name}: activity alert for review (alert #{alert.id})"
    return subject, "\n".join(line for line in lines if line)


def respond(app, alert, root, affected, quarantine_allowed=True):
    existing = ResponseAction.query.filter_by(alert_id=alert.id).first()
    if existing:
        return existing
    action = ResponseAction(alert_id=alert.id, result={"files": [], "notifications": {}})
    db.session.add(action)
    try:
        db.session.commit()
    except IntegrityError:
        # Another thread created the action for this alert first; use theirs.
        db.session.rollback()
        return ResponseAction.query.filter_by(alert_id=alert.id).one()
    result = action.result
    root = Path(root).resolve()
    quarantine = Path(app.config["QUARANTINE_PATH"]).resolve()
    if quarantine == root or root in quarantine.parents or quarantine in root.parents:
        raise ValueError("Quarantine and monitored directories must be separate")
    dry_run = app.config.get("QUARANTINE_MODE") == "dry-run"
    if app.config["AUTO_QUARANTINE"] and quarantine_allowed:
        destination = quarantine / str(alert.id)
        if not dry_run:
            destination.mkdir(parents=True, exist_ok=True)
            if destination.resolve() != destination:
                raise ValueError("Quarantine destination must not contain links")
        for name in sorted(affected):
            record = {"source": name}
            try:
                relative = Path(name)
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError("Unsafe relative path")
                source = root / relative
                resolved = source.resolve(strict=True)
                if root not in resolved.parents:
                    raise ValueError("Path escapes monitored directory")
                for part in (source, *source.parents):
                    if part == root:
                        break
                    info = part.lstat()
                    if part.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                        raise ValueError("Links and reparse points are excluded")
                if not stat.S_ISREG(source.stat().st_mode):
                    raise ValueError("Only regular files can be quarantined")
                target = destination / relative
                digest = sha256_file(source)
                size = source.stat().st_size
                if dry_run:
                    record.update(status="would_quarantine", destination=str(target), sha256=digest)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if target.parent.resolve() != target.parent:
                        raise ValueError("Quarantine destination must not contain links")
                    if target.exists():
                        raise ValueError("Destination already exists")
                    # Same-filesystem rename avoids copying partially modified files.
                    os.rename(source, target)
                    db.session.add(
                        QuarantineItem(
                            alert_id=alert.id,
                            original_path=relative.as_posix(),
                            quarantine_path=str(target),
                            sha256=digest,
                            size_bytes=size,
                        )
                    )
                    record.update(status="quarantined", destination=str(target), sha256=digest)
            except (OSError, ValueError) as exc:
                record.update(status="failed", error=str(exc))
            result["files"].append(record)
            action.result = dict(result)
            flag_modified(action, "result")
            db.session.commit()
    else:
        result["quarantine"] = "disabled" if not app.config["AUTO_QUARANTINE"] else "below_quarantine_threshold"
    if "quarantine" not in result:
        statuses = {item["status"] for item in result["files"]}
        if "would_quarantine" in statuses:
            result["quarantine"] = "dry_run"
        elif "failed" in statuses:
            result["quarantine"] = "partial_failure"
        else:
            result["quarantine"] = "quarantined" if result["files"] else "no_files"
    payload = {"alert": alert.to_dict(), "files": result["files"]}
    config = app.config
    for channel in ("webhook", "email"):
        enabled = bool(config["RESPONSE_WEBHOOK_URL"] if channel == "webhook" else config["RESPONSE_EMAIL_TO"])
        if not enabled:
            result["notifications"][channel] = "disabled"
            continue
        try:
            if channel == "webhook":
                url = config["RESPONSE_WEBHOOK_URL"]
                if not url.startswith("https://"):
                    raise ValueError("Webhook requires HTTPS")
                req = Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
                with urlopen(req, timeout=5) as response:
                    if not 200 <= response.status < 300:
                        raise ValueError("Webhook rejected notification")
            else:
                message = EmailMessage()
                app_name = config.get("APP_NAME", "RansomShield")
                subject, body = _format_alert_email(alert, result, app_name)
                message["Subject"] = subject
                message["From"] = config["RESPONSE_EMAIL_FROM"]
                message["To"] = config["RESPONSE_EMAIL_TO"]
                message.set_content(body)
                if not config["SMTP_HOST"] or not config["RESPONSE_EMAIL_FROM"]:
                    raise ValueError("SMTP host and sender are required")
                security = config.get("SMTP_SECURITY", "starttls")
                if security not in ("starttls", "ssl"):
                    raise ValueError("SMTP_SECURITY must be starttls or ssl")
                context = ssl.create_default_context()
                connection = (smtplib.SMTP_SSL(config["SMTP_HOST"], config["SMTP_PORT"], timeout=5, context=context)
                              if security == "ssl" else smtplib.SMTP(config["SMTP_HOST"], config["SMTP_PORT"], timeout=5))
                with connection as smtp:
                    if security == "starttls":
                        smtp.starttls(context=context)
                    if config["SMTP_USERNAME"]:
                        smtp.login(config["SMTP_USERNAME"], config["SMTP_PASSWORD"])
                    refused = smtp.send_message(message)
                    if isinstance(refused, dict) and refused:
                        raise ValueError("Some recipients were refused")
            result["notifications"][channel] = "sent"
        except Exception as exc:
            result["notifications"][channel] = "failed"
            # Keep credentials and message contents out of logs, but retain the
            # exception category and provider's short response for diagnosis.
            reason = " ".join(str(exc).split())[:240]
            app.logger.warning("Response notification failed: %s, alert %s (%s: %s)",
                               channel, alert.id, type(exc).__name__, reason or "no detail")
    action.result = json.loads(json.dumps(result))
    flag_modified(action, "result")
    action.completed = True
    db.session.commit()
    return action


def restore_quarantine(app, item: QuarantineItem, monitored_root: Path) -> QuarantineItem:
    """Move one quarantined file back, verifying identity and destination first.

    Raises ValueError with a specific reason when any check fails, leaving both
    the quarantine copy and the database untouched.
    """
    if item.restored_at is not None:
        raise ValueError("This file has already been restored")
    quarantine = Path(app.config["QUARANTINE_PATH"]).resolve()
    root = Path(monitored_root).resolve()
    source = Path(item.quarantine_path).resolve()
    if quarantine not in source.parents:
        raise ValueError("Quarantined file is outside the quarantine directory")
    info = source.lstat()
    if source.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("Quarantined file must not be a link")
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Only regular files can be restored")
    if sha256_file(source) != item.sha256:
        raise ValueError("Quarantined file changed since containment; refusing to restore")
    relative = Path(item.original_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Recorded original path is unsafe")
    destination = (root / relative).resolve()
    if root not in destination.parents:
        raise ValueError("Original path is outside the monitored directory")
    if destination.exists():
        raise ValueError("A file already exists at the original path")
    destination.parent.mkdir(parents=True, exist_ok=True)
    os.rename(source, destination)
    item.restored_at = datetime.now(timezone.utc)
    db.session.commit()
    return item
