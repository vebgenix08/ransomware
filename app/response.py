"""Audited containment of files in the configured decoy directory."""
import hashlib
from html import escape as html_escape
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
from .models import QuarantineItem, ResponseAction, User


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _email_recipient(alert, config) -> str:
    """Send owned alerts to their account email; retain env fallback for unowned alerts."""
    owner = db.session.get(User, alert.user_id) if alert.user_id is not None else None
    if owner is not None and not owner.email_notifications_enabled:
        return ""
    return (owner.email.strip() if owner and owner.email else config.get("RESPONSE_EMAIL_TO", "").strip())


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

    affected = trace.get("affected_files") or []
    if affected:
        lines.extend(["", "Affected files (paths relative to monitored folder):", "Activity | Path"])
        for item in affected[:50]:
            operations = ", ".join(item.get("operations", [])) or "changed"
            lines.append(f"{operations} | {item.get('path', 'unknown path')}")
        if len(affected) > 50:
            lines.append(f"...and {len(affected) - 50} more files; see the dashboard.")

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


def _format_alert_email_html(alert, result, app_name: str) -> str:
    """Build an HTML report table, escaping all alert and user supplied values."""
    trace = {item.get("signal"): item.get("value") for item in (alert.rule_trace or [])}
    moved = sum(item.get("status") == "quarantined" for item in result.get("files", []))
    failed = sum(item.get("status") == "failed" for item in result.get("files", []))
    model_version = alert.model_version or "Not specified"
    rows = [
        ("Alert ID", alert.id),
        ("Severity", (alert.severity or "unknown").title()),
    ]
    if "suspicious_windows" in trace:
        rows.extend([
            ("Analysis type", "Offline CSV dataset evaluation"),
            ("Records flagged", f"{trace.get('suspicious_windows', 'unknown')} of {trace.get('total_samples', 'unknown')}"),
            ("Dataset", trace.get("dataset_name") or model_version),
            ("Source", trace.get("dataset_source") or "Not specified"),
            ("Highest record score", f"{alert.risk_score}/100"),
            ("Details", alert.details or "Not specified"),
        ])
        note = "This report describes records in the evaluated CSV. It does not indicate that a monitored computer is infected."
    elif model_version.startswith(("rolling-file-burst", "browser-folder-burst", "endpoint-agent-burst")):
        rows.extend([
            ("Analysis type", "Live monitored-folder activity"),
            ("Activity score", f"{alert.risk_score}/100 (heuristic, not a probability)"),
            ("Detection rule", model_version),
            ("Observed activity", alert.details or "Not specified"),
        ])
        note = "This is a file-activity anomaly for review, not confirmation of malware."
    else:
        rows.extend([
            ("Analysis type", "Activity alert"),
            ("Model or rule", model_version),
            ("Score", f"{alert.risk_score}/100"),
            ("Details", alert.details or "Not specified"),
        ])
        note = "Review this alert in the RansomShield dashboard."
    affected = trace.get("affected_files") or []
    rows.extend([
        ("Files quarantined", moved),
        ("Quarantine failures", failed),
        ("Quarantine status", result.get("quarantine", "not available")),
    ])
    table_rows = "".join(
        "<tr>"
        f"<th scope=\"row\" style=\"text-align:left;padding:10px;border:1px solid #d9e2dc;background:#f3f7f4;width:34%\">{html_escape(str(label))}</th>"
        f"<td style=\"padding:10px;border:1px solid #d9e2dc;white-space:pre-wrap\">{html_escape(str(value))}</td>"
        "</tr>"
        for label, value in rows
    )
    affected_table = ""
    if affected:
        affected_rows = "".join(
            "<tr>"
            f"<td style=\"text-align:left;padding:8px;border:1px solid #d9e2dc\">{html_escape(', '.join(item.get('operations', [])) or 'changed')}</td>"
            f"<td style=\"text-align:left;padding:8px;border:1px solid #d9e2dc;word-break:break-word\">{html_escape(str(item.get('path', 'unknown path')))}</td>"
            "</tr>"
            for item in affected[:50]
        )
        if len(affected) > 50:
            affected_rows += ("<tr><td colspan=\"2\" style=\"padding:8px;border:1px solid #d9e2dc\">"
                              f"...and {len(affected) - 50} more files; see the dashboard.</td></tr>")
        affected_table = (
            "<h3 style=\"margin:22px 0 8px;font-size:16px\">Affected files (paths relative to monitored folder)</h3>"
            "<table style=\"border-collapse:collapse;width:100%;font-size:13px\"><thead><tr>"
            "<th style=\"text-align:left;padding:8px;border:1px solid #d9e2dc;background:#f3f7f4\">Activity</th>"
            "<th style=\"text-align:left;padding:8px;border:1px solid #d9e2dc;background:#f3f7f4\">Path</th>"
            f"</tr></thead><tbody>{affected_rows}</tbody></table>"
        )
    return (
        "<!doctype html><html><body style=\"margin:0;padding:24px;background:#f4f7f5;font-family:Arial,Helvetica,sans-serif;color:#1b2b22\">"
        "<div style=\"max-width:720px;margin:0 auto;background:#ffffff;border:1px solid #d9e2dc;border-radius:10px;padding:24px\">"
        f"<p style=\"margin:0 0 8px;color:#42634f;font-size:13px;font-weight:bold\">{html_escape(str(app_name))}</p>"
        "<h1 style=\"margin:0 0 8px;font-size:24px\">Alert report</h1>"
        f"<h2 style=\"margin:0 0 20px;font-size:18px;font-weight:600\">{html_escape(str(alert.title))}</h2>"
        "<table style=\"border-collapse:collapse;width:100%;font-size:14px\">"
        f"<tbody>{table_rows}</tbody></table>"
        f"{affected_table}"
        f"<p style=\"margin:20px 0 0;padding:12px;background:#f3f7f4;border-radius:6px;font-size:13px;line-height:1.5\">{html_escape(note)}</p>"
        "<p style=\"margin:18px 0 0;color:#5b6b61;font-size:12px\">Review this alert in the RansomShield dashboard.</p>"
        "</div></body></html>"
    )


def _send_alert_email(app, alert, result, recipient: str) -> None:
    config = app.config
    if not recipient:
        raise ValueError("No recipient is configured for this alert")
    if not config.get("SMTP_HOST") or not config.get("RESPONSE_EMAIL_FROM"):
        raise ValueError("SMTP host and sender are required")
    security = config.get("SMTP_SECURITY", "starttls")
    if security not in ("starttls", "ssl"):
        raise ValueError("SMTP_SECURITY must be starttls or ssl")
    message = EmailMessage()
    app_name = config.get("APP_NAME", "RansomShield")
    subject, body = _format_alert_email(alert, result, app_name)
    message["Subject"] = subject
    message["From"] = config["RESPONSE_EMAIL_FROM"]
    message["To"] = recipient
    message.set_content(body)
    message.add_alternative(_format_alert_email_html(alert, result, app_name), subtype="html")
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
            raise ValueError("Recipient was refused by the SMTP server")


def retry_alert_email(app, alert, action) -> bool:
    """Retry only the email channel and append a safe delivery-attempt record."""
    result = dict(action.result or {})
    notifications = dict(result.get("notifications") or {})
    recipient = _email_recipient(alert, app.config)
    attempted_at = datetime.now(timezone.utc).isoformat()
    try:
        _send_alert_email(app, alert, result, recipient)
        notifications["email"] = "sent"
        attempt = {"status": "sent", "at": attempted_at}
    except Exception as exc:
        notifications["email"] = "failed"
        attempt = {"status": "failed", "at": attempted_at,
                   "error": f"SMTP attempt failed ({type(exc).__name__}). Check SMTP settings and provider logs."}
        app.logger.warning("Email retry failed for alert %s (%s)", alert.id, type(exc).__name__)
    result["notifications"] = notifications
    attempts = dict(result.get("notification_attempts") or {})
    attempts.setdefault("email", []).append(attempt)
    result["notification_attempts"] = attempts
    action.result = json.loads(json.dumps(result))
    flag_modified(action, "result")
    db.session.commit()
    return notifications["email"] == "sent"


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
    result.setdefault("notification_attempts", {})
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
    email_recipient = _email_recipient(alert, config)
    for channel in ("webhook", "email"):
        enabled = bool(config["RESPONSE_WEBHOOK_URL"] if channel == "webhook" else email_recipient)
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
                _send_alert_email(app, alert, result, email_recipient)
            result["notifications"][channel] = "sent"
            result["notification_attempts"].setdefault(channel, []).append(
                {"status": "sent", "at": datetime.now(timezone.utc).isoformat()})
        except Exception as exc:
            result["notifications"][channel] = "failed"
            result["notification_attempts"].setdefault(channel, []).append(
                {"status": "failed", "at": datetime.now(timezone.utc).isoformat(),
                 "error": f"Notification attempt failed ({type(exc).__name__}). Check the channel configuration."})
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
