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
                message["Subject"] = f"RansomShield suspicious activity alert #{alert.id}"
                message["From"] = config["RESPONSE_EMAIL_FROM"]
                message["To"] = config["RESPONSE_EMAIL_TO"]
                message.set_content(json.dumps(payload, indent=2))
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
        except Exception:
            result["notifications"][channel] = "failed"
            app.logger.warning("Response notification failed: %s, alert %s", channel, alert.id)
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
