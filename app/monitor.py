from datetime import datetime, timezone
from collections import deque
import json
import os
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Lock, Thread
from time import monotonic
from typing import Dict, Optional, Set, Tuple
from uuid import uuid4

import psutil

from .extensions import db
from .models import Alert, MonitoringEvent


FileState = Tuple[int, int]

QUEUE_LIMIT = 5000
RECONCILE_SECONDS = 30.0
ACTIVITY_WINDOW_SECONDS = 30.0
DELETE_ALERT_THRESHOLD = 10
MODIFY_ALERT_THRESHOLD = 20
MIXED_ALERT_THRESHOLD = 30
MIN_DESTRUCTIVE_CHANGES = 10
ALERT_COOLDOWN_SECONDS = 60.0


def take_snapshot(root: Path) -> Dict[str, FileState]:
    snapshot: Dict[str, FileState] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            stat = path.stat()
            snapshot[path.relative_to(root).as_posix()] = (stat.st_mtime_ns, stat.st_size)
        except OSError:
            continue
    return snapshot


class _WatchCollector:
    """Push Windows filesystem notifications into a bounded queue.

    Events are reduced to (operation, relative path). If the queue is full the
    event is dropped and counted; the periodic reconciliation sweep still sees
    the resulting state, so a drop degrades latency rather than losing the
    detection permanently.
    """

    def __init__(self, service: "MonitoringService") -> None:
        self.service = service
        self.observer = None

    def _enqueue(self, operation: str, path) -> None:
        try:
            relative = Path(path).relative_to(self.service.target_path).as_posix()
        except (ValueError, TypeError):
            return
        try:
            self.service._queue.put_nowait((operation, relative))
        except Full:
            with self.service._lock:
                self.service._metrics["dropped_events"] += 1

    def start(self) -> bool:
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
        except ImportError:
            return False

        outer = self

        class Handler(FileSystemEventHandler):
            def on_created(self, event):
                if not event.is_directory:
                    outer._enqueue("created", event.src_path)

            def on_modified(self, event):
                if not event.is_directory:
                    outer._enqueue("modified", event.src_path)

            def on_deleted(self, event):
                if not event.is_directory:
                    outer._enqueue("deleted", event.src_path)

            def on_moved(self, event):
                if not event.is_directory:
                    outer._enqueue("deleted", event.src_path)
                    outer._enqueue("created", event.dest_path)

        self.observer = Observer()
        self.observer.schedule(Handler(), str(self.service.target_path), recursive=True)
        self.observer.daemon = True
        self.observer.start()
        return True

    def stop(self) -> None:
        if self.observer is not None:
            self.observer.stop()
            self.observer.join(timeout=5)
            self.observer = None


class MonitoringService:
    """Monitor system metrics and file activity in one configured directory."""

    def __init__(self) -> None:
        self.app = None
        self.target_path: Optional[Path] = None
        self.interval_seconds = 2.0
        self.reconcile_seconds = RECONCILE_SECONDS
        self._thread: Optional[Thread] = None
        self._stop_event = Event()
        self._lock = Lock()
        self._snapshot: Dict[str, FileState] = {}
        self._suppressed_delete_paths: Dict[str, float] = {}
        self._queue: Queue = Queue(maxsize=QUEUE_LIMIT)
        self._collector = _WatchCollector(self)
        self._owner_id: Optional[int] = None
        self._activity_window = deque()
        self._last_burst_alert_at = 0.0
        self._metrics = {
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "process_count": 0,
            "last_check": None,
            "last_successful_scan": None,
            "last_risk_score": 0,
            "monitored_files": 0,
            "dropped_events": 0,
            "queue_depth": 0,
            "collector": "poll",
            "last_activity": {},
        }
        self.policy_path: Optional[Path] = None
        self.policy = {
            "window_seconds": int(ACTIVITY_WINDOW_SECONDS),
            "delete_threshold": DELETE_ALERT_THRESHOLD,
            "modify_threshold": MODIFY_ALERT_THRESHOLD,
            "mixed_threshold": MIXED_ALERT_THRESHOLD,
            "mixed_destructive_minimum": MIN_DESTRUCTIVE_CHANGES,
            "auto_quarantine": False,
        }

    def init_app(self, app) -> None:
        self.app = app
        self.interval_seconds = float(app.config.get("MONITOR_INTERVAL_SECONDS", 2.0))
        self.reconcile_seconds = float(app.config.get("MONITOR_RECONCILE_SECONDS", RECONCILE_SECONDS))
        self.target_path = Path(app.config.get("MONITOR_TARGET_PATH", Path(app.instance_path) / "monitor_target"))
        self.target_path.mkdir(parents=True, exist_ok=True)
        configured_policy_path = app.config.get("MONITOR_POLICY_PATH")
        self.policy_path = (
            Path(configured_policy_path) if configured_policy_path
            else (None if app.testing else Path(app.instance_path) / "monitor_policy.json")
        )
        self.policy["auto_quarantine"] = bool(app.config.get("AUTO_QUARANTINE", False))
        saved_policy = None
        if self.policy_path:
            try:
                saved_policy = json.loads(self.policy_path.read_text(encoding="utf-8"))
                self.policy = self.validate_policy({**self.policy, **saved_policy})
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                pass
        self._apply_policy_to_app(enable_real_quarantine=bool(saved_policy and self.policy["auto_quarantine"]))
        app.extensions["monitoring_service"] = self

    @staticmethod
    def validate_policy(value: dict) -> dict:
        """Validate the user-editable server monitor policy."""
        if not isinstance(value, dict):
            raise ValueError("Monitoring settings must be an object.")

        def bounded_int(name, minimum, maximum):
            raw = value.get(name)
            if isinstance(raw, bool) or not isinstance(raw, int) or not minimum <= raw <= maximum:
                raise ValueError(f"{name.replace('_', ' ').title()} must be between {minimum} and {maximum}.")
            return raw

        policy = {
            "window_seconds": bounded_int("window_seconds", 5, 300),
            "delete_threshold": bounded_int("delete_threshold", 1, 5000),
            "modify_threshold": bounded_int("modify_threshold", 1, 5000),
            "mixed_threshold": bounded_int("mixed_threshold", 1, 5000),
            "mixed_destructive_minimum": bounded_int("mixed_destructive_minimum", 1, 5000),
            "auto_quarantine": value.get("auto_quarantine"),
        }
        if not isinstance(policy["auto_quarantine"], bool):
            raise ValueError("Automatic quarantine must be on or off.")
        if policy["mixed_destructive_minimum"] > policy["mixed_threshold"]:
            raise ValueError("The mixed-change minimum cannot exceed the total-change limit.")
        return policy

    def _apply_policy_to_app(self, enable_real_quarantine: bool = False) -> None:
        if not self.app:
            return
        self.app.config["AUTO_QUARANTINE"] = self.policy["auto_quarantine"]
        # Saving the dashboard switch explicitly opts into real file moves.
        # Environment-level AUTO_QUARANTINE can still be paired with dry-run.
        if enable_real_quarantine:
            self.app.config["QUARANTINE_MODE"] = "enabled"

    def update_policy(self, values: dict) -> dict:
        policy = self.validate_policy(values)
        if self.is_running:
            raise RuntimeError("Stop the server monitor before changing these settings.")
        self.policy = policy
        self._apply_policy_to_app(enable_real_quarantine=policy["auto_quarantine"])
        if self.policy_path:
            self.policy_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.policy_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
            os.replace(temporary, self.policy_path)
        return dict(policy)

    @property
    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def owned_by(self, user_id: int) -> bool:
        with self._lock:
            return self._owner_id == user_id

    def note_quarantined_file(self, relative_path: str) -> None:
        """Avoid reporting the monitor's own quarantine move as user activity."""
        relative = Path(relative_path).as_posix()
        with self._lock:
            self._snapshot.pop(relative, None)
            self._suppressed_delete_paths[relative] = monotonic() + 5.0

    def start(self, owner_id: Optional[int] = None) -> bool:
        with self._lock:
            if self.is_running:
                return False

            self._owner_id = owner_id
            self._snapshot = take_snapshot(self.target_path)
            self._activity_window.clear()
            self._last_burst_alert_at = 0.0
            while True:
                try:
                    self._queue.get_nowait()
                except Empty:
                    break
            self._metrics["last_activity"] = {}
            self._metrics["last_successful_scan"] = datetime.now(timezone.utc).isoformat()
            self._stop_event.clear()
            self._metrics["collector"] = "watchdog" if self._collector.start() else "poll"
            self._thread = Thread(
                target=self._run,
                name="ransomshield-monitor",
                daemon=True,
            )
            self._thread.start()
            return True

    def stop(self, owner_id: Optional[int] = None) -> bool:
        with self._lock:
            if not self.is_running or (owner_id is not None and self._owner_id != owner_id):
                return False
            self._stop_event.set()
            thread = self._thread

        thread.join(timeout=self.interval_seconds + 1.0)
        self._collector.stop()
        return True

    def status(self) -> dict:
        with self._lock:
            metrics = dict(self._metrics)

        return {
            "running": self.is_running,
            "connection_state": "Connected" if self.is_running else "Stopped",
            "model_state": "Rolling burst rules",
            "target": str(self.target_path),
            "interval_seconds": self.interval_seconds,
            "reconcile_seconds": self.reconcile_seconds,
            "auto_quarantine": self.app.config["AUTO_QUARANTINE"],
            "policy": dict(self.policy),
            **metrics,
        }

    def _drain_events(self) -> Set[Tuple[str, str]]:
        """Drain notifications into a deduplicated set for this cycle."""
        events: Set[Tuple[str, str]] = set()
        while True:
            try:
                events.add(self._queue.get_nowait())
            except Empty:
                break
        with self._lock:
            self._metrics["queue_depth"] = self._queue.qsize()
        return events

    def ingest_remote_event(self, agent_name: str, operation: str, relative_path: str) -> bool:
        """Feed an authenticated endpoint event into the same burst window."""
        safe_path = f"[agent:{agent_name}]/{relative_path}"
        try:
            self._queue.put_nowait((operation, safe_path))
            return True
        except Full:
            with self._lock:
                self._metrics["dropped_events"] += 1
            return False

    def _diff_snapshot(self, current: Dict[str, FileState]) -> Tuple[Set[str], Set[str], Set[str]]:
        previous_paths = set(self._snapshot)
        current_paths = set(current)
        created = current_paths - previous_paths
        deleted = previous_paths - current_paths
        modified = {
            path
            for path in current_paths & previous_paths
            if current[path] != self._snapshot[path]
        }
        return created, modified, deleted

    def _run(self) -> None:
        psutil.cpu_percent(interval=None)
        last_reconcile = 0.0
        clock = datetime.now(timezone.utc).timestamp()
        while not self._stop_event.wait(self.interval_seconds):
            try:
                now = datetime.now(timezone.utc).timestamp()
                reconcile = (now - last_reconcile) >= self.reconcile_seconds
                if reconcile:
                    last_reconcile = now
                self._collect_once(reconcile=reconcile)
            except Exception:
                if self.app:
                    self.app.logger.exception("Monitoring cycle failed")

    def _collect_once(self, reconcile: bool = False) -> None:
        events = self._drain_events()
        created = {path for operation, path in events if operation == "created"}
        modified = {path for operation, path in events if operation == "modified"}
        deleted = {path for operation, path in events if operation == "deleted"}

        # Diffing each cycle keeps detection
        # working when watchdog is unavailable or missed an event.
        current_snapshot = take_snapshot(self.target_path)
        snapshot_created, snapshot_modified, snapshot_deleted = self._diff_snapshot(current_snapshot)
        self._snapshot = current_snapshot
        created |= snapshot_created
        modified |= snapshot_modified
        deleted |= snapshot_deleted
        deleted -= created  # a move reported as delete+create is one file, not two
        # New files may emit both created and modified notifications while
        # they are being written. Count them once as created in this cycle.
        modified -= created
        for path in created | modified:
            deleted.discard(path)
        for path in deleted:
            modified.discard(path)

        now_monotonic = monotonic()
        with self._lock:
            suppressed = {path for path, expires in self._suppressed_delete_paths.items()
                          if expires >= now_monotonic}
            self._suppressed_delete_paths = {
                path: expires for path, expires in self._suppressed_delete_paths.items()
                if expires >= now_monotonic
            }
        deleted.difference_update(suppressed)

        cpu_percent = round(psutil.cpu_percent(interval=None), 1)
        memory_percent = round(psutil.virtual_memory().percent, 1)
        process_count = len(psutil.pids())
        file_changes = len(created) + len(modified) + len(deleted)
        touched: Set[str] = created | modified | deleted
        directories_touched = {Path(path).parts[0] for path in touched if Path(path).parts}
        operation_rate = round(file_changes / max(self.interval_seconds, 0.1), 2)
        if file_changes:
            self._activity_window.append((now_monotonic, frozenset(created), frozenset(modified), frozenset(deleted)))
        policy = dict(self.policy)
        cutoff = now_monotonic - policy["window_seconds"]
        while self._activity_window and self._activity_window[0][0] < cutoff:
            self._activity_window.popleft()

        window_created = set().union(*(item[1] for item in self._activity_window)) if self._activity_window else set()
        window_modified = set().union(*(item[2] for item in self._activity_window)) if self._activity_window else set()
        window_deleted = set().union(*(item[3] for item in self._activity_window)) if self._activity_window else set()
        window_touched = window_created | window_modified | window_deleted
        window_total = len(window_touched)
        window_destructive = len(window_modified | window_deleted)
        # This explainable activity score is not a probability or a malware
        # classification. Live alerts use only the explicit burst rules below.
        risk_score = min(100, round(100 * max(
            len(window_deleted) / policy["delete_threshold"],
            len(window_modified) / policy["modify_threshold"],
            window_total / policy["mixed_threshold"],
        )))
        burst_detected = (
            len(window_deleted) >= policy["delete_threshold"]
            or len(window_modified) >= policy["modify_threshold"]
            or (window_total >= policy["mixed_threshold"]
                and window_destructive >= policy["mixed_destructive_minimum"])
        )
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            previous_activity = self._metrics.get("last_activity", {})
            self._metrics = {
                **self._metrics,
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "process_count": process_count,
                "last_check": now,
                "last_successful_scan": now,
                "last_risk_score": risk_score,
                "monitored_files": len(self._snapshot),
                "last_activity": ({
                    "created": len(created),
                    "modified": len(modified),
                    "deleted": len(deleted),
                    "files_touched": file_changes,
                    "directories_touched": len(directories_touched),
                    "operation_rate": operation_rate,
                } if file_changes else previous_activity),
            }

        if file_changes:
            details = (
                f"{file_changes} file changes: {len(created)} created, "
                f"{len(modified)} modified, {len(deleted)} deleted. "
                f"Detected at {operation_rate} changes per second."
            )
            event_files = [
                {"operation": operation, "path": path}
                for operation, paths in (("created", created), ("modified", modified), ("deleted", deleted))
                for path in sorted(paths)
            ]
            severity = "warning" if burst_detected else "info"
            self._persist_event(
                "file_activity", severity, details, risk_score,
                source="reconcile" if reconcile else "watchdog", file_activity=event_files,
            )

            if burst_detected and now_monotonic - self._last_burst_alert_at >= ALERT_COOLDOWN_SECONDS:
                self._last_burst_alert_at = now_monotonic
                burst_details = (
                    f"High-volume file-change burst across {window_total} distinct files in "
                    f"{policy['window_seconds']} seconds ({len(window_created)} created, "
                    f"{len(window_modified)} modified, {len(window_deleted)} deleted). "
                    "Review this activity; this rule is an anomaly signal, not a malware verdict."
                )
                burst_score = max(risk_score, 60)
                severe_burst = (
                    len(window_deleted) >= 2 * policy["delete_threshold"]
                    or len(window_modified) >= 2 * policy["modify_threshold"]
                    or (window_total >= 2 * policy["mixed_threshold"]
                        and window_destructive >= 2 * policy["mixed_destructive_minimum"])
                )
                alert_files = [
                    {
                        "path": path,
                        "operations": [
                            operation
                            for operation, paths in (
                                ("created", window_created),
                                ("modified", window_modified),
                                ("deleted", window_deleted),
                            )
                            if path in paths
                        ],
                    }
                    for path in sorted(window_touched)
                ][:100]
                quarantine_candidates = {
                    item["path"] for item in alert_files
                    if any(operation in {"created", "modified"} for operation in item["operations"])
                }
                self._persist_alert(
                    "High-volume file-change burst",
                    burst_details,
                    "high" if severe_burst else "medium",
                    burst_score,
                    window_touched,
                    file_activity=alert_files,
                    quarantine_candidates=quarantine_candidates,
                )

    def _persist_event(        self,
        event_type: str,
        severity: str,
        details: str,
        risk_score: int,
        source: str = "poll",
        file_activity=None,
    ) -> None:
        if not self.app:
            return
        with self.app.app_context():
            db.session.add(
                MonitoringEvent(
                    user_id=self._owner_id,
                    event_type=event_type,
                    severity=severity,
                    details=details,
                    file_activity=file_activity or [],
                    risk_score=risk_score,
                    event_id=str(uuid4()),
                    source=source,
                )
            )
            db.session.commit()

    def _persist_alert(
        self,
        title: str,
        details: str,
        severity: str,
        risk_score: int,
        affected=None,
        model_version: str = "rolling-file-burst-v1",
        owner_id: Optional[int] = None,
        file_activity=None,
        quarantine_candidates=None,
    ) -> None:
        if not self.app:
            return
        with self.app.app_context():
            alert = Alert(
                    user_id=self._owner_id if owner_id is None else owner_id,
                    title=title,
                    details=details,
                    severity=severity,
                    risk_score=risk_score,
                    model_version=model_version,
                    rule_trace=[
                        {"signal": "files_touched_in_window", "value": len(affected or ())},
                        {"signal": "risk_score", "value": risk_score},
                        *([{"signal": "affected_files", "value": file_activity[:100]}]
                          if file_activity else []),
                        {"signal": "policy", "value": "rolling-file-burst-v1"},
                    ],
                )
            db.session.add(alert)
            db.session.commit()
            if risk_score >= 60:
                from .response import respond
                action = respond(
                    self.app, alert, self.target_path,
                    quarantine_candidates if quarantine_candidates is not None else (affected or set()),
                    quarantine_allowed=model_version == "rolling-file-burst-v1",
                )
                # Suppress only our own moves, retaining concurrent external changes.
                for record in action.result["files"]:
                    if record["status"] == "quarantined":
                        self.note_quarantined_file(record["source"])
