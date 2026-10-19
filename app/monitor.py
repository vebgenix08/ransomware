from datetime import datetime, timezone
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Lock, Thread
from typing import Dict, Optional, Set, Tuple
from uuid import uuid4

import psutil

from .detector import BehavioralDetector
from .extensions import db
from .models import Alert, MonitoringEvent


FileState = Tuple[int, int]
CANARY_NAMES = {
    "Finance/Salary_Data.xlsx",
    "HR/Employee_Data.xlsx",
    "Backup/database_backup.sql",
}

DECOY_FILES = {
    "Finance/Financial_Report.pdf": "Synthetic quarterly financial report. No real data.\n",
    "Finance/Budget_2026.xlsx": "Synthetic budget workbook placeholder. No real data.\n",
    "Finance/Salary_Data.xlsx": "RANSOMSHIELD CANARY: synthetic salary data.\n",
    "HR/Employee_Data.xlsx": "RANSOMSHIELD CANARY: synthetic employee data.\n",
    "HR/Employee_Records.pdf": "Synthetic employee records. No real data.\n",
    "Backup/backup_2026.zip": "Synthetic backup placeholder. No archive content.\n",
    "Backup/database_backup.sql": "RANSOMSHIELD CANARY: synthetic database backup.\n",
    "Documents/Customer_List.csv": "name,account\nSynthetic Customer,DEMO-001\n",
    "Documents/Strategy.docx": "Synthetic strategy document. No real data.\n",
    "Backup/restore_point_01.tmp": "Disposable synthetic restore point.\n",
    "Backup/restore_point_02.tmp": "Disposable synthetic restore point.\n",
    "Backup/restore_point_03.tmp": "Disposable synthetic restore point.\n",
    "Documents/archive_copy_01.tmp": "Disposable synthetic archive copy.\n",
    "Documents/archive_copy_02.tmp": "Disposable synthetic archive copy.\n",
}
DISPOSABLE_NAMES = {name for name in DECOY_FILES if name.endswith(".tmp")}

QUEUE_LIMIT = 5000
RECONCILE_SECONDS = 30.0


# --- Shared helpers: used by live monitoring and by isolated simulation runs ---

def seed_decoy_server(root: Path) -> None:
    """Create an attractive but entirely synthetic server-like directory tree."""
    for relative_name, content in DECOY_FILES.items():
        path = root / Path(relative_name)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(content, encoding="utf-8")
    readme = root / "DECOY_NOTICE.txt"
    if not readme.exists():
        readme.write_text(
            "Controlled RansomShield decoy environment. All content is synthetic.\n",
            encoding="utf-8",
        )


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


def create_safe_demo_files(root: Path, batch_id: str, count: int = 24) -> int:
    """Generate a harmless burst and modify canaries in an isolated directory."""
    seed_decoy_server(root)
    batch_path = root / "Incoming" / f"simulation_{batch_id}"
    batch_path.mkdir(parents=True, exist_ok=True)
    for index in range(count):
        (batch_path / f"document_{index + 1:02d}.locked-demo").write_text(
            f"Harmless RansomShield simulation artifact {index + 1}; no encryption occurred.\n",
            encoding="utf-8",
        )
    for relative_name in sorted(CANARY_NAMES):
        path = root / Path(relative_name)
        path.write_text(path.read_text(encoding="utf-8") + "Safe simulation touch.\n", encoding="utf-8")
    for relative_name in sorted(DISPOSABLE_NAMES):
        (root / Path(relative_name)).unlink(missing_ok=True)
    return count + len(CANARY_NAMES) + len(DISPOSABLE_NAMES)


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
    """Safely monitor system metrics and one isolated demonstration directory."""

    def __init__(self) -> None:
        self.app = None
        self.target_path: Optional[Path] = None
        self.interval_seconds = 2.0
        self.reconcile_seconds = RECONCILE_SECONDS
        self._thread: Optional[Thread] = None
        self._stop_event = Event()
        self._lock = Lock()
        self._snapshot: Dict[str, FileState] = {}
        self._queue: Queue = Queue(maxsize=QUEUE_LIMIT)
        self._collector = _WatchCollector(self)
        self._metrics = {
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "process_count": 0,
            "last_check": None,
            "last_successful_scan": None,
            "last_risk_score": 0,
            "canary_triggered": False,
            "canary_files": len(CANARY_NAMES),
            "decoy_files": 0,
            "dropped_events": 0,
            "queue_depth": 0,
            "collector": "poll",
            "last_activity": {},
        }

    def init_app(self, app) -> None:
        self.app = app
        self.interval_seconds = float(app.config.get("MONITOR_INTERVAL_SECONDS", 2.0))
        self.reconcile_seconds = float(app.config.get("MONITOR_RECONCILE_SECONDS", RECONCILE_SECONDS))
        self.target_path = Path(app.config.get("MONITOR_TARGET_PATH", Path(app.instance_path) / "decoy_server"))
        self.target_path.mkdir(parents=True, exist_ok=True)
        seed_decoy_server(self.target_path)
        model_path = Path(app.root_path) / "artifacts" / "behavioral_model.json"
        self.detector = BehavioralDetector(model_path)
        if not self.detector.is_ready:
            app.logger.warning("Behavioral model unavailable: %s", self.detector.load_error)
        app.extensions["monitoring_service"] = self

    @property
    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> bool:
        with self._lock:
            if self.is_running:
                return False

            self._snapshot = take_snapshot(self.target_path)
            self.detector.history.clear()
            while True:
                try:
                    self._queue.get_nowait()
                except Empty:
                    break
            self._metrics["canary_triggered"] = False
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

    def stop(self) -> bool:
        with self._lock:
            if not self.is_running:
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
            "model_state": self.detector.display_name,
            "target": "instance/decoy_server",
            "decoy_directories": sorted({name.split("/", 1)[0] for name in DECOY_FILES}),
            "interval_seconds": self.interval_seconds,
            "reconcile_seconds": self.reconcile_seconds,
            "auto_quarantine": self.app.config["AUTO_QUARANTINE"],
            **metrics,
        }

    def create_safe_demo_files(self, batch_id: str, count: int = 24) -> int:
        """Generate a harmless burst and modify canaries in the isolated decoy."""
        if not self.target_path:
            return 0
        return create_safe_demo_files(self.target_path, batch_id, count)

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

        # Diffing every cycle is cheap for a decoy tree and keeps detection
        # working when watchdog is unavailable or missed an event.
        current_snapshot = take_snapshot(self.target_path)
        snapshot_created, snapshot_modified, snapshot_deleted = self._diff_snapshot(current_snapshot)
        self._snapshot = current_snapshot
        created |= snapshot_created
        modified |= snapshot_modified
        deleted |= snapshot_deleted
        deleted -= created  # a move reported as delete+create is one file, not two
        for path in created | modified:
            deleted.discard(path)
        for path in deleted:
            modified.discard(path)

        cpu_percent = round(psutil.cpu_percent(interval=None), 1)
        memory_percent = round(psutil.virtual_memory().percent, 1)
        process_count = len(psutil.pids())
        file_changes = len(created) + len(modified) + len(deleted)
        touched: Set[str] = created | modified | deleted
        canaries_touched = touched & CANARY_NAMES
        canaries_modified = modified & CANARY_NAMES
        directories_touched = {Path(path).parts[0] for path in touched if Path(path).parts}
        operation_rate = round(file_changes / max(self.interval_seconds, 0.1), 2)
        fallback_risk_score = min(
            100,
            file_changes * 7
            + len(deleted) * 8
            + (15 if cpu_percent >= 90 else 0)
            + (10 if memory_percent >= 92 else 0)
            + (35 if canaries_touched else 0)
            + min(20, round(operation_rate)),
        )
        probability = self.detector.predict_probability(
            {
                "created_count": len(created),
                "modified_count": len(modified),
                "deleted_count": len(deleted),
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "process_count": process_count,
                "canary_accessed": int(bool(canaries_touched)),
                "canary_modified": int(bool(canaries_modified)),
                "decoy_files_touched": file_changes,
                "directories_touched": len(directories_touched),
                "operation_rate": operation_rate,
            }
        )
        risk_score = fallback_risk_score if probability is None else round(probability * 100)
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            previous_activity = self._metrics.get("last_activity", {})
            previous_canary = bool(self._metrics.get("canary_triggered", False))
            self._metrics = {
                **self._metrics,
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "process_count": process_count,
                "last_check": now,
                "last_successful_scan": now,
                "last_risk_score": risk_score,
                "canary_triggered": previous_canary or bool(canaries_touched),
                "canary_files": len(CANARY_NAMES),
                "decoy_files": len(self._snapshot),
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
                f"Observed {file_changes} decoy-server changes "
                f"({len(created)} created, {len(modified)} modified, {len(deleted)} deleted; "
                f"{operation_rate} operations/s)."
            )
            if canaries_touched:
                details += f" Canary triggered: {', '.join(sorted(canaries_touched))}."
            severity = "warning" if risk_score >= 60 else "info"
            self._persist_event("file_activity", severity, details, risk_score, source="reconcile" if reconcile else "watchdog")

            if risk_score >= 60:
                self._persist_alert(
                    "Canary and ransomware-like activity" if canaries_touched else "Unusual file activity burst",
                    details,
                    "high" if risk_score >= 85 else "medium",
                    risk_score,
                    touched,
                )

    def _persist_event(        self,
        event_type: str,
        severity: str,
        details: str,
        risk_score: int,
        source: str = "poll",
    ) -> None:
        if not self.app:
            return
        with self.app.app_context():
            db.session.add(
                MonitoringEvent(
                    event_type=event_type,
                    severity=severity,
                    details=details,
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
    ) -> None:
        if not self.app:
            return
        with self.app.app_context():
            alert = Alert(
                    title=title,
                    details=details,
                    severity=severity,
                    risk_score=risk_score,
                    model_version=self.detector.display_name,
                    rule_trace=[{"signal": "risk_score", "value": risk_score}],
                )
            db.session.add(alert)
            db.session.commit()
            if risk_score >= 60:
                from .response import respond
                action = respond(self.app, alert, self.target_path, affected or set(), quarantine_allowed=risk_score >= 85)
                # Suppress only our own removals, retaining concurrent external changes.
                for record in action.result["files"]:
                    if record["status"] == "quarantined":
                        self._snapshot.pop(record["source"], None)
