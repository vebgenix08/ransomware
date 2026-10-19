from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Lock, Thread
from typing import Dict, Optional, Set, Tuple

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


class MonitoringService:
    """Safely monitor system metrics and one isolated demonstration directory."""

    def __init__(self) -> None:
        self.app = None
        self.target_path: Optional[Path] = None
        self.interval_seconds = 2.0
        self._thread: Optional[Thread] = None
        self._stop_event = Event()
        self._lock = Lock()
        self._snapshot: Dict[str, FileState] = {}
        self._metrics = {
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "process_count": 0,
            "last_check": None,
            "last_risk_score": 0,
            "canary_triggered": False,
            "canary_files": len(CANARY_NAMES),
            "decoy_files": 0,
            "last_activity": {},
        }

    def init_app(self, app) -> None:
        self.app = app
        self.interval_seconds = float(app.config.get("MONITOR_INTERVAL_SECONDS", 2.0))
        self.target_path = Path(app.config.get("MONITOR_TARGET_PATH", Path(app.instance_path) / "decoy_server"))
        self.target_path.mkdir(parents=True, exist_ok=True)
        self._seed_decoy_server()
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

            self._snapshot = self._take_snapshot()
            self.detector.history.clear()
            self._metrics["canary_triggered"] = False
            self._metrics["last_activity"] = {}
            self._stop_event.clear()
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
            "auto_quarantine": self.app.config["AUTO_QUARANTINE"],
            **metrics,
        }

    def create_safe_demo_files(self, batch_id: str, count: int = 24) -> int:
        """Generate a harmless burst and modify canaries in the isolated decoy."""
        if not self.target_path:
            return 0

        self._seed_decoy_server()
        batch_path = self.target_path / "Incoming" / f"simulation_{batch_id}"
        batch_path.mkdir(parents=True, exist_ok=True)
        for index in range(count):
            sample_path = batch_path / f"document_{index + 1:02d}.locked-demo"
            sample_path.write_text(
                f"Harmless RansomShield simulation artifact {index + 1}; no encryption occurred.\n",
                encoding="utf-8",
            )
        for relative_name in sorted(CANARY_NAMES):
            path = self.target_path / Path(relative_name)
            path.write_text(path.read_text(encoding="utf-8") + "Safe simulation touch.\n", encoding="utf-8")
        for relative_name in sorted(DISPOSABLE_NAMES):
            (self.target_path / Path(relative_name)).unlink(missing_ok=True)
        return count + len(CANARY_NAMES) + len(DISPOSABLE_NAMES)

    def _seed_decoy_server(self) -> None:
        """Create an attractive but entirely synthetic server-like directory tree."""
        if not self.target_path:
            return
        for relative_name, content in DECOY_FILES.items():
            path = self.target_path / Path(relative_name)
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.write_text(content, encoding="utf-8")
        readme = self.target_path / "DECOY_NOTICE.txt"
        if not readme.exists():
            readme.write_text(
                "Controlled RansomShield decoy environment. All content is synthetic.\n",
                encoding="utf-8",
            )

    def _take_snapshot(self) -> Dict[str, FileState]:
        snapshot: Dict[str, FileState] = {}
        if not self.target_path:
            return snapshot

        for path in self.target_path.rglob("*"):
            if not path.is_file():
                continue
            try:
                stat = path.stat()
                snapshot[path.relative_to(self.target_path).as_posix()] = (
                    stat.st_mtime_ns,
                    stat.st_size,
                )
            except OSError:
                continue
        return snapshot

    def _run(self) -> None:
        psutil.cpu_percent(interval=None)
        while not self._stop_event.wait(self.interval_seconds):
            try:
                self._collect_once()
            except Exception:
                if self.app:
                    self.app.logger.exception("Monitoring cycle failed")

    def _collect_once(self) -> None:
        current_snapshot = self._take_snapshot()
        previous_paths = set(self._snapshot)
        current_paths = set(current_snapshot)

        created = current_paths - previous_paths
        deleted = previous_paths - current_paths
        modified = {
            path
            for path in current_paths & previous_paths
            if current_snapshot[path] != self._snapshot[path]
        }
        self._snapshot = current_snapshot

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

        with self._lock:
            previous_activity = self._metrics.get("last_activity", {})
            previous_canary = bool(self._metrics.get("canary_triggered", False))
            self._metrics = {
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "process_count": process_count,
                "last_check": datetime.now(timezone.utc).isoformat(),
                "last_risk_score": risk_score,
                "canary_triggered": previous_canary or bool(canaries_touched),
                "canary_files": len(CANARY_NAMES),
                "decoy_files": len(current_snapshot),
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
            self._persist_event("file_activity", severity, details, risk_score)

            if risk_score >= 60:
                self._persist_alert(
                    "Canary and ransomware-like activity" if canaries_touched else "Unusual file activity burst",
                    details,
                    "high" if risk_score >= 85 else "medium",
                    risk_score,
                    touched,
                )

    def _persist_event(
        self,
        event_type: str,
        severity: str,
        details: str,
        risk_score: int,
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


monitoring_service = MonitoringService()
