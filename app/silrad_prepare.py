"""Prepare the published SILRAD benchmark on the app host when requested."""

from __future__ import annotations

from pathlib import Path
from threading import Lock, Thread


class SilradPreparation:
    def __init__(self) -> None:
        self._lock = Lock()
        self._state = "idle"
        self._error = None
        self._thread = None
        self.app = None

    def init_app(self, app) -> None:
        self.app = app
        app.extensions["silrad_preparation"] = self

    @property
    def directory(self) -> Path:
        return Path(self.app.config["SILRAD_DATA_DIR"])

    def status(self) -> dict:
        metadata_path = self.directory / "metadata.json"
        test_path = self.directory / "fasttext-testmodel.csv"
        train_path = self.directory / "fasttext-trainmodel.csv"
        if metadata_path.is_file() and test_path.is_file() and train_path.is_file():
            try:
                import json
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                booster_name = metadata.get("booster", "")
                if not booster_name or Path(booster_name).name != booster_name or not (self.directory / booster_name).is_file():
                    raise ValueError("SILRAD model artifact is missing or invalid.")
                evaluation = metadata.get("heldout_evaluation", {})
                return {
                    "ready": True,
                    "state": "ready",
                    "model_name": metadata.get("display_name"),
                    "training_rows": metadata.get("training_rows"),
                    "test_rows": evaluation.get("windows"),
                    "threshold": evaluation.get("threshold"),
                    "metrics": evaluation.get("metrics", {}),
                    "confusion_matrix": evaluation.get("confusion_matrix", {}),
                    "class_counts": evaluation.get("class_counts", {}),
                    "limitations": metadata.get("limitations", []),
                }
            except (OSError, ValueError, TypeError):
                pass
        with self._lock:
            return {"ready": False, "state": self._state, "error": self._error}

    def start(self) -> bool:
        if self.status().get("ready"):
            with self._lock:
                self._state, self._error = "ready", None
            return False
        with self._lock:
            if self._state == "preparing":
                return False
            self._state, self._error = "preparing", None
            self._thread = Thread(target=self._prepare, name="silrad-prepare", daemon=True)
            self._thread.start()
            return True

    def _prepare(self) -> None:
        try:
            with self.app.app_context():
                from scripts.setup_silrad import prepare

                try:
                    prepare(self.directory)
                except FileExistsError:
                    # Recover from an interrupted prior setup, but only within
                    # this benchmark's private instance directory.
                    prepare(self.directory, force=True)
            if not self.status().get("ready"):
                raise RuntimeError("SILRAD setup finished without complete model and split files.")
            with self._lock:
                self._state, self._error = "ready", None
        except Exception:
            self.app.logger.exception("SILRAD benchmark preparation failed")
            with self._lock:
                self._state = "failed"
                self._error = "Preparation failed. Check the Render service logs, then try again."

