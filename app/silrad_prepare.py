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
        incremental_metadata_path = self.directory / "incremental_metadata.json"
        test_path = self.directory / "fasttext-testmodel.csv"
        train_path = self.directory / "fasttext-trainmodel.csv"
        model_path = self.directory / "silrad_incremental.pkl"
        if metadata_path.is_file() and incremental_metadata_path.is_file() and model_path.is_file() and test_path.is_file() and train_path.is_file():
            try:
                import json
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                incremental = metadata.get("incremental_model", {})
                comparison = metadata.get("xgboost_comparison", {}).get("heldout_evaluation", {})
                artifact_name = incremental.get("model_file", "")
                if artifact_name != model_path.name:
                    raise ValueError("SILRAD incremental model artifact is missing or invalid.")
                evaluation = incremental.get("heldout_evaluation", {})
                metrics = evaluation.get("metrics")
                confusion_matrix = evaluation.get("confusion_matrix")
                if (
                    not isinstance(evaluation.get("windows"), int)
                    or evaluation["windows"] <= 0
                    or not isinstance(metrics, dict)
                    or not isinstance(metrics.get("recall"), (int, float))
                    or not isinstance(confusion_matrix, dict)
                    or not isinstance(confusion_matrix.get("fn"), int)
                ):
                    raise ValueError("SILRAD held-out evaluation is incomplete.")
                return {
                    "ready": True,
                    "state": "ready",
                    "model_name": incremental.get("display_name"),
                    "training_rows": incremental.get("training_rows"),
                    "test_rows": evaluation.get("windows"),
                    "threshold": evaluation.get("threshold"),
                    "metrics": metrics,
                    "confusion_matrix": confusion_matrix,
                    "class_counts": evaluation.get("class_counts", {}),
                    "validation": incremental.get("validation", {}),
                    "frozen_model_evaluation": evaluation.get("frozen_model_evaluation", {}),
                    "xgboost_comparison": {
                        "model_name": metadata.get("display_name", "XGBoost comparison"),
                        "threshold": comparison.get("threshold"),
                        "metrics": comparison.get("metrics", {}),
                        "confusion_matrix": comparison.get("confusion_matrix", {}),
                    },
                    "limitations": incremental.get("limitations", []),
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

