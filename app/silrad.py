"""Local-only SILRAD Sysmon event preparation and held-out evaluation.

This is a dataset benchmark path. It is deliberately separate from the live
folder monitor and from the synthetic-trained temporal telemetry model.
"""
import csv
import hashlib
import json
import re
import zlib
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import scipy.sparse as sp
import xgboost as xgb


SOURCE = "https://github.com/JamilIsp/SILRAD-dataset"
LABEL_COLUMN = "class"
HASH_SIZE = 1 << 17
THRESHOLD = 0.60
TEXT_COLUMNS = {"CallTrace", "CommandLine", "ParentCommandLine", "Description", "Details", "TargetObject"}
EXCLUDED_COLUMNS = {
    "class", "task", "ProcessGuid", "ParentProcessGuid", "TargetProcessGUID",
    "ProcessId", "ParentProcessId", "TargetProcessId", "SourceThreadId",
    "User", "ParentUser", "SourceUser", "TargetUser", "TerminalSessionId",
}
TOKEN_RE = re.compile(r"[a-z0-9_.:/\\-]+", re.IGNORECASE)


def _feature_indices(row, columns):
    values = {}
    for column in columns:
        value = (row.get(column) or "").strip()
        if not value:
            continue
        value = value[:2048].casefold()
        tokens = [f"{column}={value}"]
        if column in TEXT_COLUMNS:
            tokens.extend(f"{column}:{token}" for token in TOKEN_RE.findall(value)[:48])
        for token in tokens:
            index = zlib.crc32(token.encode("utf-8")) % HASH_SIZE
            values[index] = values.get(index, 0) + 1
    return values


def _matrix(path, columns, *, max_rows=250_000):
    data, indices, indptr, labels = [], [], [0], []
    with Path(path).open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or LABEL_COLUMN not in reader.fieldnames or "event.code" not in reader.fieldnames:
            raise ValueError("SILRAD CSV must contain event.code and class columns.")
        missing = set(columns) - set(reader.fieldnames)
        if missing:
            raise ValueError("SILRAD CSV is missing required columns: " + ", ".join(sorted(missing)))
        if len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError("SILRAD CSV contains duplicate column names.")
        for line_number, row in enumerate(reader, 2):
            if len(labels) >= max_rows:
                raise ValueError(f"SILRAD file exceeds the {max_rows:,} row safety limit.")
            try:
                label = int(row[LABEL_COLUMN])
                if label not in (0, 1):
                    raise ValueError("class must be 0 or 1")
            except (ValueError, TypeError) as exc:
                raise ValueError(f"SILRAD CSV line {line_number}: invalid class label") from exc
            features = _feature_indices(row, columns)
            indices.extend(features.keys())
            data.extend(features.values())
            indptr.append(len(indices))
            labels.append(label)
    if not labels or len(set(labels)) != 2:
        raise ValueError("SILRAD evaluation requires rows from both classes.")
    matrix = sp.csr_matrix((np.asarray(data, dtype=np.float32), np.asarray(indices, dtype=np.int32),
                            np.asarray(indptr, dtype=np.int64)), shape=(len(labels), HASH_SIZE))
    matrix.sum_duplicates()
    return matrix, np.asarray(labels, dtype=np.uint8)


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def train_model(train_csv, model_dir):
    """Train once on SILRAD's published training split, never on its test split."""
    model_dir = Path(model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    with Path(train_csv).open(encoding="utf-8-sig", newline="") as stream:
        columns = next(csv.reader(stream), [])
    if "class" not in columns or "event.code" not in columns:
        raise ValueError("This is not a SILRAD Sysmon CSV (expected event.code and class).")
    feature_columns = [name for name in columns if name not in EXCLUDED_COLUMNS]
    if not feature_columns:
        raise ValueError("SILRAD CSV has no usable feature columns.")
    matrix, labels = _matrix(train_csv, feature_columns, max_rows=100_000)
    counts = np.bincount(labels, minlength=2)
    booster = xgb.train(
        {"objective": "binary:logistic", "eval_metric": "logloss", "tree_method": "hist",
         "max_depth": 6, "eta": 0.1, "seed": 42, "nthread": 4},
        xgb.DMatrix(matrix, label=labels), num_boost_round=180,
    )
    booster_path = model_dir / "xgboost.json"
    booster.save_model(booster_path)
    metadata = {
        "model_type": "silrad_sysmon_xgboost_hashed",
        "display_name": "SILRAD Sysmon event XGBoost",
        "source": SOURCE,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "training_file_sha256": _sha256(train_csv),
        "training_rows": int(len(labels)),
        "training_class_counts": {"benign": int(counts[0]), "ransomware": int(counts[1])},
        "feature_columns": feature_columns,
        "excluded_columns": sorted(EXCLUDED_COLUMNS),
        "hash_size": HASH_SIZE,
        "decision_threshold": THRESHOLD,
        "booster": booster_path.name,
        "evaluation_policy": "Use only SILRAD fasttext-testmodel.csv as held-out data; never tune on that split.",
        "limitations": [
            "Event-level public-dataset benchmark; it is not live endpoint or prospective validation.",
            "The test split is publisher-provided and not claimed to be family-disjoint.",
            "Hashed event text is a project-specific representation, not the SILRAD paper's reported model.",
            "The 0.60 threshold is fixed from the supplied methodology and is not calibrated by this run.",
        ],
    }
    (model_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def evaluate_test(test_csv, model_dir, predictions_csv=None):
    """Evaluate the untouched SILRAD test split; store row outcomes without raw Sysmon text."""
    model_dir = Path(model_dir)
    metadata = json.loads((model_dir / "metadata.json").read_text(encoding="utf-8"))
    if metadata.get("model_type") != "silrad_sysmon_xgboost_hashed":
        raise ValueError("The prepared SILRAD model is missing or has an unsupported format.")
    matrix, labels = _matrix(test_csv, metadata["feature_columns"], max_rows=250_000)
    booster = xgb.Booster()
    booster.load_model(model_dir / metadata["booster"])
    probabilities = booster.predict(xgb.DMatrix(matrix))
    predicted = probabilities >= float(metadata["decision_threshold"])
    actual = labels == 1
    counts = {"tp": int(np.sum(predicted & actual)), "tn": int(np.sum(~predicted & ~actual)),
              "fp": int(np.sum(predicted & ~actual)), "fn": int(np.sum(~predicted & actual))}
    tp, tn, fp, fn = (counts[key] for key in ("tp", "tn", "fp", "fn"))
    ratio = lambda numerator, denominator: numerator / denominator if denominator else None
    scores = {"accuracy": ratio(tp + tn, len(labels)), "precision": ratio(tp, tp + fp),
              "recall": ratio(tp, tp + fn), "f1": ratio(2 * tp, 2 * tp + fp + fn),
              "false_positive_rate": ratio(fp, fp + tn)}
    if predictions_csv:
        with Path(predictions_csv).open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(["row_number", "actual_class", "predicted_class", "probability", "correct"])
            for number, (label, probability, prediction) in enumerate(zip(labels, probabilities, predicted), 1):
                writer.writerow([number, int(label), int(prediction), f"{float(probability):.8f}", int(bool(label == prediction))])
    return {
        "dataset": "SILRAD Sysmon held-out test split", "source": SOURCE,
        "evaluated_at": datetime.now(timezone.utc).isoformat(), "dataset_sha256": _sha256(test_csv),
        "model_sha256": _sha256(model_dir / metadata["booster"]), "model_name": metadata["display_name"],
        "dataset_schema": "silrad", "record_unit": "Sysmon events", "threshold": metadata["decision_threshold"],
        "windows": int(len(labels)), "traces": None, "confusion_matrix": counts, "metrics": scores,
        "class_counts": {"benign": int(np.sum(~actual)), "ransomware": int(np.sum(actual))},
        "suspicious_count": int(np.sum(predicted)), "max_probability": float(np.max(probabilities)),
        "model_prediction": "suspicious" if np.any(predicted) else "benign",
        "evaluation_role": "publisher-provided held-out test split",
        "limitations": metadata["limitations"], "predictions": [],
    }
