"""Published MLRan feature-schema inference; never invents a temporal sequence."""
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import xgboost as xgb

LABEL_COLUMNS = {"sample_id", "sample_type", "family_label", "type_label"}
SOURCE = "https://github.com/faithfulco/mlran/tree/main/6_experiments/FS_MLRan_Datasets"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def row_hash(values):
    return hashlib.sha256(np.asarray(values, dtype=np.uint8).tobytes()).hexdigest()


def read_csv(path, feature_names, maximum=5000):
    with Path(path).open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        headers = reader.fieldnames or []
        if len(headers) != len(set(headers)):
            raise ValueError("Duplicate CSV headers")
        missing = set(["sample_id", "sample_type", *feature_names]) - set(headers)
        if missing:
            raise ValueError("Missing MLRan columns: " + ", ".join(sorted(missing)[:20]))
        records, identifiers = [], set()
        for number, row in enumerate(reader, 2):
            if len(records) >= maximum:
                raise ValueError(f"Maximum {maximum} MLRan samples per run")
            try:
                sample_id = row["sample_id"].strip()
                if not sample_id or sample_id in identifiers:
                    raise ValueError("Sample IDs must be present and unique")
                label = int(row["sample_type"])
                features = np.asarray([float(row[name]) for name in feature_names], dtype=np.float32)
                if label not in (0, 1) or not np.isin(features, [0, 1]).all():
                    raise ValueError("MLRan labels/features must be binary 0 or 1")
                records.append({"sample_id": sample_id, "label": label, "features": features})
                identifiers.add(sample_id)
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValueError(f"MLRan CSV line {number}: {exc}") from exc
    if not records:
        raise ValueError("MLRan CSV is empty")
    return records


def metrics(labels, probabilities, threshold):
    labels = np.asarray(labels)
    predicted = np.asarray(probabilities) >= threshold
    counts = {"tp": int(np.sum(predicted & (labels == 1))), "tn": int(np.sum(~predicted & (labels == 0))),
              "fp": int(np.sum(predicted & (labels == 0))), "fn": int(np.sum(~predicted & (labels == 1)))}
    tp, tn, fp, fn = (counts[k] for k in ("tp", "tn", "fp", "fn"))
    ratio = lambda a, b: a / b if b else None
    return {"accuracy": ratio(tp + tn, len(labels)), "precision": ratio(tp, tp + fp),
            "recall": ratio(tp, tp + fn), "f1": ratio(2 * tp, 2 * tp + fp + fn),
            "false_positive_rate": ratio(fp, fp + tn)}, counts


def evaluate_mlran(csv_path, artifact_path, dataset_name, source):
    artifact_path = Path(artifact_path)
    model = json.loads(artifact_path.read_text(encoding="utf-8"))
    if model.get("model_type") != "mlran_xgboost_tabular":
        raise ValueError("Wrong MLRan model artifact")
    records = read_csv(csv_path, model["input_features"], maximum=2000)
    chosen = [model["input_features"].index(name) for name in model["feature_names"]]
    matrix = np.stack([record["features"][chosen] for record in records])
    booster = xgb.Booster()
    booster_path = artifact_path.parent / model["xgboost_artifact"]
    booster.load_model(booster_path)
    probabilities = booster.predict(xgb.DMatrix(matrix))
    scores, counts = metrics([r["label"] for r in records], probabilities, model["decision_threshold"])
    training_hashes = set(model["training_feature_hashes"])
    overlap = sum(row_hash(row) in training_hashes for row in matrix)
    predictions = []
    for record, probability in zip(records, probabilities):
        active_files = [model["feature_descriptions"][name] for name, value in zip(model["input_features"], record["features"])
                        if value and model["feature_descriptions"][name].startswith(("FILE:", "DIRECTORY:", "DROP:"))]
        predictions.append({"trace_id": record["sample_id"], "window_index": 0, "label": record["label"],
                            "probability": float(probability), "prediction": int(probability >= model["decision_threshold"]),
                            "observed_activity": {"sample_id": record["sample_id"], "active_file_indicators": active_files,
                                                  "semantics": "Published binary feature presence; not file-operation counts or live file paths."}})
    return {"dataset": dataset_name, "source": source, "publisher_source": SOURCE,
            "evaluated_at": datetime.now(timezone.utc).isoformat(), "dataset_sha256": sha256(csv_path),
            "model_sha256": {artifact_path.name: sha256(artifact_path), booster_path.name: sha256(booster_path)},
            "model_name": model["display_name"], "dataset_schema": "mlran", "record_unit": "samples",
            "threshold": model["decision_threshold"], "windows": len(records), "traces": len(records),
            "window_seconds": None, "confusion_matrix": counts, "metrics": scores, "predictions": predictions,
            "training_overlap_samples": overlap,
            "evaluation_role": "contains_training_vectors" if overlap else "no_exact_training_vector_overlap",
            "limitations": model["limitations"] + ([f"{overlap} sample(s) match training feature vectors; these metrics are not held-out performance."] if overlap else [])}


def evaluate_dataset(csv_path, model_path, dataset_name, source):
    with Path(csv_path).open(encoding="utf-8-sig", newline="") as stream:
        columns = next(csv.reader(stream), [])
    if "sample_id" in columns and "sample_type" in columns:
        return evaluate_mlran(csv_path, Path(model_path).parent / "mlran/model.json", dataset_name, source)
    from scripts.evaluate_external import evaluate
    report = evaluate(csv_path, model_path, dataset_name, source)
    report.update(model_name="TCN + XGBoost (telemetry)", dataset_schema="telemetry", record_unit="windows")
    return report
