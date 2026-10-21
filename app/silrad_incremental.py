"""SILRAD-style incremental benchmark using the publisher's numeric features.

This is an implementation of the paper's core model choices, not a claim of
bit-for-bit reproduction: the provided published split already contains
numeric feature vectors, so this module consumes those values directly.
"""
from __future__ import annotations

import csv
import copy
import json
import math
import pickle
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from river import drift, forest

from .silrad import SOURCE

LABEL_COLUMN = "class"
FEATURE_COLUMNS = ("TargetObject", "task", "CallTrace", "ParentImage", "IntegrityLevel")
MODEL_FILENAME = "silrad_incremental.pkl"
METADATA_FILENAME = "incremental_metadata.json"
MAX_ROWS = 250_000
VALIDATION_FRACTION = 0.20


def _read_rows(path: Path) -> list[tuple[dict[str, float], int]]:
    rows = []
    with Path(path).open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or LABEL_COLUMN not in reader.fieldnames:
            raise ValueError("SILRAD CSV must contain the class label column.")
        missing = set(FEATURE_COLUMNS) - set(reader.fieldnames)
        if missing:
            raise ValueError("SILRAD CSV is missing required feature columns: " + ", ".join(sorted(missing)))
        if len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError("SILRAD CSV contains duplicate column names.")
        for line_number, row in enumerate(reader, 2):
            if len(rows) >= MAX_ROWS:
                raise ValueError(f"SILRAD file exceeds the {MAX_ROWS:,} row safety limit.")
            try:
                label = int(row[LABEL_COLUMN])
                if label not in (0, 1):
                    raise ValueError("class must be 0 or 1")
                features = {name: float(row[name]) for name in FEATURE_COLUMNS}
                if not all(math.isfinite(value) for value in features.values()):
                    raise ValueError("features must be finite numbers")
            except (ValueError, TypeError, KeyError) as exc:
                raise ValueError(f"SILRAD CSV line {line_number}: invalid label or numeric feature") from exc
            rows.append((features, label))
    if not rows or len({label for _, label in rows}) != 2:
        raise ValueError("SILRAD evaluation requires rows from both classes.")
    return rows


def _new_model():
    return forest.ARFClassifier(
        n_models=10,
        max_features="sqrt",
        lambda_value=6,
        drift_detector=drift.ADWIN(delta=0.002),
        warning_detector=drift.ADWIN(delta=0.01),
        grace_period=50,
        leaf_prediction="nb",
        seed=42,
    )


def _rates(labels: list[int], probabilities: list[float], threshold: float) -> dict:
    tp = tn = fp = fn = 0
    for label, probability in zip(labels, probabilities):
        predicted = probability >= threshold
        if label and predicted:
            tp += 1
        elif label:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    ratio = lambda numerator, denominator: numerator / denominator if denominator else None
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = ratio(2 * tp, 2 * tp + fp + fn)
    f2 = ratio(5 * tp, 5 * tp + 4 * fn + fp)
    return {
        "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "metrics": {
            "accuracy": ratio(tp + tn, len(labels)),
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "f2": f2,
            "false_positive_rate": ratio(fp, fp + tn),
        },
    }


def _select_threshold(labels: list[int], probabilities: list[float]) -> tuple[float, dict]:
    """Select an F2 (recall-weighted) operating point using training validation only."""
    best = None
    for step in range(1, 100):
        threshold = step / 100
        result = _rates(labels, probabilities, threshold)
        metrics = result["metrics"]
        # Prefer higher precision and then a higher threshold when F2 ties.
        key = (metrics["f2"] or 0.0, metrics["precision"] or 0.0, threshold)
        if best is None or key > best[0]:
            best = (key, threshold, result)
    return best[1], best[2]


def train_model(train_csv: Path, model_dir: Path) -> dict:
    """Fit ARF in stream order and choose its threshold on a train-only tail split."""
    rows = _read_rows(train_csv)
    split = int(len(rows) * (1 - VALIDATION_FRACTION))
    if split < 2 or split >= len(rows):
        raise ValueError("SILRAD training data is too small for stream validation.")
    train_rows, validation_rows = rows[:split], rows[split:]
    if len({label for _, label in train_rows}) < 2 or len({label for _, label in validation_rows}) < 2:
        raise ValueError("The ordered SILRAD training split must contain both classes in train and validation portions.")

    validation_model = _new_model()
    for features, label in train_rows:
        validation_model.learn_one(features, label)
    validation_probabilities = [
        float(validation_model.predict_proba_one(features).get(1, 0.0))
        for features, _ in validation_rows
    ]
    validation_labels = [label for _, label in validation_rows]
    threshold, validation_result = _select_threshold(validation_labels, validation_probabilities)

    # Refit from scratch over the full published training stream only.
    model = _new_model()
    for features, label in rows:
        model.learn_one(features, label)

    model_dir = Path(model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / MODEL_FILENAME
    with model_path.open("wb") as stream:
        pickle.dump(model, stream, protocol=pickle.HIGHEST_PROTOCOL)

    counts = Counter(label for _, label in rows)
    metadata = {
        "model_type": "silrad_style_adaptive_random_forest",
        "display_name": "RansomShield Adaptive Stream Model",
        "source": SOURCE,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "training_rows": len(rows),
        "training_class_counts": {"benign": counts[0], "ransomware": counts[1]},
        "feature_columns": list(FEATURE_COLUMNS),
        "feature_representation": "Publisher-provided numeric SILRAD feature values",
        "algorithm": "Adaptive Random Forest with per-tree ADWIN drift and warning detectors; Naive Bayes leaves",
        "threshold": threshold,
        "threshold_selection": "Maximum F2 on the final 20% of the published training split; the test stream is not used to choose the threshold.",
        "validation": {
            "rows": len(validation_rows),
            "threshold": threshold,
            **validation_result,
        },
        "model_file": MODEL_FILENAME,
        "limitations": [
            "SILRAD-style implementation, not a bit-for-bit reproduction of the paper.",
            "Validation is the final 20% of the publisher's training file in row order; test labels are excluded from threshold selection and are used only after each prequential prediction to update the next one.",
            "The benchmark is event-level and does not validate live endpoint detection.",
            "Threshold selection favors recall (F2); false positives may increase.",
            "Prequential evaluation uses each known SILRAD test label only after that event is predicted, to update the model for the next event.",
            "This offline benchmark has labels; a live endpoint needs a trusted delayed-label source before supervised online updates are safe.",
        ],
    }
    (model_dir / METADATA_FILENAME).write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def evaluate_test(test_csv: Path, model_dir: Path, predictions_csv: Path | None = None) -> dict:
    """Evaluate a labeled stream prequentially: predict first, then learn its label."""
    model_dir = Path(model_dir)
    metadata = json.loads((model_dir / METADATA_FILENAME).read_text(encoding="utf-8"))
    if metadata.get("model_type") != "silrad_style_adaptive_random_forest":
        raise ValueError("The prepared incremental SILRAD model is missing or unsupported.")
    model_path = model_dir / metadata["model_file"]
    if model_path.parent.resolve() != model_dir.resolve() or not model_path.is_file():
        raise ValueError("The prepared incremental model artifact is missing or invalid.")
    with model_path.open("rb") as stream:
        model = pickle.load(stream)
    frozen_model = copy.deepcopy(model)

    rows = _read_rows(test_csv)
    threshold = float(metadata["threshold"])
    labels = [label for _, label in rows]
    frozen_probabilities = [
        float(frozen_model.predict_proba_one(features).get(1, 0.0))
        for features, _ in rows
    ]
    probabilities = []
    for features, label in rows:
        # Strict prequential order: no current-row label is visible until after
        # this row has already been predicted.
        probabilities.append(float(model.predict_proba_one(features).get(1, 0.0)))
        model.learn_one(features, label)
    result = _rates(labels, probabilities, threshold)
    frozen_result = _rates(labels, frozen_probabilities, threshold)
    if predictions_csv:
        with Path(predictions_csv).open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow([
                "row_number", "actual_class", "predicted_class", "probability",
                "frozen_predicted_class", "frozen_probability", "correct",
            ])
            for number, (label, probability, frozen_probability) in enumerate(zip(labels, probabilities, frozen_probabilities), 1):
                prediction = int(probability >= threshold)
                frozen_prediction = int(frozen_probability >= threshold)
                writer.writerow([
                    number, label, prediction, f"{probability:.8f}", frozen_prediction,
                    f"{frozen_probability:.8f}", int(label == prediction),
                ])
    return {
        "dataset": "SILRAD publisher-provided held-out test split",
        "source": SOURCE,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "dataset_schema": "silrad",
        "record_unit": "Sysmon events",
        "model_name": metadata["display_name"],
        "model_type": metadata["model_type"],
        "threshold": threshold,
        "windows": len(rows),
        "traces": None,
        **result,
        "frozen_model_evaluation": {
            "confusion_matrix": frozen_result["confusion_matrix"],
            "metrics": frozen_result["metrics"],
            "evaluation_role": "diagnostic only; frozen at the end of training, no test-stream learning",
        },
        "class_counts": {"benign": sum(label == 0 for label in labels), "ransomware": sum(label == 1 for label in labels)},
        "suspicious_count": sum(probability >= threshold for probability in probabilities),
        "max_probability": max(probabilities, default=0.0),
        "evaluation_role": "prequential online stream: each row is predicted first, then its known dataset label updates the model for the next row",
        "label_availability": "SILRAD supplies labels for this offline benchmark; live endpoints do not provide immediate verified labels",
        "limitations": metadata["limitations"],
        "predictions": [],
    }
