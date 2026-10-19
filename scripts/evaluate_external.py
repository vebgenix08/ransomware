"""Evaluate a frozen detector on independent, ordered telemetry CSV traces."""
import argparse
import csv
import hashlib
import json
import math
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.detector import BehavioralDetector, FEATURE_NAMES


def evaluate(csv_path, model_path, dataset_name, source, threshold=None, mapping=None):
    detector = BehavioralDetector(model_path)
    if not detector.is_ready:
        raise ValueError(f"Model unavailable: {detector.load_error}")
    threshold = detector.model["decision_threshold"] if threshold is None else threshold
    if not math.isfinite(threshold) or not 0 < threshold < 1:
        raise ValueError("Threshold must be between zero and one")
    mapping = mapping or {}
    if any(not isinstance(value, str) or not value for value in mapping.values()):
        raise ValueError("Column mappings must be nonempty strings")
    required = ["trace_id", "window_index", "label", *FEATURE_NAMES]
    if set(mapping) - set(required):
        raise ValueError("Mapping contains unknown canonical columns")
    groups = {}
    with Path(csv_path).open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        missing = [key for key in required if mapping.get(key, key) not in (reader.fieldnames or [])]
        if missing:
            raise ValueError("Missing columns (no implicit zero-filling): " + ", ".join(missing))
        for line, row in enumerate(reader, 2):
            if line > 2001:
                raise ValueError("Maximum 2000 windows per evaluation; split larger datasets by trace")
            try:
                values = {key: row[mapping.get(key, key)] for key in required}
                trace = values["trace_id"].strip()
                index = int(values["window_index"])
                label = int(values["label"])
                features = {key: float(values[key]) for key in FEATURE_NAMES}
                if not trace or index < 0 or label not in (0, 1):
                    raise ValueError("Invalid trace, index, or binary label")
                if any(not math.isfinite(v) or v < 0 for v in features.values()):
                    raise ValueError("Features must be finite and nonnegative")
                if any(features[k] > 100 for k in ("cpu_percent", "memory_percent")):
                    raise ValueError("Percentages must be in [0,100]")
                if any(features[k] not in (0, 1) for k in ("canary_accessed", "canary_modified")):
                    raise ValueError("Canary indicators must be binary")
                groups.setdefault(trace, []).append((index, label, features))
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValueError(f"CSV line {line}: {exc}") from exc
    if not groups:
        raise ValueError("Dataset is empty")
    counts = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    predictions = []
    for trace, windows in sorted(groups.items()):
        windows.sort(key=lambda item: item[0])
        indices = [item[0] for item in windows]
        if indices != list(range(indices[0], indices[0] + len(indices))):
            raise ValueError(f"Trace {trace}: duplicate or nonconsecutive window indices")
        detector.history.clear()
        for index, label, features in windows:
            probability = detector.predict_probability(features)
            predicted = int(probability >= threshold)
            counts["tp" if predicted and label else "fp" if predicted else "fn" if label else "tn"] += 1
            predictions.append({"trace_id": trace, "window_index": index, "label": label, "probability": probability, "prediction": predicted, "observed_activity": features})
    tp, tn, fp, fn = (counts[k] for k in ("tp", "tn", "fp", "fn"))
    ratio = lambda a, b: a / b if b else None
    files = [model_path, model_path.parent / detector.model["tcn_artifact"], model_path.parent / detector.model["xgboost_artifact"]]
    return {
        "dataset": dataset_name, "source": source, "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "dataset_sha256": hashlib.sha256(Path(csv_path).read_bytes()).hexdigest(),
        "model_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
        "threshold": threshold, "column_mapping": mapping, "windows": len(predictions), "traces": len(groups),
        "window_seconds": 2.0,
        "confusion_matrix": counts,
        "metrics": {"accuracy": ratio(tp + tn, len(predictions)), "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn), "f1": ratio(2 * tp, 2 * tp + fp + fn), "false_positive_rate": ratio(fp, fp + tn)},
        "limitations": ["Window-level metrics; correlated windows are not independent samples.", "Initial windows use the detector's repeated-first-window padding.", "Dataset provenance and feature semantics require independent review."] + (["Only one label class is present; this is not a complete validation."] if not (tp + fn and tn + fp) else []),
        "predictions": predictions,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path)
    parser.add_argument("--dataset-name", required=True)
    parser.add_argument("--source", required=True, help="Publication or dataset URL")
    parser.add_argument("--model", type=Path, default=Path(__file__).resolve().parents[1] / "app/artifacts/behavioral_model.json")
    parser.add_argument("--mapping", type=Path, help="JSON canonical-column to input-column mapping")
    parser.add_argument("--threshold", type=float)
    parser.add_argument("--output", type=Path, default=Path("instance/external_evaluation.json"))
    args = parser.parse_args()
    try:
        mapping = json.loads(args.mapping.read_text()) if args.mapping else None
        if mapping is not None and not isinstance(mapping, dict):
            raise ValueError("Mapping must be a JSON object")
        if args.output.resolve() in {args.csv.resolve(), args.model.resolve(), args.mapping.resolve() if args.mapping else None} or args.model.resolve().parent in args.output.resolve().parents:
            raise ValueError("Output must not overwrite an input")
        report = evaluate(args.csv, args.model, args.dataset_name, args.source, args.threshold, mapping)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(args.output), "metrics": report["metrics"]}, indent=2))


if __name__ == "__main__":
    main()
