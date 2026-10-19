"""Train a separate XGBoost model on published MLRan records, excluding labels/IDs.

MLRan's feature matrix is tabular. It must not be passed off as temporal TCN data.
"""
import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import xgboost as xgb

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.mlran import read_csv, row_hash, metrics, sha256, SOURCE


def clean_unique(records, indices):
    groups = defaultdict(list)
    for record in records:
        groups[row_hash(record["features"][indices])].append(record)
    clean = [values[0] for values in groups.values() if len({v["label"] for v in values}) == 1]
    return clean, {"input_samples": len(records), "unique_vectors": len(groups),
                   "ambiguous_vector_groups_removed": sum(len({v["label"] for v in group}) > 1 for group in groups.values()),
                   "retained_samples": len(clean)}


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=root/"data/mlran")
    parser.add_argument("--output-dir", type=Path, default=root/"app/artifacts/mlran")
    parser.add_argument("--seed", type=int, default=20261014)
    args = parser.parse_args()
    descriptions = json.loads((args.data_dir/"RFE_selected_feature_names_dic.json").read_text(encoding="utf-8"))
    with (args.data_dir/"MLRan_X_train_RFE.csv").open() as stream:
        all_features = [name for name in next(csv.reader(stream)) if name not in {"sample_id", "sample_type", "family_label", "type_label"}]
    if set(all_features) != set(descriptions):
        parser.error("Published feature dictionary does not match matrix")
    # Avoid sandbox verdict/signature fields and high-cardinality string/system fingerprints.
    features = [name for name in all_features if descriptions[name].split(":")[0] in {"API", "FILE", "DIRECTORY", "REG", "DROP"}]
    indices = [all_features.index(name) for name in features]
    original_train = read_csv(args.data_dir/"MLRan_X_train_RFE.csv", all_features)
    original_test = read_csv(args.data_dir/"MLRan_X_test_RFE.csv", all_features)
    if {r["sample_id"] for r in original_train} & {r["sample_id"] for r in original_test}:
        parser.error("Published train/test sample IDs overlap")
    with (args.data_dir/"MLRan_labels.csv").open() as stream:
        labels = {r["sample_id"]: int(r["sample_type"]) for r in csv.DictReader(stream)}
    if any(labels.get(r["sample_id"]) != r["label"] for r in original_train + original_test):
        parser.error("Labels disagree with published label file")
    train, train_audit = clean_unique(original_train, indices)
    test_unique, test_audit = clean_unique(original_test, indices)
    train_hashes = {row_hash(r["features"][indices]) for r in train}
    # Remove all original train vectors from evaluation, including ambiguous ones.
    all_train_hashes = {row_hash(r["features"][indices]) for r in original_train}
    test = [r for r in test_unique if row_hash(r["features"][indices]) not in all_train_hashes]
    test_audit["train_overlap_vectors_removed"] = len(test_unique) - len(test)
    test_audit["retained_samples"] = len(test)
    if any(len({r["label"] for r in split}) != 2 for split in (train, test)):
        parser.error("Both classes are required in cleaned train and test sets")
    matrix = lambda records: np.stack([r["features"][indices] for r in records])
    params = {"max_depth": 4, "eta": .05, "subsample": .9, "colsample_bytree": .9,
              "objective": "binary:logistic", "eval_metric": "logloss", "seed": args.seed, "nthread": 1}
    booster = xgb.train(params, xgb.DMatrix(matrix(train), label=[r["label"] for r in train]), num_boost_round=160)
    probabilities = booster.predict(xgb.DMatrix(matrix(test)))
    scores, confusion = metrics([r["label"] for r in test], probabilities, .5)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    booster.save_model(args.output_dir/"xgboost_model.json")
    limitations = [
        "Published MLRan tabular features; this model is XGBoost, not a temporal TCN validation.",
        "Publisher-preselected feature matrix; upstream selection and collection biases are not independently eliminated.",
        "Train/test IDs and exact selected-feature vectors are disjoint after documented cleaning; no family-disjoint or prospective test is claimed.",
        "Risk score is model probability, not a calibrated estimate of real-world infection risk.",
        "File indicators are binary recorded evidence; uploaded paths are never accessed or executed."]
    provenance = {p.name: sha256(p) for p in args.data_dir.glob("*.csv") if p.name.startswith(('MLRan_', 'mlran_dataset_'))}
    model = {"model_type": "mlran_xgboost_tabular", "display_name": "XGBoost — published MLRan",
             "input_features": all_features, "feature_names": features, "feature_descriptions": descriptions,
             "xgboost_artifact": "xgboost_model.json", "decision_threshold": .5,
             "trained_at": datetime.now(timezone.utc).isoformat(), "training_feature_hashes": sorted(train_hashes),
             "training": {"source": SOURCE, "seed": args.seed, "training_samples": len(train), "test_samples": len(test),
                          "original_train_samples": len(original_train), "original_test_samples": len(original_test),
                          "training_classes": dict(Counter(str(r['label']) for r in train)),
                          "test_classes": dict(Counter(str(r['label']) for r in test)),
                          "train_audit": train_audit, "test_audit": test_audit,
                          "excluded_domains": ["SIGNATURE", "STRING", "SYSTEM"],
                          "input_sha256": provenance, "parameters": params, "boost_rounds": 160},
             "metrics": scores, "confusion_matrix": confusion, "limitations": limitations}
    (args.output_dir/"model.json").write_text(json.dumps(model, indent=2)+"\n", encoding="utf-8")
    with (args.data_dir/"heldout.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["sample_id", "sample_type", *all_features])
        for record in test:
            writer.writerow([record["sample_id"], record["label"], *record["features"].astype(int).tolist()])
    report = {k: model[k] for k in ("display_name", "trained_at", "training", "metrics", "confusion_matrix", "limitations")}
    report["model_sha256"] = {p.name: sha256(p) for p in args.output_dir.glob("*.json")}
    report["heldout_csv_sha256"] = sha256(args.data_dir/"heldout.csv")
    (args.data_dir/"training_report.json").write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
