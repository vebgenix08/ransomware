"""Explainable rolling file-burst rules shared by every live activity source."""


OPERATIONS = ("created", "modified", "deleted")


def evaluate_burst(paths_by_operation: dict, policy: dict) -> dict:
    paths = {operation: set(paths_by_operation.get(operation, ())) for operation in OPERATIONS}
    all_paths = set().union(*paths.values())
    destructive = paths["modified"] | paths["deleted"]
    counts = {operation: len(paths[operation]) for operation in OPERATIONS}
    checks = [
        {"rule": "Deletion limit", "signal": "deleted_files", "observed": counts["deleted"],
         "threshold": policy["delete_threshold"]},
        {"rule": "Modification limit", "signal": "modified_files", "observed": counts["modified"],
         "threshold": policy["modify_threshold"]},
        {"rule": "Mixed-change limit", "signal": "distinct_files", "observed": len(all_paths),
         "threshold": policy["mixed_threshold"], "requires": {
             "signal": "modified_or_deleted_files", "observed": len(destructive),
             "threshold": policy["mixed_destructive_minimum"]}},
    ]
    checks[0]["triggered"] = counts["deleted"] >= checks[0]["threshold"]
    checks[1]["triggered"] = counts["modified"] >= checks[1]["threshold"]
    checks[2]["triggered"] = (len(all_paths) >= checks[2]["threshold"]
                               and len(destructive) >= checks[2]["requires"]["threshold"])
    score = min(100, round(100 * max(
        counts["deleted"] / policy["delete_threshold"],
        counts["modified"] / policy["modify_threshold"],
        len(all_paths) / policy["mixed_threshold"],
    )))
    severe = (counts["deleted"] >= 2 * policy["delete_threshold"]
              or counts["modified"] >= 2 * policy["modify_threshold"]
              or (len(all_paths) >= 2 * policy["mixed_threshold"]
                  and len(destructive) >= 2 * policy["mixed_destructive_minimum"]))
    return {
        "triggered": any(check["triggered"] for check in checks),
        "severe": severe,
        "score": score,
        "distinct_files": len(all_paths),
        "distinct_file_operations": sum(counts.values()),
        "operation_counts": counts,
        "destructive_files": len(destructive),
        "window_seconds": policy["window_seconds"],
        "checks": checks,
    }


def burst_details(evaluation: dict, prefix: str = "") -> str:
    counts = evaluation["operation_counts"]
    lead = f"{prefix}: " if prefix else ""
    return (f"{lead}{evaluation['distinct_files']} distinct files; "
            f"{evaluation['distinct_file_operations']} distinct file-operation types "
            f"({counts['created']} created, {counts['modified']} modified, {counts['deleted']} deleted) "
            f"within {evaluation['window_seconds']} seconds.")


def synthetic_validation(policy: dict) -> dict:
    """Evaluate deterministic, explicitly labeled example windows (not field data)."""
    scenarios = [
        ("steady_office_work", "benign", {"created": 3, "modified": 2, "deleted": 0}),
        ("legitimate_bulk_import", "benign", {"created": 40, "modified": 0, "deleted": 0}),
        ("backup_snapshot", "benign", {"created": 60, "modified": 0, "deleted": 0}),
        ("routine_cleanup_below_limit", "benign", {"created": 0, "modified": 0,
         "deleted": max(0, policy["delete_threshold"] - 1)}),
        ("small_mixed_maintenance", "benign", {
            "created": max(0, policy["mixed_threshold"] - 1),
            "modified": max(0, min(policy["mixed_destructive_minimum"] - 1,
                                    policy["modify_threshold"] - 1)), "deleted": 0}),
        ("single_document_edit", "benign", {"created": 0, "modified": 1, "deleted": 0}),
        ("legitimate_batch_edit", "benign", {"created": 0, "modified": max(1, policy["modify_threshold"]), "deleted": 0}),
        ("synthetic_modify_burst", "burst", {"created": 0, "modified": max(1, policy["modify_threshold"]), "deleted": 0}),
        ("synthetic_delete_burst", "burst", {"created": 0, "modified": 0, "deleted": max(1, policy["delete_threshold"])}),
        ("synthetic_mixed_burst", "burst", {"created": policy["mixed_threshold"],
         "modified": policy["mixed_destructive_minimum"], "deleted": 0}),
    ]
    rows = []
    tp = fp = tn = fn = 0
    for name, label, counts in scenarios:
        paths = {operation: {f"{name}/{operation}-{index}.dat" for index in range(count)}
                 for operation, count in counts.items()}
        evaluation = evaluate_burst(paths, policy)
        predicted = "burst" if evaluation["triggered"] else "benign"
        if label == "burst" and predicted == "burst": tp += 1
        elif label == "burst": fn += 1
        elif predicted == "burst": fp += 1
        else: tn += 1
        rows.append({"scenario": name, "expected": label, "predicted": predicted,
                     "correct": label == predicted, "evaluation": evaluation})
    return {
        "generator_version": "ransomshield-synthetic-windows-v1",
        "scenario_count": len(rows),
        "confusion_matrix": {"true_positive": tp, "false_positive": fp,
                             "true_negative": tn, "false_negative": fn},
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else None,
        "burst_capture_rate": round(tp / (tp + fn), 4) if tp + fn else None,
        "scenarios": rows,
        "limitations": "These are hand-authored synthetic windows, not measured user activity or an estimate of real-world performance. The legitimate batch-edit case intentionally shows when a threshold can alert on normal work.",
    }
