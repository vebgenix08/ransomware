"""Create safe, explicitly synthetic records for the two-laptop workflow."""
import csv
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.detector import FEATURE_NAMES


def main():
    path = Path(__file__).resolve().parents[1] / "data/safe_demo.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["trace_id", "window_index", "label", *FEATURE_NAMES])
        writer.writeheader()
        for label in (0, 1):
            for index in range(8):
                row = dict.fromkeys(FEATURE_NAMES, 0)
                row.update(cpu_percent=10, memory_percent=30, process_count=100)
                if label:
                    row.update(created_count=24, modified_count=3, deleted_count=5, canary_accessed=1,
                               canary_modified=1, decoy_files_touched=32, directories_touched=5, operation_rate=16)
                writer.writerow(dict(trace_id=f"synthetic_{label}", window_index=index, label=label, **row))
    print(path)


if __name__ == "__main__":
    main()
