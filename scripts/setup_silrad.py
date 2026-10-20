"""Download the published SILRAD splits locally and train this app's benchmark model.

The dataset is not bundled with the application. Keep the downloaded files and
derived model on the local machine; the upstream repository does not declare a
redistribution license.
"""
import argparse
import hashlib
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
ARCHIVE_URL = "https://raw.githubusercontent.com/JamilIsp/SILRAD-dataset/main/SILRAD-dataset.zip"
EXPECTED = {"fasttext-trainmodel.csv", "fasttext-testmodel.csv"}
MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_EXTRACTED_BYTES = 150 * 1024 * 1024


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepare(output_dir, archive_path=None, force=False):
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = Path(archive_path).resolve() if archive_path else output_dir / "silrad-source.zip"
    if not archive_path.exists():
        request = urllib.request.Request(ARCHIVE_URL, headers={"User-Agent": "RansomShield local research setup"})
        with urllib.request.urlopen(request, timeout=30) as response, archive_path.open("wb") as target:
            size = 0
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_ARCHIVE_BYTES:
                    raise ValueError("SILRAD archive exceeded the 20 MB download limit.")
                target.write(chunk)
    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("SILRAD archive exceeded the 20 MB download limit.")

    targets = {name: output_dir / name for name in EXPECTED}
    if not force and any(path.exists() for path in [*targets.values(), output_dir / "model.json", output_dir / "metadata.json"]):
        raise FileExistsError("SILRAD files or model already exist. Use --force to replace them.")
    with zipfile.ZipFile(archive_path) as archive:
        members = {Path(info.filename).name: info for info in archive.infolist() if not info.is_dir()}
        if not EXPECTED.issubset(members):
            raise ValueError("Archive does not contain the expected SILRAD train and test CSV files.")
        if sum(members[name].file_size for name in EXPECTED) > MAX_EXTRACTED_BYTES:
            raise ValueError("SILRAD data exceeds the 150 MB extracted-data limit.")
        for name, target in targets.items():
            if target.exists() and force:
                target.unlink()
            with archive.open(members[name]) as source, target.open("wb") as destination:
                while chunk := source.read(1024 * 1024):
                    destination.write(chunk)

    from app.silrad import evaluate_test, train_model
    metadata = train_model(targets["fasttext-trainmodel.csv"], output_dir)
    metrics = evaluate_test(targets["fasttext-testmodel.csv"], output_dir)
    metadata["heldout_evaluation"] = metrics
    (output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return {
        "directory": str(output_dir),
        "archive_sha256": sha256(archive_path),
        "training_sha256": metadata["training_file_sha256"],
        "test_sha256": metrics["dataset_sha256"],
        "training_rows": metadata["training_rows"],
        "test_rows": metrics["windows"],
        "class_counts": metrics["class_counts"],
        "threshold": metrics["threshold"],
        "confusion_matrix": metrics["confusion_matrix"],
        "metrics": metrics["metrics"],
        "limitations": metrics["limitations"],
    }


def main():
    parser = argparse.ArgumentParser(description="Prepare the local SILRAD benchmark model and held-out test split.")
    parser.add_argument("--output", default=str(Path("instance") / "silrad"), help="Local output directory (default: instance/silrad).")
    parser.add_argument("--archive", help="Use a previously downloaded SILRAD ZIP instead of downloading it.")
    parser.add_argument("--force", action="store_true", help="Replace existing SILRAD files and model.")
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.output, args.archive, args.force), indent=2))
    except Exception as exc:
        print(f"SILRAD setup failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
