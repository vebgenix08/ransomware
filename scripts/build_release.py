"""Build authenticated-release ZIPs and the manifest served at /downloads.

Never packages secrets, the local database, quarantined evidence or run output.
Usage: python scripts/build_release.py --version 1.2.0
"""
import argparse
import hashlib
import json
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "instance" / "releases"

INCLUDED_PATHS = [
    "app/__init__.py",
    "app/api.py",
    "app/auth.py",
    "app/detector.py",
    "app/downloads.py",
    "app/extensions.py",
    "app/forms.py",
    "app/mlran.py",
    "app/models.py",
    "app/monitor.py",
    "app/response.py",
    "app/routes.py",
    "app/runs.py",
    "app/transfer.py",
    "app/artifacts/behavioral_model.json",
    "app/artifacts/xgboost_model.json",
    "app/artifacts/tcn_weights.npz",
    "app/artifacts/mlran/model.json",
    "app/artifacts/mlran/xgboost_model.json",
    "app/templates/base.html",
    "app/templates/dashboard.html",
    "app/templates/downloads.html",
    "app/templates/index.html",
    "app/templates/auth/signin.html",
    "app/templates/auth/signup.html",
    "migrations/env.py",
    "migrations/alembic.ini",
    "migrations/script.py.mako",
    "migrations/versions/0001_baseline.py",
    "migrations/versions/0002_evidence.py",
    "scripts/evaluate_external.py",
    "scripts/prepare_demo_csv.py",
    "scripts/receive_dataset.py",
    "scripts/send_dataset.py",
    "scripts/train_mlran.py",
    "scripts/train_model.py",
    "run.py",
    "requirements.txt",
    "README.md",
    "ROADMAP.md",
    "TWO_LAPTOP_SETUP.md",
    ".env.example",
]

# Belt-and-braces: refuse to publish if a name or a member ever matches these.
FORBIDDEN_NAMES = {".env", "Laptop1_Sender.zip", "ransomshield.db"}
FORBIDDEN_PARTS = {"instance", ".venv", "venv", "__pycache__", ".git"}
FORBIDDEN_SUFFIXES = (".db", ".key", ".pem", ".log", ".pyc")

VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def forbidden(relative: Path) -> bool:
    return (
        relative.name in FORBIDDEN_NAMES
        or relative.name.endswith(FORBIDDEN_SUFFIXES)
        or bool(FORBIDDEN_PARTS & set(relative.parts))
    )


def build_zip(output: Path, members: list[Path], prefix: str) -> None:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in members:
            relative = path.relative_to(ROOT)
            if forbidden(relative):
                raise ValueError(f"Refusing to package sensitive path: {relative.as_posix()}")
            archive.write(path, arcname=f"{prefix}/{relative.as_posix()}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="Semantic version, e.g. 1.2.0")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--notes", default="")
    args = parser.parse_args()
    if not VERSION.match(args.version):
        parser.error("--version must look like 1.2.0")

    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)

    members = []
    for relative in INCLUDED_PATHS:
        path = ROOT / relative
        if not path.is_file():
            print(f"missing: {relative}", file=sys.stderr)
            return 1
        members.append(path)

    prefix = f"ransomshield-{args.version}"
    agent = output / f"ransomshield-agent-{args.version}-win64.zip"
    build_zip(agent, members, prefix)

    sender_members = [ROOT / "scripts/send_dataset.py", ROOT / "data/safe_demo.csv"]
    sender = output / f"ransomshield-sender-{args.version}.zip"
    build_zip(sender, sender_members, f"{prefix}-sender")

    built_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    files = []
    for path, platform, notes in (
        (agent, "Windows", "Full application: dashboard, detector, migrations and transfer receiver."),
        (sender, "Windows / Python 3.11+", "Laptop 1 sender only: no model, credentials or database."),
    ):
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            leaked = [n for n in names if forbidden(Path(n))]
            if leaked:
                print(f"refusing to publish {path.name}: {leaked}", file=sys.stderr)
                return 1
            bad = archive.testzip()
            if bad:
                print(f"corrupt member in {path.name}: {bad}", file=sys.stderr)
                return 1
        files.append(
            {
                "name": path.name,
                "version": args.version,
                "platform": platform,
                "sha256": sha256(path),
                "size_bytes": path.stat().st_size,
                "notes": notes,
            }
        )

    manifest = {
        "version": args.version,
        "built_at": built_at,
        "notes": args.notes or "Release built from the local working tree.",
        "files": files,
    }
    manifest_path = output / "releases.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    # Read the manifest back so a partially written file cannot be published.
    if json.loads(manifest_path.read_text(encoding="utf-8")) != manifest:
        print("manifest failed read-back verification", file=sys.stderr)
        return 1
    for item in files:
        if sha256(output / item["name"]) != item["sha256"]:
            print(f"checksum mismatch after write: {item['name']}", file=sys.stderr)
            return 1

    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
