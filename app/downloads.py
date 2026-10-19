"""Authenticated download of packaged RansomShield releases.

Release artifacts live under ``instance/releases`` (gitignored, outside any
statically served directory). A JSON manifest is the only source of truth for
which files may be served; filenames arriving in the URL are matched against it
and re-verified against the filesystem before a byte is sent.
"""
import hashlib
import json
import re
from pathlib import Path

from flask import Blueprint, abort, current_app, jsonify, render_template, send_file
from flask_login import current_user, login_required

from .extensions import db
from .models import DownloadLog

downloads = Blueprint("downloads", __name__, url_prefix="/downloads")

MANIFEST_NAME = "releases.json"
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.(zip|exe|msi|tar\.gz)$")


def release_dir() -> Path:
    root = Path(current_app.config["RELEASE_PATH"]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def manifest() -> dict:
    path = release_dir() / MANIFEST_NAME
    if not path.is_file():
        return {"version": None, "files": [], "notes": "No release has been built yet."}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        current_app.logger.error("Release manifest is unreadable: %s", exc)
        return {"version": None, "files": [], "notes": "Release manifest is unreadable."}
    if not isinstance(data, dict) or not isinstance(data.get("files"), list):
        return {"version": None, "files": [], "notes": "Release manifest is malformed."}
    return data


def _resolve_artifact(filename: str) -> tuple[Path, dict]:
    """Return the artifact path only if the manifest vouches for it."""
    if not SAFE_NAME.match(filename):
        abort(404)
    entry = next((item for item in manifest()["files"] if item.get("name") == filename), None)
    if not isinstance(entry, dict) or not isinstance(entry.get("sha256"), str):
        abort(404)
    root = release_dir()
    path = (root / filename).resolve()
    if path.parent != root or path.is_symlink() or not path.is_file():
        abort(404)
    return path, entry


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@downloads.get("/")
@login_required
def index():
    return render_template("downloads.html", manifest=manifest())


@downloads.get("/<path:filename>")
@login_required
def download(filename: str):
    path, entry = _resolve_artifact(filename)
    digest = sha256_of(path)
    if digest != entry["sha256"]:
        current_app.logger.error("Release %s does not match its manifest hash", filename)
        abort(500, description="Release artifact failed its integrity check; rebuild the release.")
    db.session.add(
        DownloadLog(
            user_id=current_user.id,
            release_version=str(entry.get("version", manifest().get("version") or ""))[:50],
            filename=filename,
            sha256=digest,
        )
    )
    db.session.commit()
    return send_file(path, as_attachment=True, download_name=filename, conditional=True)


@downloads.get("/api/manifest")
@login_required
def manifest_api():
    data = manifest()
    safe = {
        "version": data.get("version"),
        "built_at": data.get("built_at"),
        "notes": data.get("notes", ""),
        "files": [
            {key: item.get(key) for key in ("name", "sha256", "size_bytes", "version", "platform")}
            for item in data.get("files", [])
            if isinstance(item, dict)
        ],
    }
    return jsonify(safe)
