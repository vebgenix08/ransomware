import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from app import create_app
from app.downloads import manifest
from app.extensions import db
from app.models import DownloadLog, User


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.releases = self.root / "releases"
        self.releases.mkdir()
        self.app = create_app(dict(
            TESTING=True, WTF_CSRF_ENABLED=False, SQLALCHEMY_DATABASE_URI="sqlite://",
            MONITOR_TARGET_PATH=str(self.root / "decoy"), QUARANTINE_PATH=str(self.root / "quarantine"),
            RUNS_PATH=str(self.root / "runs"), RELEASE_PATH=str(self.releases),
            RESPONSE_WEBHOOK_URL="", RESPONSE_EMAIL_TO="",
        ))
        self.context = self.app.app_context()
        self.context.push()
        self.addCleanup(self.context.pop)
        self.user = User(full_name="Downloader", email="downloads@example.invalid", password_hash="unused")
        db.session.add(self.user)
        db.session.commit()
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session["_user_id"] = str(self.user.id)
            session["_fresh"] = True

    def publish(self, name="ransomshield-agent-1.0.0-win64.zip", payload=b"release payload", version="1.0.0"):
        path = self.releases / name
        path.write_bytes(payload)
        manifest_data = {
            "version": version,
            "built_at": "2026-10-19T00:00:00+00:00",
            "notes": "test",
            "files": [{
                "name": name, "version": version, "platform": "Windows",
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size_bytes": len(payload), "notes": "",
            }],
        }
        (self.releases / "releases.json").write_text(json.dumps(manifest_data), encoding="utf-8")
        return path

    def test_download_requires_sign_in(self):
        self.publish()
        anonymous = self.app.test_client()
        self.assertEqual(anonymous.get("/downloads/").status_code, 302)
        self.assertEqual(anonymous.get("/downloads/ransomshield-agent-1.0.0-win64.zip").status_code, 302)

    def test_authenticated_download_is_logged_and_served(self):
        payload = b"release payload"
        self.publish(payload=payload)
        response = self.client.get("/downloads/ransomshield-agent-1.0.0-win64.zip")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, payload)
        self.assertIn("attachment", response.headers["Content-Disposition"])
        record = DownloadLog.query.one()
        self.assertEqual(record.user_id, self.user.id)
        self.assertEqual(record.release_version, "1.0.0")
        self.assertEqual(record.sha256, hashlib.sha256(payload).hexdigest())

    def test_unknown_and_traversal_filenames_are_rejected(self):
        self.publish()
        for name in ("../releases.json", "..%2Freleases.json", "releases.json", "other.zip"):
            self.assertEqual(self.client.get(f"/downloads/{name}").status_code, 404, name)
        outside = self.root / "outside.zip"
        outside.write_bytes(b"x")
        self.assertEqual(self.client.get("/downloads/outside.zip").status_code, 404)
        self.assertEqual(DownloadLog.query.count(), 0)

    def test_tampered_artifact_is_refused(self):
        self.publish()
        (self.releases / "ransomshield-agent-1.0.0-win64.zip").write_bytes(b"tampered")
        response = self.client.get("/downloads/ransomshield-agent-1.0.0-win64.zip")
        self.assertEqual(response.status_code, 500)
        self.assertEqual(DownloadLog.query.count(), 0)

    def test_missing_manifest_is_reported_not_crashed(self):
        response = self.client.get("/downloads/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"No release has been built yet", response.data)
        self.assertEqual(manifest()["files"], [])
        self.assertEqual(self.client.get("/downloads/api/manifest").status_code, 200)


if __name__ == "__main__":
    unittest.main()
