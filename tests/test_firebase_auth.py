import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app
from app.extensions import db
from app.models import AnalysisRun, User


class FirebaseAuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.app = create_app({
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "AUTH_PROVIDER": "firebase",
            "FIREBASE_API_KEY": "public-test-key",
            "FIREBASE_AUTH_DOMAIN": "test-project.firebaseapp.com",
            "FIREBASE_PROJECT_ID": "test-project",
            "FIREBASE_MESSAGING_SENDER_ID": "123456789",
            "FIREBASE_APP_ID": "1:123456789:web:test",
            "MONITOR_TARGET_PATH": root / "monitor",
            "QUARANTINE_PATH": root / "quarantine",
            "RUNS_PATH": root / "runs",
            "RESPONSE_WEBHOOK_URL": "",
            "RESPONSE_EMAIL_TO": "",
        })
        self.context = self.app.app_context()
        self.context.push()
        self.addCleanup(self.context.pop)
        self.client = self.app.test_client()

    def test_verified_firebase_user_links_existing_local_account_and_preserves_history(self):
        local_user = User(full_name="Existing User", email="existing@example.test", password_hash="old-hash")
        db.session.add(local_user)
        db.session.commit()
        run = AnalysisRun(id="existing-run", user_id=local_user.id, kind="dataset", status="completed", result={})
        db.session.add(run)
        db.session.commit()

        claims = {"uid": "firebase-uid-1", "email": "existing@example.test", "email_verified": True, "name": "Verified Name"}
        with patch("app.firebase_auth.verify_firebase_id_token", return_value=claims):
            response = self.client.post("/auth/firebase/session", headers={"Authorization": "Bearer valid-token"}, json={})

        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(response.json["next"], "/dashboard")
        self.assertEqual(User.query.count(), 1)
        self.assertEqual(local_user.firebase_uid, "firebase-uid-1")
        self.assertEqual(local_user.full_name, "Verified Name")
        self.assertEqual(AnalysisRun.query.one().user_id, local_user.id)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)

    def test_verified_new_firebase_user_is_created_with_uid_and_unusable_random_password(self):
        claims = {"uid": "firebase-uid-2", "email": "new@example.test", "email_verified": True}
        with patch("app.firebase_auth.verify_firebase_id_token", return_value=claims):
            response = self.client.post("/auth/firebase/session", headers={"Authorization": "Bearer valid-token"}, json={})

        self.assertEqual(response.status_code, 200, response.json)
        user = User.query.one()
        self.assertEqual(user.firebase_uid, "firebase-uid-2")
        self.assertEqual(user.full_name, "new")
        self.assertTrue(user.password_hash)

    def test_unverified_email_cannot_create_app_session_or_account(self):
        claims = {"uid": "firebase-uid-3", "email": "unverified@example.test", "email_verified": False}
        with patch("app.firebase_auth.verify_firebase_id_token", return_value=claims):
            response = self.client.post("/auth/firebase/session", headers={"Authorization": "Bearer valid-token"}, json={})

        self.assertEqual(response.status_code, 403)
        self.assertEqual(User.query.count(), 0)

    def test_missing_token_is_rejected(self):
        response = self.client.post("/auth/firebase/session", json={})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(User.query.count(), 0)

    def test_firebase_config_is_rendered_only_for_enabled_provider(self):
        page = self.client.get("/auth/signin")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"firebase-web-config", page.data)
        self.assertIn(b"test-project.firebaseapp.com", page.data)


if __name__ == "__main__":
    unittest.main()
