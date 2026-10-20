import unittest
from uuid import uuid4

from app import create_app
from app.extensions import db
from app.models import Alert, MonitoringEvent, User


class EndpointAgentApiTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({
            "TESTING": True, "WTF_CSRF_ENABLED": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "AGENT_API_TOKEN": "test-agent-secret",
            "AGENT_OWNER_EMAIL": "agent-owner@example.invalid",
            "RESPONSE_EMAIL_TO": "", "RESPONSE_WEBHOOK_URL": "",
        })
        self.client = self.app.test_client()
        with self.app.app_context():
            db.session.add(User(full_name="Agent owner", email="agent-owner@example.invalid", password_hash="unused"))
            db.session.commit()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_rejects_missing_or_invalid_agent_token(self):
        response = self.client.post("/api/agent/events", json={})
        self.assertEqual(response.status_code, 401)
        response = self.client.post("/api/agent/events", json={}, headers={"Authorization": "Bearer wrong"})
        self.assertEqual(response.status_code, 401)

    def test_accepts_event_and_deduplicates_retries(self):
        payload = {"event_id": str(uuid4()), "agent": "windows-vm", "operation": "created", "path": "safe/file.txt"}
        headers = {"Authorization": "Bearer test-agent-secret"}
        first = self.client.post("/api/agent/events", json=payload, headers=headers)
        second = self.client.post("/api/agent/events", json=payload, headers=headers)
        self.assertEqual(first.status_code, 202)
        self.assertFalse(first.json["duplicate"])
        self.assertTrue(second.json["duplicate"])
        with self.app.app_context():
            event = MonitoringEvent.query.filter_by(source="agent").one()
            owner = User.query.filter_by(email="agent-owner@example.invalid").one()
            self.assertEqual(event.user_id, owner.id)

    def test_rejects_traversal_and_invalid_operation(self):
        headers = {"Authorization": "Bearer test-agent-secret"}
        for payload in (
            {"event_id": str(uuid4()), "agent": "vm", "operation": "created", "path": "../secret"},
            {"event_id": str(uuid4()), "agent": "vm", "operation": "execute", "path": "a.exe"},
        ):
            self.assertEqual(self.client.post("/api/agent/events", json=payload, headers=headers).status_code, 400)

    def test_remote_burst_uses_persisted_events_to_create_one_alert(self):
        headers = {"Authorization": "Bearer test-agent-secret"}
        for index in range(20):
            payload = {"event_id": str(uuid4()), "agent": "windows-vm", "operation": "modified",
                       "path": f"safe/file-{index}.txt"}
            response = self.client.post("/api/agent/events", json=payload, headers=headers)
        self.assertEqual(response.status_code, 202)
        self.assertTrue(response.json["alert_created"])
        with self.app.app_context():
            alert = Alert.query.filter_by(model_version="endpoint-agent-burst-v1").one()
            self.assertIn("20 distinct file changes", alert.details)
            self.assertEqual(alert.user_id, User.query.filter_by(email="agent-owner@example.invalid").one().id)

    def test_agent_rejects_events_without_a_configured_existing_account_owner(self):
        headers = {"Authorization": "Bearer test-agent-secret"}
        with self.app.app_context():
            self.app.config["AGENT_OWNER_EMAIL"] = "missing@example.invalid"
        payload = {"event_id": str(uuid4()), "agent": "vm", "operation": "created", "path": "file.txt"}
        response = self.client.post("/api/agent/events", json=payload, headers=headers)
        self.assertEqual(response.status_code, 503)
        with self.app.app_context():
            self.assertEqual(MonitoringEvent.query.count(), 0)

    def test_agent_names_with_underscores_do_not_mix_other_agents_events(self):
        headers = {"Authorization": "Bearer test-agent-secret"}
        for index in range(19):
            payload = {"event_id": str(uuid4()), "agent": "winXvm", "operation": "modified",
                       "path": f"safe/file-{index}.txt"}
            self.client.post("/api/agent/events", json=payload, headers=headers)
        payload = {"event_id": str(uuid4()), "agent": "win_vm", "operation": "modified",
                   "path": "safe/own-file.txt"}
        response = self.client.post("/api/agent/events", json=payload, headers=headers)
        self.assertEqual(response.status_code, 202)
        self.assertFalse(response.json["alert_created"])


if __name__ == "__main__":
    unittest.main()
