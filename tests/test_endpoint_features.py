import hashlib
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app import create_app
from app.extensions import db
from app.models import AgentCommand, AgentDevice, Alert, MonitoringEvent, User


class EndpointFeatureApiTests(unittest.TestCase):
    def setUp(self):
        self.device_id = str(uuid4())
        self.app = create_app({
            "TESTING": True, "WTF_CSRF_ENABLED": False,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "AGENT_API_TOKEN": "agent-secret",
            "AGENT_OWNER_EMAIL": "owner@example.invalid",
        })
        self.client = self.app.test_client()
        with self.app.app_context():
            self.owner = User(full_name="Owner", email="owner@example.invalid", password_hash="unused")
            db.session.add(self.owner)
            db.session.commit()
            self.owner_id = self.owner.id
        with self.client.session_transaction() as session:
            session["_user_id"] = str(self.owner_id)
            session["_fresh"] = True
        self.agent_headers = {"Authorization": "Bearer agent-secret"}

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def register_device(self, label="work-laptop"):
        return self.client.post("/api/agent/heartbeat", json={
            "device_id": self.device_id, "agent": label,
            "folder_name": "test-folder", "agent_version": "1.0.0",
        }, headers=self.agent_headers)

    def create_burst_alert(self, label="work-laptop"):
        self.register_device(label)
        result = None
        for index in range(20):
            result = self.client.post("/api/agent/events", json={
                "event_id": str(uuid4()), "device_id": self.device_id,
                "agent": label, "folder_name": "test-folder", "operation": "modified",
                "path": f"safe/file-{index}.txt", "observed_at": datetime.now(timezone.utc).isoformat(),
            }, headers=self.agent_headers)
        self.assertTrue(result.json["alert_created"])
        with self.app.app_context():
            return Alert.query.filter_by(model_version="endpoint-agent-burst-v1").one().id

    def test_device_checkins_show_online_status_and_last_event(self):
        self.assertEqual(self.register_device().status_code, 200)
        devices = self.client.get("/api/devices").json["devices"]
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["status"], "online")
        self.assertEqual(devices[0]["folder_name"], "test-folder")

    def test_manual_endpoint_quarantine_and_restore_are_explicit_commands(self):
        alert_id = self.create_burst_alert()
        alert_response = self.client.get("/api/alerts?limit=10&status=all")
        alert = next(item for item in alert_response.json["alerts"] if item["id"] == alert_id)
        path = next(entry["value"][0]["path"] for entry in alert["rule_trace"]
                    if entry["signal"] == "affected_files")

        queued = self.client.post(f"/api/agents/{self.device_id}/quarantine/{alert_id}", json={"path": path})
        self.assertEqual(queued.status_code, 202)
        command_id = queued.json["command"]["command_id"]
        commands = self.client.get(f"/api/agent/commands?device_id={self.device_id}", headers=self.agent_headers)
        self.assertEqual(commands.status_code, 200)
        self.assertEqual(commands.json["commands"][0]["command_id"], command_id)
        self.assertEqual(commands.json["commands"][0]["payload"]["path"], path)

        digest = hashlib.sha256(b"test file").hexdigest()
        completed = self.client.post(f"/api/agent/commands/{command_id}/result", headers=self.agent_headers, json={
            "device_id": self.device_id, "status": "completed",
            "result": {"status": "quarantined", "path": path,
                       "quarantine_key": f"{command_id}/{path}", "sha256": digest, "size_bytes": 9},
        })
        self.assertEqual(completed.status_code, 200)
        listing = self.client.get("/api/devices").json["quarantine"]
        item = next(row for row in listing if row["command_id"] == command_id)
        self.assertEqual(item["status"], "completed")
        self.assertIn("not uploaded", item["display_destination"])

        restore = self.client.post(f"/api/devices/{self.device_id}/quarantine/{command_id}/restore")
        self.assertEqual(restore.status_code, 202)
        restore_command = self.client.get(f"/api/agent/commands?device_id={self.device_id}", headers=self.agent_headers).json["commands"][0]
        self.assertEqual(restore_command["action"], "restore")
        self.assertEqual(restore_command["payload"]["path"], path)
        restore_result = self.client.post(f"/api/agent/commands/{restore_command['command_id']}/result",
                                          headers=self.agent_headers, json={
            "device_id": self.device_id, "status": "completed",
            "result": {"status": "restored", "path": path, "sha256": digest, "size_bytes": 9},
        })
        self.assertEqual(restore_result.status_code, 200)
        listing = self.client.get("/api/devices").json["quarantine"]
        self.assertTrue(next(row for row in listing if row["command_id"] == command_id)["restored"])

    def test_agent_cannot_claim_command_complete_with_mismatched_path(self):
        alert_id = self.create_burst_alert()
        alert = next(item for item in self.client.get("/api/alerts?limit=10&status=all").json["alerts"]
                     if item["id"] == alert_id)
        path = next(entry["value"][0]["path"] for entry in alert["rule_trace"]
                    if entry["signal"] == "affected_files")
        queued = self.client.post(f"/api/agents/{self.device_id}/quarantine/{alert_id}", json={"path": path})
        command_id = queued.json["command"]["command_id"]
        response = self.client.post(f"/api/agent/commands/{command_id}/result", headers=self.agent_headers, json={
            "device_id": self.device_id, "status": "completed",
            "result": {"status": "quarantined", "path": "other.txt",
                       "quarantine_key": f"{command_id}/other.txt", "sha256": "a" * 64, "size_bytes": 3},
        })
        self.assertEqual(response.status_code, 400)

    def test_quarantine_request_rejects_unlisted_file_and_wrong_user(self):
        alert_id = self.create_burst_alert()
        result = self.client.post(f"/api/agents/{self.device_id}/quarantine/{alert_id}", json={"path": "not-in-alert.txt"})
        self.assertEqual(result.status_code, 400)

    def test_endpoint_quarantine_refuses_a_deleted_alert_path(self):
        self.register_device("work-laptop")
        for index in range(10):
            self.client.post("/api/agent/events", json={
                "event_id": str(uuid4()), "device_id": self.device_id,
                "agent": "work-laptop", "folder_name": "test-folder", "operation": "deleted",
                "path": f"safe/gone-{index}.txt",
            }, headers=self.agent_headers)
        with self.app.app_context():
            alert = Alert.query.filter_by(model_version="endpoint-agent-burst-v1").one()
            alert_id = alert.id
        response = self.client.post(f"/api/agents/{self.device_id}/quarantine/{alert_id}",
                                    json={"path": "safe/gone-0.txt"})
        self.assertEqual(response.status_code, 409)

    def test_activity_filters_export_and_policy_preview(self):
        self.register_device("activity-laptop")
        for index in range(6):
            self.client.post("/api/agent/events", headers=self.agent_headers, json={
                "event_id": str(uuid4()), "device_id": self.device_id, "agent": "activity-laptop",
                "folder_name": "test-folder", "operation": "modified", "path": f"edited/{index}.txt",
            })
        filtered = self.client.get(f"/api/events?limit=50&source=agent&action=modified&device={self.device_id}")
        self.assertEqual(filtered.status_code, 200)
        self.assertEqual(len(filtered.json["events"]), 6)
        export = self.client.get(f"/api/events/export.csv?limit=50&source=agent&device={self.device_id}")
        self.assertEqual(export.status_code, 200)
        self.assertIn("edited/0.txt", export.get_data(as_text=True))

        preview = self.client.post("/api/monitor/policy/simulate", json={
            "window_seconds": 30, "delete_threshold": 10, "modify_threshold": 5,
            "mixed_threshold": 30, "mixed_destructive_minimum": 10,
        })
        self.assertEqual(preview.status_code, 200)
        self.assertGreaterEqual(preview.json["would_alert_count"], 1)
        self.assertIn("cannot tell false alarms", preview.json["note"])


class EndpointQuarantineFileOperationTests(unittest.TestCase):
    def test_quarantine_then_restore_keeps_content_local(self):
        from scripts.windows_endpoint_agent import execute_endpoint_command

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "watched"
            root.mkdir()
            quarantine = Path(directory) / "local-app-data" / "RansomShield" / "quarantine"
            original = root / "nested" / "sample.txt"
            original.parent.mkdir()
            original.write_bytes(b"safe test file")
            device_id, command_id = str(uuid4()), str(uuid4())
            result = execute_endpoint_command({"command_id": command_id, "action": "quarantine",
                                               "payload": {"path": "nested/sample.txt"}},
                                              root, quarantine, device_id)
            self.assertFalse(original.exists())
            stored = quarantine / device_id / command_id / "nested" / "sample.txt"
            self.assertEqual(stored.read_bytes(), b"safe test file")
            self.assertEqual(result["size_bytes"], 14)
            self.assertNotIn("contents", result)
            retry = execute_endpoint_command({"command_id": command_id, "action": "quarantine",
                                              "payload": {"path": "nested/sample.txt"}},
                                             root, quarantine, device_id)
            self.assertEqual(retry, result)

            restored = execute_endpoint_command({"command_id": str(uuid4()), "action": "restore",
                                                 "payload": {"quarantine_command_id": command_id,
                                                             "quarantine_key": result["quarantine_key"],
                                                             "path": "nested/sample.txt"}},
                                                root, quarantine, device_id)
            self.assertEqual(restored["status"], "restored")
            self.assertEqual(original.read_bytes(), b"safe test file")
            restored_retry = execute_endpoint_command({"command_id": "" + str(uuid4()), "action": "restore",
                                                       "payload": {"quarantine_command_id": command_id,
                                                                   "quarantine_key": result["quarantine_key"],
                                                                   "path": "nested/sample.txt"}},
                                                      root, quarantine, device_id)
            self.assertEqual(restored_retry["status"], "restored")

    def test_restore_never_overwrites_an_existing_file(self):
        from scripts.windows_endpoint_agent import execute_endpoint_command

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "watched"
            root.mkdir()
            quarantine = Path(directory) / "quarantine"
            original = root / "test.txt"
            original.write_text("original", encoding="utf-8")
            device_id, command_id = str(uuid4()), str(uuid4())
            result = execute_endpoint_command({"command_id": command_id, "action": "quarantine",
                                               "payload": {"path": "test.txt"}}, root, quarantine, device_id)
            original.write_text("new file", encoding="utf-8")
            with self.assertRaisesRegex(FileExistsError, "not overwritten"):
                execute_endpoint_command({"command_id": str(uuid4()), "action": "restore",
                                          "payload": {"quarantine_command_id": command_id,
                                                      "quarantine_key": result["quarantine_key"],
                                                      "path": "test.txt"}}, root, quarantine, device_id)
            self.assertEqual(original.read_text(encoding="utf-8"), "new file")

    def test_tampered_endpoint_quarantine_file_is_not_restored(self):
        from scripts.windows_endpoint_agent import execute_endpoint_command

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "watched"
            root.mkdir()
            quarantine = Path(directory) / "quarantine"
            original = root / "test.txt"
            original.write_bytes(b"original")
            device_id, command_id = str(uuid4()), str(uuid4())
            result = execute_endpoint_command({"command_id": command_id, "action": "quarantine",
                                               "payload": {"path": "test.txt"}}, root, quarantine, device_id)
            stored = quarantine / device_id / command_id / "test.txt"
            stored.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "was changed"):
                execute_endpoint_command({"command_id": str(uuid4()), "action": "restore",
                                          "payload": {"quarantine_command_id": command_id,
                                                      "quarantine_key": result["quarantine_key"],
                                                      "path": "test.txt", "expected_sha256": result["sha256"],
                                                      "expected_size_bytes": result["size_bytes"]}},
                                         root, quarantine, device_id)
            self.assertFalse(original.exists())
            self.assertEqual(stored.read_bytes(), b"changed")


class EndpointSchemaMigrationTests(unittest.TestCase):
    def test_fresh_database_migrates_agent_device_and_command_tables(self):
        from sqlalchemy import inspect, text

        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "migration-test.sqlite3"
            app = create_app({
                "TESTING": True,
                "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database.as_posix()}",
                "MONITOR_TARGET_PATH": str(Path(directory) / "monitor"),
                "QUARANTINE_PATH": str(Path(directory) / "quarantine"),
                "RUNS_PATH": str(Path(directory) / "runs"),
                "SILRAD_DATA_DIR": str(Path(directory) / "silrad"),
            })
            with app.app_context():
                tables = set(inspect(db.engine).get_table_names())
                self.assertIn("agent_devices", tables)
                self.assertIn("agent_commands", tables)
                self.assertIn("alembic_version", tables)
                self.assertEqual(db.session.execute(text("SELECT version_num FROM alembic_version")).scalar(),
                                 "0009_agent_devices_commands")
                db.session.remove()
                db.engine.dispose()


if __name__ == "__main__":
    unittest.main()
