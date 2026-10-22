import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "windows_endpoint_agent.py"
SPEC = importlib.util.spec_from_file_location("windows_endpoint_agent", SCRIPT)
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)


class EndpointAgentHelpersTests(unittest.TestCase):
    def test_requires_https_for_remote_servers(self):
        with self.assertRaisesRegex(ValueError, "Use HTTPS"):
            agent.endpoint_url("http://example.com")
        self.assertEqual(agent.endpoint_url("http://127.0.0.1:5000"),
                         "http://127.0.0.1:5000/api/agent/events")
        self.assertEqual(agent.endpoint_url("http://example.com", allow_insecure_http=True),
                         "http://example.com/api/agent/events")

    def test_rejects_server_urls_with_embedded_credentials(self):
        with self.assertRaisesRegex(ValueError, "must not contain credentials"):
            agent.endpoint_url("https://user:secret@example.com")

    def test_agent_label_is_safe_and_bounded(self):
        self.assertEqual(agent.safe_agent_name("Dhanush Laptop / Documents"), "Dhanush-Laptop-Documents")
        self.assertLessEqual(len(agent.safe_agent_name("a" * 100)), 64)
        with self.assertRaises(ValueError):
            agent.safe_agent_name("...")

    def test_remote_paths_reject_traversal_ads_and_windows_device_names(self):
        self.assertEqual(agent.safe_relative_path("folder/report.txt"), ("folder", "report.txt"))
        for path in ("../secret.txt", "C:/Windows/system.ini", "file.txt:secret", "folder/CON.txt"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                agent.safe_relative_path(path)

    def test_pending_events_persist_until_acknowledged(self):
        with tempfile.TemporaryDirectory() as temporary:
            queue = Path(temporary) / "agent.sqlite3"
            store = agent.PendingEventStore(queue)
            payload = {"event_id": "event-1", "agent": "laptop", "operation": "created", "path": "x.txt"}
            store.enqueue(payload)
            store.enqueue(payload)
            self.assertEqual(store.count(), 1)
            restarted = agent.PendingEventStore(queue)
            self.assertEqual(restarted.first(), payload)
            restarted.acknowledge("event-1")
            self.assertEqual(restarted.count(), 0)

    def test_watcher_records_only_paths_inside_selected_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "watched"
            root.mkdir()
            outside = Path(temporary) / "outside.txt"
            with (Path(temporary) / "queue.sqlite3").open("w") as stream:
                stream.write("")
            store = agent.PendingEventStore(Path(temporary) / "queue.sqlite3")
            handler = agent.AgentEventHandler(root, "test-laptop", store)
            handler._record("created", str(root / "sub" / "file.txt"))
            handler._record("created", str(outside))
            event = store.first()
            self.assertEqual(event["path"], "sub/file.txt")
            self.assertEqual(store.count(), 1)


if __name__ == "__main__":
    unittest.main()
