import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app
from app.detector import FEATURE_NAMES
from app.extensions import db
from app.models import Alert, MonitoringEvent, QuarantineItem, ResponseAction, User
from app.monitor import take_snapshot
from app.response import respond, restore_quarantine
from scripts.evaluate_external import evaluate

MODEL = Path(__file__).resolve().parents[1] / "app/artifacts/behavioral_model.json"


class SafeDefaultsTests(unittest.TestCase):
    def test_automatic_quarantine_is_disabled_by_default(self):
        app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite://"})
        self.assertFalse(app.config["AUTO_QUARANTINE"])


class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "MONITOR_TARGET_PATH": self.root / "decoy", "QUARANTINE_PATH": self.root / "quarantine",
            "RESPONSE_WEBHOOK_URL": "", "RESPONSE_EMAIL_TO": "", "QUARANTINE_MODE": "enabled",
            "AUTO_QUARANTINE": True})
        self.context = self.app.app_context()
        self.context.push()
        self.addCleanup(self.context.pop)
        self.monitor = self.app.extensions["monitoring_service"]

    def alert(self):
        alert = Alert(title="Test", details="Synthetic test", severity="high", risk_score=95)
        db.session.add(alert)
        db.session.commit()
        return alert

    def test_containment_audit_and_idempotence(self):
        target = self.monitor.target_path / "test.txt"
        target.write_text("evidence")
        outside = self.root / "outside.txt"
        outside.write_text("keep")
        alert = self.alert()
        action = respond(self.app, alert, self.monitor.target_path, {"test.txt", "../outside.txt", "missing.txt"})
        db.session.expire_all()
        self.assertTrue(action.completed)
        self.assertFalse(target.exists())
        self.assertEqual(outside.read_text(), "keep")
        self.assertEqual((self.root / "quarantine" / str(alert.id) / "test.txt").read_text(), "evidence")
        self.assertEqual([x["status"] for x in action.result["files"]].count("failed"), 2)
        self.assertEqual(respond(self.app, alert, self.monitor.target_path, {"test.txt"}).id, action.id)
        self.assertEqual(ResponseAction.query.count(), 1)

    def test_disabled_quarantine_and_failed_webhook(self):
        target = self.monitor.target_path / "keep.txt"
        target.write_text("keep")
        self.app.config.update(AUTO_QUARANTINE=False, RESPONSE_WEBHOOK_URL="https://example.invalid/alert")
        with patch("app.response.urlopen", side_effect=OSError("offline")):
            action = respond(self.app, self.alert(), self.monitor.target_path, {"keep.txt"})
        db.session.expire_all()
        self.assertTrue(target.exists())
        self.assertEqual(action.result["notifications"]["webhook"], "failed")
        self.assertEqual(action.result["quarantine"], "disabled")

    def test_successful_notifications(self):
        self.app.config.update(RESPONSE_WEBHOOK_URL="https://example.invalid/alert", RESPONSE_EMAIL_TO="analyst@example.invalid", RESPONSE_EMAIL_FROM="monitor@example.invalid", SMTP_HOST="smtp.example.invalid")
        with patch("app.response.urlopen") as webhook, patch("app.response.smtplib.SMTP") as smtp:
            webhook.return_value.__enter__.return_value.status = 202
            action = respond(self.app, self.alert(), self.monitor.target_path, set())
            self.assertEqual(action.result["notifications"], {"webhook": "sent", "email": "sent"})
            smtp.return_value.__enter__.return_value.send_message.assert_called_once()

    def test_owned_alert_email_goes_to_account_not_global_fallback(self):
        self.app.config.update(RESPONSE_EMAIL_TO="old-recipient@example.invalid",
            RESPONSE_EMAIL_FROM="monitor@example.invalid", SMTP_HOST="smtp.example.invalid")
        user = User(full_name="Account Owner", email="account-owner@example.invalid", password_hash="unused")
        db.session.add(user)
        db.session.commit()
        alert = self.alert()
        alert.user_id = user.id
        db.session.commit()
        with patch("app.response.smtplib.SMTP") as smtp:
            action = respond(self.app, alert, self.monitor.target_path, set())
            message = smtp.return_value.__enter__.return_value.send_message.call_args.args[0]
        self.assertEqual(message["To"], "account-owner@example.invalid")
        self.assertEqual(action.result["notifications"]["email"], "sent")

    def test_alert_email_lists_changed_file_paths(self):
        self.app.config.update(RESPONSE_EMAIL_TO="analyst@example.invalid",
            RESPONSE_EMAIL_FROM="monitor@example.invalid", SMTP_HOST="smtp.example.invalid")
        alert = self.alert()
        alert.model_version = "rolling-file-burst-v1"
        alert.rule_trace = [
            {"signal": "affected_files", "value": [
                {"path": "reports/quarterly.xlsx", "operations": ["created", "modified"]},
                {"path": "notes.txt", "operations": ["deleted"]},
            ]},
        ]
        db.session.commit()
        with patch("app.response.smtplib.SMTP") as smtp:
            respond(self.app, alert, self.monitor.target_path, set())
            message = smtp.return_value.__enter__.return_value.send_message.call_args.args[0]
        plain_body = message.get_body(preferencelist=("plain",)).get_content()
        html_body = message.get_body(preferencelist=("html",)).get_content()
        self.assertIn("Activity | Path", plain_body)
        self.assertIn("created, modified | reports/quarterly.xlsx", plain_body)
        self.assertIn("deleted | notes.txt", plain_body)
        self.assertIn("Affected files (paths relative to monitored folder)", html_body)
        self.assertIn("reports/quarterly.xlsx", html_body)
        self.assertIn("notes.txt", html_body)

    def test_ssl_email_authentication_and_recipient_refusal(self):
        self.app.config.update(RESPONSE_EMAIL_TO="test@example.invalid", RESPONSE_EMAIL_FROM="sender@example.invalid",
            SMTP_HOST="smtp.example.invalid", SMTP_PORT=465, SMTP_SECURITY="ssl", SMTP_USERNAME="sender", SMTP_PASSWORD="test-only")
        with patch("app.response.smtplib.SMTP_SSL") as smtp:
            connection = smtp.return_value.__enter__.return_value
            connection.send_message.return_value = {"test@example.invalid": (550, b"rejected")}
            action = respond(self.app, self.alert(), self.monitor.target_path, set())
            connection.login.assert_called_once_with("sender", "test-only")
            connection.starttls.assert_not_called()
            self.assertEqual(action.result["notifications"]["email"], "failed")

    def test_starttls_before_login_and_successful_email(self):
        self.app.config.update(RESPONSE_EMAIL_TO="test@example.invalid", RESPONSE_EMAIL_FROM="sender@example.invalid",
            SMTP_HOST="smtp.example.invalid", SMTP_SECURITY="starttls", SMTP_USERNAME="sender", SMTP_PASSWORD="test-only")
        with patch("app.response.smtplib.SMTP") as smtp:
            connection = smtp.return_value.__enter__.return_value
            connection.send_message.return_value = {}
            action = respond(self.app, self.alert(), self.monitor.target_path, set())
            self.assertEqual([call[0] for call in connection.method_calls], ['starttls', 'login', 'send_message'])
            self.assertEqual(action.result["notifications"]["email"], "sent")
            message = connection.send_message.call_args.args[0]
            plain_body = message.get_body(preferencelist=("plain",)).get_content()
            html_body = message.get_body(preferencelist=("html",)).get_content()
            self.assertIn("RansomShield notification", plain_body)
            self.assertIn("Synthetic test", plain_body)
            self.assertIn("<table", html_body)
            self.assertIn("Alert report", html_body)
            self.assertNotIn('"alert": {', plain_body)

    def test_dataset_email_explains_that_results_are_csv_records(self):
        self.app.config.update(RESPONSE_EMAIL_TO="test@example.invalid", RESPONSE_EMAIL_FROM="sender@example.invalid",
            SMTP_HOST="smtp.example.invalid", SMTP_SECURITY="starttls")
        alert = self.alert()
        alert.title = "Dataset run flagged samples"
        alert.model_version = "XGBoost published MLRan"
        alert.rule_trace = [
            {"signal": "suspicious_windows", "value": 102},
            {"signal": "total_samples", "value": 324},
            {"signal": "dataset_name", "value": "Published held-out test set"},
            {"signal": "dataset_source", "value": "Published MLRan research dataset"},
        ]
        db.session.commit()
        with patch("app.response.smtplib.SMTP") as smtp:
            action = respond(self.app, alert, self.monitor.target_path, set())
            message = smtp.return_value.__enter__.return_value.send_message.call_args.args[0]
        body = message.get_body(preferencelist=("plain",)).get_content()
        html_body = message.get_body(preferencelist=("html",)).get_content()
        self.assertIn("Offline CSV dataset evaluation", body)
        self.assertIn("102 of 324", body)
        self.assertIn("Published MLRan research dataset", body)
        self.assertIn("does not mean a monitored computer is infected", body)
        self.assertIn("No files were moved to quarantine", body)
        self.assertIn("<table", html_body)
        self.assertIn("102 of 324", html_body)
        self.assertIn("Published MLRan research dataset", html_body)
        self.assertNotIn('"alert": {', body)
        self.assertIn("dataset analysis flagged records", message["Subject"])
        self.assertEqual(action.result["notifications"]["email"], "sent")

    def test_incomplete_smtp_fails_without_connecting(self):
        self.app.config.update(RESPONSE_EMAIL_TO="test@example.invalid", SMTP_HOST="", RESPONSE_EMAIL_FROM="")
        with patch("app.response.smtplib.SMTP") as smtp:
            action = respond(self.app, self.alert(), self.monitor.target_path, set())
            smtp.assert_not_called()
            self.assertEqual(action.result["notifications"]["email"], "failed")

    def test_normal_single_file_create_modify_delete_are_events_not_alerts(self):
        self.monitor._snapshot = take_snapshot(self.monitor.target_path)
        target = self.monitor.target_path / "ordinary.txt"
        target.write_text("first version", encoding="utf-8")
        self.monitor._collect_once()
        target.write_text("second version, slightly longer", encoding="utf-8")
        self.monitor._collect_once()
        target.unlink()
        self.monitor._collect_once()
        self.assertEqual(Alert.query.count(), 0)
        self.assertEqual(ResponseAction.query.count(), 0)
        events = MonitoringEvent.query.all()
        self.assertEqual(len(events), 3)
        self.assertTrue(all(event.severity == "info" for event in events))

    def test_high_volume_modification_burst_alerts_without_auto_quarantine(self):
        targets = []
        for index in range(20):
            target = self.monitor.target_path / f"modified-{index}.txt"
            target.write_text("original", encoding="utf-8")
            targets.append(target)
        self.monitor._snapshot = take_snapshot(self.monitor.target_path)
        for target in targets:
            target.write_text("modified content", encoding="utf-8")
        self.monitor._collect_once()

        alert = Alert.query.one()
        self.assertEqual(alert.title, "High-volume file-change burst")
        self.assertEqual(alert.model_version, "rolling-file-burst-v1")
        self.assertEqual(alert.rule_trace[-1]["value"], "rolling-file-burst-v1")
        affected_files = next(item["value"] for item in alert.rule_trace if item["signal"] == "affected_files")
        self.assertEqual(len(affected_files), 20)
        self.assertIn("modified-0.txt", {item["path"] for item in affected_files})
        action = ResponseAction.query.one()
        self.assertTrue(action.completed)
        self.assertEqual(action.result["quarantine"], "below_quarantine_threshold")
        self.assertTrue(all(target.exists() for target in targets))

    def test_burst_alert_has_cooldown(self):
        first_batch = []
        for index in range(20):
            target = self.monitor.target_path / f"first-{index}.txt"
            target.write_text("before", encoding="utf-8")
            first_batch.append(target)
        self.monitor._snapshot = take_snapshot(self.monitor.target_path)
        for target in first_batch:
            target.write_text("after update", encoding="utf-8")
        self.monitor._collect_once()

        second_batch = []
        for index in range(20):
            target = self.monitor.target_path / f"second-{index}.txt"
            target.write_text("before", encoding="utf-8")
            second_batch.append(target)
        self.monitor._snapshot = take_snapshot(self.monitor.target_path)
        for target in second_batch:
            target.write_text("after update", encoding="utf-8")
        self.monitor._collect_once()
        self.assertEqual(Alert.query.count(), 1)

    def test_monitor_initialization_does_not_create_sample_content(self):
        self.assertEqual(list(self.monitor.target_path.iterdir()), [])

    def test_authenticated_alert_response_and_dashboard(self):
        user = User(full_name="Tester", email="tester@example.invalid", password_hash="unused")
        db.session.add(user)
        db.session.commit()
        alert = self.alert()
        alert.user_id = user.id
        db.session.commit()
        respond(self.app, alert, self.monitor.target_path, set())
        client = self.app.test_client()
        with client.session_transaction() as session:
            session["_user_id"] = str(user.id)
            session["_fresh"] = True
        self.assertTrue(client.get("/api/alerts").json["alerts"][0]["response"]["completed"])
        self.assertEqual(client.get("/dashboard").status_code, 200)

    def test_anonymous_access_denied(self):
        self.assertEqual(self.app.test_client().get("/api/alerts").status_code, 302)


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "traces.csv"

    def write(self, rows):
        with self.path.open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=["trace_id", "window_index", "label", *FEATURE_NAMES])
            writer.writeheader()
            writer.writerows(rows)

    def row(self, trace="a", index=0, label=0):
        return {"trace_id": trace, "window_index": index, "label": label, **dict.fromkeys(FEATURE_NAMES, 0)}

    def test_metrics_and_trace_isolation(self):
        rows = [self.row("a", 0), self.row("a", 1, 1), self.row("b", 0)]
        rows[1].update(created_count=100, modified_count=100, deleted_count=100, operation_rate=150)
        self.write(rows)
        result = evaluate(self.path, MODEL, "Test fixture only", "unit-test")
        self.assertEqual(result["windows"], 3)
        self.assertEqual(result["traces"], 2)
        self.assertEqual(sum(result["confusion_matrix"].values()), 3)
        self.assertEqual(result["predictions"][0]["probability"], result["predictions"][2]["probability"])
        self.assertEqual(len(result["model_sha256"]), 3)
        json.dumps(result, allow_nan=False)

    def test_invalid_and_missing_values_rejected(self):
        for value in (float("nan"), float("inf"), -1):
            row = self.row()
            row["created_count"] = value
            self.write([row])
            with self.assertRaises(ValueError):
                evaluate(self.path, MODEL, "Test", "test")
        self.path.write_text("trace_id,label\na,0\n")
        with self.assertRaisesRegex(ValueError, "Missing columns"):
            evaluate(self.path, MODEL, "Test", "test")

    def test_duplicate_windows_rejected(self):
        self.write([self.row(), self.row()])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            evaluate(self.path, MODEL, "Test", "test")


if __name__ == "__main__":
    unittest.main()


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "MONITOR_TARGET_PATH": self.root / "decoy", "QUARANTINE_PATH": self.root / "quarantine",
            "RESPONSE_WEBHOOK_URL": "", "RESPONSE_EMAIL_TO": "", "QUARANTINE_MODE": "enabled",
            "AUTO_QUARANTINE": True})
        self.context = self.app.app_context()
        self.context.push()
        self.addCleanup(self.context.pop)
        self.monitor = self.app.extensions["monitoring_service"]

    def quarantined(self, content=b"evidence"):
        target = self.monitor.target_path / "restore.txt"
        target.write_text(content.decode())
        alert = Alert(title="Restore", details="Synthetic", severity="high", risk_score=95)
        db.session.add(alert)
        db.session.commit()
        respond(self.app, alert, self.monitor.target_path, {"restore.txt"})
        item = QuarantineItem.query.one()
        return alert, item

    def test_restore_returns_file_and_records_time(self):
        _, item = self.quarantined()
        restore_quarantine(self.app, item, self.monitor.target_path)
        self.assertEqual((self.monitor.target_path / "restore.txt").read_text(), "evidence")
        self.assertFalse(Path(item.quarantine_path).exists())
        self.assertIsNotNone(item.restored_at)
        with self.assertRaises(ValueError):
            restore_quarantine(self.app, item, self.monitor.target_path)

    def test_tampered_quarantined_file_is_refused(self):
        _, item = self.quarantined()
        Path(item.quarantine_path).write_text("changed")
        with self.assertRaises(ValueError):
            restore_quarantine(self.app, item, self.monitor.target_path)
        self.assertTrue(Path(item.quarantine_path).exists())

    def test_existing_destination_blocks_restore(self):
        _, item = self.quarantined()
        (self.monitor.target_path / "restore.txt").write_text("newer file")
        with self.assertRaises(ValueError):
            restore_quarantine(self.app, item, self.monitor.target_path)
        self.assertEqual((self.monitor.target_path / "restore.txt").read_text(), "newer file")

    def test_dry_run_records_without_moving(self):
        self.app.config["QUARANTINE_MODE"] = "dry-run"
        target = self.monitor.target_path / "keep.txt"
        target.write_text("keep")
        alert = Alert(title="Dry", details="Synthetic", severity="high", risk_score=95)
        db.session.add(alert)
        db.session.commit()
        action = respond(self.app, alert, self.monitor.target_path, {"keep.txt"})
        self.assertTrue(target.exists())
        self.assertEqual(action.result["quarantine"], "dry_run")
        self.assertEqual(action.result["files"][0]["status"], "would_quarantine")
        self.assertEqual(QuarantineItem.query.count(), 0)

    def test_quarantine_item_records_hash_and_source(self):
        _, item = self.quarantined(b"hashed")
        self.assertEqual(item.sha256, hashlib.sha256(b"hashed").hexdigest())
        self.assertEqual(item.original_path, "restore.txt")
        self.assertEqual(item.size_bytes, len(b"hashed"))
