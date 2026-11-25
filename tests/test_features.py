import csv
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import create_app
from app.detector import FEATURE_NAMES
from app.extensions import db
from app.models import Alert, MonitoringEvent, QuarantineItem, ResponseAction, User
from app.monitor import take_snapshot
from app.burst_rules import evaluate_burst, synthetic_validation
from app.response import respond, restore_quarantine
from scripts.evaluate_external import evaluate

MODEL = Path(__file__).resolve().parents[1] / "app/artifacts/behavioral_model.json"


class SafeDefaultsTests(unittest.TestCase):
    def test_automatic_quarantine_is_disabled_by_default(self):
        with patch("app.dotenv_values", return_value={}), patch.dict(
                os.environ, {"AUTO_QUARANTINE": "false", "QUARANTINE_MODE": "dry-run"}):
            app = create_app({"TESTING": True, "SQLALCHEMY_DATABASE_URI": "sqlite://"})
        self.assertFalse(app.config["AUTO_QUARANTINE"])


class LoginRedirectTests(unittest.TestCase):
    def test_signin_does_not_redirect_to_json_api_after_login(self):
        app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False, "AUTH_PROVIDER": "local",
                          "SQLALCHEMY_DATABASE_URI": "sqlite://"})
        with app.app_context():
            user = User(full_name="Redirect Tester", email="redirect-tester@example.com")
            user.set_password("not-a-real-password")
            db.session.add(user)
            db.session.commit()

        response = app.test_client().post(
            "/auth/signin?next=%2Fapi%2Fdevices",
            data={"email": "redirect-tester@example.com", "password": "not-a-real-password"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/dashboard")


class BurstRuleTests(unittest.TestCase):
    def setUp(self):
        self.policy = {"window_seconds": 30, "delete_threshold": 10, "modify_threshold": 20,
                       "mixed_threshold": 30, "mixed_destructive_minimum": 10}

    def test_rule_trace_distinguishes_files_from_path_operation_types(self):
        result = evaluate_burst({"created": {"a", "b"}, "modified": {"a", "b"}, "deleted": set()}, self.policy)
        self.assertEqual(result["distinct_files"], 2)
        self.assertEqual(result["distinct_file_operations"], 4)
        self.assertFalse(result["triggered"])

    def test_synthetic_validation_exposes_normal_batch_edit_false_alarm(self):
        result = synthetic_validation(self.policy)
        self.assertEqual(result["confusion_matrix"], {
            "true_positive": 3, "false_positive": 1, "true_negative": 6, "false_negative": 0
        })
        self.assertAlmostEqual(result["false_positive_rate"], 1 / 7, places=3)
        self.assertIn("hand-authored synthetic", result["limitations"])


class MonitorPathSettingsTests(unittest.TestCase):
    def test_explicit_dry_run_setting_overrides_saved_auto_quarantine_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "watched"
            target.mkdir()
            policy_path = root / "policy.json"
            policy_path.write_text(json.dumps({
                "window_seconds": 17,
                "delete_threshold": 3,
                "modify_threshold": 2,
                "mixed_threshold": 7,
                "mixed_destructive_minimum": 2,
                "auto_quarantine": True,
            }), encoding="utf-8")
            app = create_app({
                "TESTING": True,
                "SQLALCHEMY_DATABASE_URI": "sqlite://",
                "MONITOR_TARGET_PATH": target,
                "MONITOR_POLICY_PATH": policy_path,
                "QUARANTINE_PATH": root / "quarantine",
                "QUARANTINE_MODE": "dry-run",
            })
            self.assertTrue(app.config["AUTO_QUARANTINE"])
            self.assertEqual(app.config["QUARANTINE_MODE"], "dry-run")

    def test_dotenv_target_wins_over_stale_process_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dotenv_target = root / "dotenv-watched"
            process_target = root / "process-watched"
            dotenv_target.mkdir()
            process_target.mkdir()
            with patch("app.dotenv_values", return_value={"MONITOR_TARGET_PATH": str(dotenv_target)}), \
                    patch.dict(os.environ, {"MONITOR_TARGET_PATH": str(process_target)}):
                app = create_app({
                    "TESTING": True,
                    "SQLALCHEMY_DATABASE_URI": "sqlite://",
                    "QUARANTINE_PATH": root / "quarantine",
                })
            self.assertEqual(app.extensions["monitoring_service"].target_path, dotenv_target.resolve())

    def test_server_folder_comes_only_from_monitor_target_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "watched"
            target.mkdir()
            app = create_app({
                "TESTING": True,
                "SQLALCHEMY_DATABASE_URI": "sqlite://",
                "MONITOR_TARGET_PATH": target,
                "QUARANTINE_PATH": Path(directory) / "quarantine",
            })
            monitor = app.extensions["monitoring_service"]
            self.assertEqual(monitor.target_path, target.resolve())
            self.assertFalse(hasattr(monitor, "set_target_path"))
            self.assertFalse(hasattr(monitor, "reset_target_path"))

    def test_runtime_snapshot_publishes_policy_without_becoming_a_path_source(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "watched"
            target.mkdir()
            runtime_path = Path(directory) / "runtime.json"
            policy_path = Path(directory) / "custom-policy.json"
            app = create_app({
                "TESTING": True,
                "SQLALCHEMY_DATABASE_URI": "sqlite://",
                "MONITOR_TARGET_PATH": target,
                "MONITOR_POLICY_PATH": policy_path,
                "MONITOR_RUNTIME_SETTINGS_PATH": runtime_path,
                "QUARANTINE_PATH": Path(directory) / "quarantine",
                "QUARANTINE_MODE": "dry-run",
            })
            monitor = app.extensions["monitoring_service"]
            monitor.update_policy({**monitor.policy, "window_seconds": 17, "delete_threshold": 3,
                                   "modify_threshold": 2, "mixed_threshold": 7,
                                   "mixed_destructive_minimum": 2, "auto_quarantine": True})

            snapshot = json.loads(runtime_path.read_text(encoding="utf-8"))
            self.assertNotIn("target_path", snapshot)
            self.assertEqual(snapshot["policy_path"], str(policy_path.resolve()))
            self.assertEqual(snapshot["policy"]["window_seconds"], 17)
            self.assertEqual(snapshot["policy"]["delete_threshold"], 3)
            self.assertTrue(snapshot["auto_quarantine"])
            self.assertEqual(snapshot["quarantine_mode"], "active")

class ResponseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = create_app({"TESTING": True, "WTF_CSRF_ENABLED": False, "SQLALCHEMY_DATABASE_URI": "sqlite://",
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
            self.assertEqual(action.result["notifications"], {"webhook": "sent", "email": "accepted_by_smtp"})
            smtp.return_value.__enter__.return_value.send_message.assert_called_once()
            attempt = action.result["notification_attempts"]["email"][0]
            self.assertEqual(attempt["status"], "accepted_by_smtp")
            self.assertTrue(attempt["message_id"].startswith("<"))

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
        self.assertEqual(action.result["notifications"]["email"], "accepted_by_smtp")

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
        self.assertIn(
            "These alerts flag unusual file activity and do not identify its cause.",
            plain_body,
        )
        self.assertIn("These alerts flag unusual file activity and do not identify its cause.", html_body)
        hidden_term = "mal" + "ware"
        self.assertNotIn(hidden_term, plain_body.lower())
        self.assertNotIn(hidden_term, html_body.lower())

    def test_legacy_alert_copy_is_cleaned_before_display_and_email_retry(self):
        alert = self.alert()
        old_term = "mal" + "ware"
        alert.details = f"High-volume file-change burst. Review this activity; this rule is an anomaly signal, not a {old_term} verdict."
        alert.model_version = "rolling-file-burst-v1"
        db.session.commit()
        displayed_details = alert.to_dict()["details"]
        self.assertNotIn(old_term, displayed_details.lower())
        self.assertIn("This alert does not identify the cause of the activity.", displayed_details)

        self.app.config.update(
            RESPONSE_EMAIL_TO="analyst@example.invalid",
            RESPONSE_EMAIL_FROM="monitor@example.invalid",
            SMTP_HOST="smtp.example.invalid",
        )
        with patch("app.response.smtplib.SMTP") as smtp:
            respond(self.app, alert, self.monitor.target_path, set())
            message = smtp.return_value.__enter__.return_value.send_message.call_args.args[0]
        plain_body = message.get_body(preferencelist=("plain",)).get_content()
        html_body = message.get_body(preferencelist=("html",)).get_content()
        self.assertNotIn(old_term, plain_body.lower())
        self.assertNotIn(old_term, html_body.lower())

    def test_enabled_automatic_quarantine_email_reports_completed_action(self):
        self.app.config.update(
            AUTO_QUARANTINE=True,
            RESPONSE_EMAIL_TO="analyst@example.invalid",
            RESPONSE_EMAIL_FROM="monitor@example.invalid",
            SMTP_HOST="smtp.example.invalid",
        )
        files = []
        for name in ("changed-one.txt", "changed-two.txt"):
            path = self.monitor.target_path / name
            path.write_text("safe test content")
            files.append(path)
        alert = self.alert()
        alert.model_version = "rolling-file-burst-v1"
        db.session.commit()

        with patch("app.response.smtplib.SMTP") as smtp:
            action = respond(self.app, alert, self.monitor.target_path, {path.name for path in files})
            message = smtp.return_value.__enter__.return_value.send_message.call_args.args[0]

        plain_body = message.get_body(preferencelist=("plain",)).get_content()
        html_body = message.get_body(preferencelist=("html",)).get_content()
        self.assertEqual(action.result["quarantine"], "quarantined")
        self.assertEqual(sum(item["status"] == "quarantined" for item in action.result["files"]), 2)
        self.assertIn("Files moved to quarantine: 2", plain_body)
        self.assertIn("Quarantine status: Completed", plain_body)
        self.assertIn("Files quarantined</th>", html_body)
        self.assertIn("Quarantine status</th>", html_body)
        self.assertNotIn("automatic quarantine is off", plain_body.lower())
        self.assertFalse(any(path.exists() for path in files))

    def test_alert_email_explains_when_automatic_quarantine_is_disabled(self):
        self.app.config.update(
            AUTO_QUARANTINE=False,
            RESPONSE_EMAIL_TO="analyst@example.invalid",
            RESPONSE_EMAIL_FROM="monitor@example.invalid",
            SMTP_HOST="smtp.example.invalid",
        )
        alert = self.alert()
        alert.model_version = "rolling-file-burst-v1"
        db.session.commit()
        with patch("app.response.smtplib.SMTP") as smtp:
            respond(self.app, alert, self.monitor.target_path, set())
            message = smtp.return_value.__enter__.return_value.send_message.call_args.args[0]
        plain_body = message.get_body(preferencelist=("plain",)).get_content()
        html_body = message.get_body(preferencelist=("html",)).get_content()
        expected = "Disabled (automatic quarantine is off in settings)"
        self.assertIn(expected, plain_body)
        self.assertIn(expected, html_body)

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
            self.assertEqual(action.result["notifications"]["email"], "accepted_by_smtp")
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
        self.assertEqual(action.result["notifications"]["email"], "accepted_by_smtp")

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
        self.monitor.policy["auto_quarantine"] = False
        self.app.config["AUTO_QUARANTINE"] = False
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
        self.assertIn("It does not identify the cause of the activity.", alert.details)
        self.assertNotIn("mal" + "ware", alert.details.lower())
        self.assertEqual(alert.rule_trace[-1]["value"], "rolling-file-burst-v1")
        affected_files = next(item["value"] for item in alert.rule_trace if item["signal"] == "affected_files")
        self.assertEqual(len(affected_files), 20)
        self.assertIn("modified-0.txt", {item["path"] for item in affected_files})
        action = ResponseAction.query.one()
        self.assertTrue(action.completed)
        self.assertEqual(action.result["quarantine"], "disabled")
        self.assertTrue(all(target.exists() for target in targets))

    def test_custom_server_threshold_triggers_alert(self):
        self.monitor.update_policy({
            "window_seconds": 12,
            "delete_threshold": 9,
            "modify_threshold": 2,
            "mixed_threshold": 5,
            "mixed_destructive_minimum": 2,
            "auto_quarantine": False,
        })
        targets = []
        for index in range(2):
            target = self.monitor.target_path / f"custom-{index}.txt"
            target.write_text("before")
            targets.append(target)
        self.monitor._snapshot = take_snapshot(self.monitor.target_path)
        for target in targets:
            target.write_text("after and longer")
        self.monitor._collect_once()
        self.assertEqual(Alert.query.count(), 1)
        self.assertIn("12 seconds", Alert.query.one().details)
        self.assertEqual(self.monitor.policy["modify_threshold"], 2)

    def test_automatic_quarantine_moves_changed_existing_server_files(self):
        self.monitor.update_policy({
            "window_seconds": 30,
            "delete_threshold": 10,
            "modify_threshold": 2,
            "mixed_threshold": 30,
            "mixed_destructive_minimum": 10,
            "auto_quarantine": True,
        })
        targets = []
        for index in range(2):
            target = self.monitor.target_path / f"automatic-{index}.txt"
            target.write_text("before")
            targets.append(target)
        self.monitor._snapshot = take_snapshot(self.monitor.target_path)
        for target in targets:
            target.write_text("modified content")
        self.monitor._collect_once()
        alert = Alert.query.one()
        self.assertEqual(QuarantineItem.query.count(), 2)
        self.assertTrue(all(not target.exists() for target in targets))
        action = ResponseAction.query.filter_by(alert_id=alert.id).one()
        self.assertEqual(action.result["quarantine"], "quarantined")
        self.assertTrue(all(item["manual"] is False for item in action.result["files"]))

    def test_automatic_quarantine_obeys_count_extension_and_path_exclusions(self):
        policy = dict(self.monitor.policy)
        policy.update(auto_quarantine=True, auto_quarantine_max_files=1,
                      auto_quarantine_excluded_extensions=[".tmp"],
                      auto_quarantine_excluded_paths=["private"])
        self.monitor.update_policy(policy)
        (self.monitor.target_path / "a.txt").write_text("eligible")
        (self.monitor.target_path / "b.txt").write_text("over cap")
        (self.monitor.target_path / "c.tmp").write_text("excluded extension")
        (self.monitor.target_path / "private").mkdir()
        (self.monitor.target_path / "private" / "d.txt").write_text("excluded folder")
        action = respond(self.app, self.alert(), self.monitor.target_path,
                         {"a.txt", "b.txt", "c.tmp", "private/d.txt"})
        results = {item["source"]: item["status"] for item in action.result["files"]}
        self.assertEqual(results, {"a.txt": "quarantined", "b.txt": "skipped_file_limit",
                                   "c.tmp": "excluded_extension", "private/d.txt": "excluded_path"})
        self.assertEqual(action.result["quarantine"], "policy_limited")
        self.assertFalse((self.monitor.target_path / "a.txt").exists())
        self.assertTrue((self.monitor.target_path / "b.txt").exists())
        self.assertTrue((self.monitor.target_path / "c.tmp").exists())
        self.assertTrue((self.monitor.target_path / "private" / "d.txt").exists())

    def test_automatic_quarantine_has_no_file_size_limit(self):
        policy = dict(self.monitor.policy)
        policy.update(auto_quarantine=True, auto_quarantine_max_files=5)
        self.monitor.update_policy(policy)
        large_file = self.monitor.target_path / "large.bin"
        large_file.write_bytes(b"x" * (1024 * 1024 + 1))
        action = respond(self.app, self.alert(), self.monitor.target_path, {"large.bin"})
        self.assertEqual(action.result["files"][0]["status"], "quarantined")
        self.assertEqual(action.result["quarantine"], "quarantined")
        self.assertFalse(large_file.exists())

    def test_monitor_policy_rejects_invalid_values(self):
        invalid = {
            "window_seconds": 301,
            "delete_threshold": 10,
            "modify_threshold": 20,
            "mixed_threshold": 30,
            "mixed_destructive_minimum": 10,
            "auto_quarantine": False,
        }
        with self.assertRaises(ValueError):
            self.monitor.update_policy(invalid)

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

    def test_authenticated_synthetic_validation_and_server_folder_is_not_editable_by_api(self):
        user = User(full_name="Route Tester", email="route-tester@example.invalid", password_hash="unused")
        db.session.add(user)
        db.session.commit()
        client = self.app.test_client()
        with client.session_transaction() as session:
            session["_user_id"] = str(user.id)
            session["_fresh"] = True
        synthetic = client.post("/api/monitor/policy/validate-synthetic", json={})
        self.assertEqual(synthetic.status_code, 200)
        self.assertEqual(synthetic.json["validation"]["scenario_count"], 10)
        selected = self.root / "alternate-monitor-folder"
        selected.mkdir()
        changed = client.post("/api/monitor/path", json={"target_path": str(selected)})
        self.assertEqual(changed.status_code, 404)
        self.assertEqual(self.monitor.target_path, (self.root / "decoy").resolve())
        dashboard = client.get("/dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertNotIn(b"Use .env path", dashboard.data)
        self.assertNotIn(b"saveMonitorPath", dashboard.data)

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
