import csv
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4
from flask import g

from app import create_app
from app.detector import FEATURE_NAMES
from app.extensions import db
from app.models import Alert, AnalysisRun, MonitoringEvent, QuarantineItem, User


class RunTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = create_app(dict(TESTING=True, WTF_CSRF_ENABLED=False, SQLALCHEMY_DATABASE_URI="sqlite://",
                                   MONITOR_TARGET_PATH=self.root/'decoy', QUARANTINE_PATH=self.root/'quarantine',
                                   RUNS_PATH=self.root/'runs', RESPONSE_WEBHOOK_URL="", RESPONSE_EMAIL_TO="",
                                   AUTO_QUARANTINE=True))
        self.context = self.app.app_context()
        self.context.push()
        self.addCleanup(self.context.pop)
        self.user = User(full_name="Tester", email="runs@example.invalid", password_hash="unused")
        db.session.add(self.user)
        db.session.commit()
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session['_user_id'] = str(self.user.id)
            session['_fresh'] = True

    def upload(self, payload):
        return self.client.post('/api/runs/dataset', data=dict(dataset=(io.BytesIO(payload), 'records.csv'), dataset_name='Fixture', source='unit test'))

    def fixture(self, suspicious=False):
        stream = io.StringIO()
        writer = csv.DictWriter(stream, fieldnames=['trace_id', 'window_index', 'label', *FEATURE_NAMES])
        writer.writeheader()
        for i in range(8):
            values = dict.fromkeys(FEATURE_NAMES, 0)
            values.update(cpu_percent=10, memory_percent=30, process_count=100)
            if suspicious:
                values.update(created_count=24, modified_count=3, deleted_count=5, canary_accessed=1,
                              canary_modified=1, decoy_files_touched=32, directories_touched=5, operation_rate=16)
            writer.writerow(dict(trace_id='fixture', window_index=i, label=int(suspicious), **values))
        return stream.getvalue().encode()

    def test_suspicious_dataset_runs_record_alerts_without_moving_local_files(self):
        first = self.upload(self.fixture(True))
        self.assertEqual(first.status_code, 200, first.json)
        run = first.json['run']
        self.assertEqual(run['result']['model_prediction'], 'suspicious')
        self.assertEqual(run['status'], 'completed')
        files = run['incident']['response']['files']
        self.assertEqual(files, [])
        self.assertEqual(run['incident']['response']['quarantine'], 'no_files')
        second = self.upload(self.fixture(True)).json['run']
        self.assertNotEqual(run['id'], second['id'])
        self.assertEqual(len(self.client.get('/api/runs').json['runs']), 2)
        report = self.client.get(f"/api/alerts/{run['incident']['id']}/report.csv")
        self.assertEqual(report.status_code, 200)
        self.assertIn(run['id'], report.text)
        self.assertIn('notification_status', report.text)

    def test_dataset_benign_and_suspicious_real_model(self):
        benign = self.upload(self.fixture()).json['run']
        self.assertEqual(benign['result']['model_prediction'], 'benign')
        self.assertIsNone(benign['incident'])
        suspicious = self.upload(self.fixture(True)).json['run']
        self.assertEqual(suspicious['result']['model_prediction'], 'suspicious')
        self.assertEqual(suspicious['result']['metrics']['recall'], 1)
        self.assertEqual(suspicious['incident']['response']['files'], [])
        self.assertEqual(suspicious['result']['quarantine_scope'], 'No files were moved from a dataset evaluation. CSV path fields are never acted on.')

    def test_invalid_dataset_persists_failed_run_and_creates_no_incident(self):
        result = self.upload(b'wrong,column\n1,2\n')
        self.assertEqual(result.status_code, 422)
        run = result.json['run']
        self.assertEqual(run['status'], 'failed')
        self.assertIsNone(run['incident'])
        self.assertIn('Missing columns', run['result']['error'])

    def test_published_preview_is_rejected_without_fabricating_features(self):
        result = self.upload((Path(__file__).resolve().parents[1]/'data/rande_w11_preview.csv').read_bytes())
        self.assertEqual(result.status_code, 422)
        self.assertIn('Missing columns', result.json['message'])

    def test_failed_notifications_do_not_undo_incident_record(self):
        self.app.config['RESPONSE_WEBHOOK_URL'] = 'https://example.invalid'
        with patch('app.response.urlopen', side_effect=OSError('offline')):
            run = self.upload(self.fixture(True)).json['run']
        self.assertEqual(run['status'], 'completed')
        self.assertEqual(run['incident']['response']['notifications']['webhook'], 'failed')
        self.assertEqual(run['incident']['response']['files'], [])

    def test_run_access_is_owned_and_anonymous_is_denied(self):
        run = self.upload(self.fixture(True)).json['run']
        other = User(full_name='Other', email='other@example.invalid', password_hash='unused')
        db.session.add(other)
        db.session.commit()
        with self.client.session_transaction() as session:
            session['_user_id'] = str(other.id)
        # Tests hold an outer app context; clear Flask-Login's cached user.
        g.pop('_login_user', None)
        self.assertEqual(self.client.get('/api/runs').json['runs'], [])
        self.assertEqual(self.client.get('/api/alerts').json['alerts'], [])
        for url in (f"/api/runs/{run['id']}", f"/api/runs/{run['id']}/report.csv", f"/api/alerts/{run['incident']['id']}/report.csv"):
            self.assertEqual(self.client.get(url).status_code, 404)
        g.pop('_login_user', None)
        self.assertEqual(self.app.test_client().get('/api/runs').status_code, 302)

    def test_live_events_alerts_quarantine_and_monitor_controls_are_account_scoped(self):
        other = User(full_name='Other', email='other-live@example.invalid', password_hash='unused')
        db.session.add(other)
        db.session.flush()
        own_event = MonitoringEvent(user_id=self.user.id, event_type='file_created', severity='info', details='own path', risk_score=0)
        other_event = MonitoringEvent(user_id=other.id, event_type='file_created', severity='info', details='private path', risk_score=0)
        own_alert = Alert(user_id=self.user.id, title='Own live alert', details='own', severity='medium', risk_score=60)
        other_alert = Alert(user_id=other.id, title='Private live alert', details='private', severity='medium', risk_score=60)
        db.session.add_all([own_event, other_event, own_alert, other_alert])
        db.session.flush()
        own_item = QuarantineItem(alert_id=own_alert.id, original_path='own.txt', quarantine_path=str(self.root / 'q' / 'own.txt'), sha256='a' * 64)
        other_item = QuarantineItem(alert_id=other_alert.id, original_path='private.txt', quarantine_path=str(self.root / 'q' / 'private.txt'), sha256='b' * 64)
        db.session.add_all([own_item, other_item])
        db.session.commit()

        with self.client.session_transaction() as session:
            session['_user_id'] = str(other.id)
        g.pop('_login_user', None)
        self.assertEqual([event['details'] for event in self.client.get('/api/events').json['events']], ['private path'])
        self.assertEqual([alert['title'] for alert in self.client.get('/api/alerts').json['alerts']], ['Private live alert'])
        self.assertEqual([item['original_path'] for item in self.client.get('/api/quarantine').json['items']], ['private.txt'])
        self.assertEqual(self.client.post(f'/api/alerts/{own_alert.id}/acknowledge').status_code, 404)
        self.assertEqual(self.client.post(f'/api/quarantine/{own_item.id}/restore').status_code, 404)
        self.assertEqual(self.client.get(f'/api/alerts/{own_alert.id}/report.csv').status_code, 404)

        class ActiveMonitor:
            is_running = True

            def owned_by(self, user_id):
                return user_id == self.owner_id

            def __init__(self, owner_id):
                self.owner_id = owner_id

            def status(self):
                return {"running": True, "connection_state": "Connected", "model_state": "Rolling burst rules",
                        "target": "private/server/path", "interval_seconds": 2, "reconcile_seconds": 30,
                        "auto_quarantine": False, "cpu_percent": 17, "memory_percent": 20,
                        "process_count": 4, "last_check": None, "last_successful_scan": None,
                        "last_risk_score": 60, "monitored_files": 9, "dropped_events": 0,
                        "queue_depth": 0, "collector": "poll", "last_activity": {}}

            def start(self, owner_id=None):
                raise AssertionError('another account must not start the active monitor')

            def stop(self, owner_id=None):
                raise AssertionError('another account must not stop the active monitor')

        with patch('app.api.get_monitor', return_value=ActiveMonitor(self.user.id)):
            status = self.client.get('/api/monitor/status').json
            self.assertEqual(status['event_count'], 1)
            self.assertEqual(status['status']['target'], 'Not assigned to this account')
            self.assertEqual(status['status']['connection_state'], 'In use by another account')
            self.assertEqual(status['status']['cpu_percent'], 0)
            self.assertEqual(self.client.post('/api/monitor/start').status_code, 409)
            self.assertEqual(self.client.post('/api/monitor/stop').status_code, 403)

    def test_model_unavailable_records_failure(self):
        with patch('app.runs.evaluate', side_effect=ValueError('Model unavailable')):
            response = self.upload(self.fixture(True))
        self.assertEqual(response.status_code, 422)
        self.assertEqual(AnalysisRun.query.one().status, 'failed')

    def test_dashboard_renders_and_settings_do_not_expose_secrets(self):
        self.app.config['SMTP_PASSWORD'] = 'never-expose-me'
        dashboard = self.client.get('/dashboard')
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn('Start here: test and use RansomShield', dashboard.text)
        self.assertIn('SILRAD Sysmon benchmark', dashboard.text)
        self.assertNotIn('Published MLRan evaluation', dashboard.text)
        self.assertNotIn('never-expose-me', self.client.get('/api/notifications').text)
        self.assertIn('Run history', dashboard.text)

    def test_upload_limits_and_published_dataset_download(self):
        self.assertEqual(self.upload(b'x' * (5 * 1024 * 1024)).status_code, 413)
        response = self.client.get('/api/datasets/mlran.csv')
        self.assertEqual(response.status_code, 200)
        self.assertIn('sample_id,sample_type', response.text)
        response.close()

    def test_blank_telemetry_template_has_only_the_real_required_headers(self):
        response = self.client.get('/api/datasets/telemetry-template.csv')
        self.assertEqual(response.status_code, 200)
        rows = list(csv.reader(io.StringIO(response.text)))
        self.assertEqual(rows, [['trace_id', 'window_index', 'label', *FEATURE_NAMES]])
        response.close()
        g.pop('_login_user', None)
        self.assertEqual(self.app.test_client().get('/api/datasets/telemetry-template.csv').status_code, 302)

    def test_csv_formula_is_escaped(self):
        payload = self.fixture().replace(b'fixture', b'=1+1')
        run = self.upload(payload).json['run']
        response = self.client.get(f"/api/runs/{run['id']}/report.csv")
        rows = list(csv.reader(io.StringIO(response.text)))
        self.assertTrue(any(row and row[0] == "'=1+1" for row in rows))

    def test_csrf_required_for_mutation(self):
        self.app.config['WTF_CSRF_ENABLED'] = True
        self.assertEqual(self.client.post('/api/monitor/start').status_code, 400)

    def test_live_monitor_status_explains_real_file_burst_policy(self):
        response = self.client.get('/api/monitor/status')
        self.assertEqual(response.status_code, 200)
        policy = response.json['live_policy']
        self.assertEqual(policy['name'], 'Rolling file-burst rules')
        self.assertEqual(policy['alert_thresholds']['deleted_files'], 10)
        self.assertEqual(policy['alert_thresholds']['modified_files'], 20)
        self.assertFalse(policy['automatic_quarantine'])
        self.assertIn('not a probability', policy['score_type'])

    def test_browser_folder_events_are_authenticated_scoped_deduplicated_and_alerted(self):
        folder_id = str(uuid4())
        events = [{"event_id": str(uuid4()), "operation": "modified", "path": f"safe/file-{i}.txt"}
                  for i in range(20)]
        response = self.client.post('/api/browser-folder/events', json={"folder_id": folder_id, "events": events})
        self.assertEqual(response.status_code, 202, response.json)
        self.assertEqual(response.json['accepted'], 20)
        self.assertTrue(response.json['alert_created'])
        self.assertEqual(MonitoringEvent.query.filter_by(source='browser', user_id=self.user.id).count(), 20)
        alert = Alert.query.filter_by(model_version='browser-folder-burst-v1', user_id=self.user.id).one()
        self.assertIn('20 distinct file changes', alert.details)
        self.assertTrue(alert.responses[0].completed)

        duplicate = self.client.post('/api/browser-folder/events', json={"folder_id": folder_id, "events": events})
        self.assertEqual(duplicate.status_code, 202)
        self.assertEqual(duplicate.json['accepted'], 0)
        self.assertEqual(MonitoringEvent.query.filter_by(source='browser', user_id=self.user.id).count(), 20)

        invalid = self.client.post('/api/browser-folder/events', json={"folder_id": folder_id, "events": [
            {"event_id": str(uuid4()), "operation": "created", "path": "../outside.txt"}
        ]})
        self.assertEqual(invalid.status_code, 400)

        g.pop('_login_user', None)
        anonymous = self.app.test_client().post('/api/browser-folder/events', json={"folder_id": folder_id, "events": events[:1]})
        self.assertEqual(anonymous.status_code, 302)

    def test_included_mlran_runs_and_exports_real_published_predictions(self):
        response = self.client.post('/api/runs/mlran')
        self.assertEqual(response.status_code, 200, response.json)
        run = response.json['run']
        self.assertEqual(run['result']['dataset_schema'], 'mlran')
        self.assertEqual(run['result']['windows'], 324)
        self.assertEqual(run['result']['training_overlap_samples'], 0)
        self.assertAlmostEqual(run['result']['metrics']['accuracy'], 301 / 324)
        self.assertEqual(run['incident']['response']['files'], [])
        self.assertEqual(run['incident']['response']['quarantine'], 'no_files')
        self.assertIn('XGBoost', run['incident']['details'])
        report = self.client.get(f"/api/runs/{run['id']}/report.csv")
        self.assertIn('active_file_indicators', report.text)

    def test_silrad_uses_its_published_heldout_split_when_prepared(self):
        silrad = Path(self.app.instance_path) / 'silrad'
        if not (silrad / 'fasttext-testmodel.csv').is_file() or not (silrad / 'metadata.json').is_file():
            self.skipTest('Run scripts/setup_silrad.py to prepare the local SILRAD data.')
        response = self.client.post('/api/runs/silrad')
        self.assertEqual(response.status_code, 200, response.json)
        run = response.json['run']
        self.assertEqual(run['result']['dataset_schema'], 'silrad')
        self.assertEqual(run['result']['windows'], 156841)
        self.assertEqual(run['result']['class_counts'], {'benign': 137312, 'ransomware': 19529})
        self.assertEqual(sum(run['result']['confusion_matrix'].values()), 156841)
        self.assertNotIn('CommandLine', str(run['result']))
        predictions = self.client.get(f"/api/runs/{run['id']}/predictions.csv")
        self.assertEqual(predictions.status_code, 200)
        self.assertIn('row_number,actual_class,predicted_class,probability,correct', predictions.text[:200])
        predictions.close()
        status = self.client.get('/api/silrad/status')
        self.assertEqual(status.status_code, 200)
        self.assertTrue(status.json['ready'])
        self.assertAlmostEqual(status.json['metrics']['recall'], 1986 / 19529)

    def test_silrad_status_and_server_prepare_action(self):
        preparation = self.app.extensions['silrad_preparation']
        self.app.config['SILRAD_DATA_DIR'] = str(self.root / 'unprepared-silrad')
        self.assertEqual(self.client.get('/api/silrad/status').json['state'], 'idle')

        def start_preparation():
            preparation._state = 'preparing'
            return True

        with patch.object(preparation, 'start', side_effect=start_preparation):
            response = self.client.post('/api/silrad/prepare')
        self.assertEqual(response.status_code, 202)
        self.assertTrue(response.json['ok'])
        self.assertEqual(response.json['state'], 'preparing')

    def test_incomplete_silrad_metadata_is_not_reported_ready(self):
        import json
        data_dir = self.root / 'partial-silrad'
        data_dir.mkdir()
        for filename in ('fasttext-testmodel.csv', 'fasttext-trainmodel.csv', 'model.ubj'):
            (data_dir / filename).write_text('partial', encoding='utf-8')
        (data_dir / 'metadata.json').write_text(json.dumps({
            'booster': 'model.ubj', 'display_name': 'SILRAD', 'training_rows': 39999,
        }), encoding='utf-8')
        self.app.config['SILRAD_DATA_DIR'] = str(data_dir)
        status = self.client.get('/api/silrad/status').json
        self.assertFalse(status['ready'])
        self.assertEqual(status['state'], 'idle')

    def test_demo_endpoints_are_removed(self):
        self.assertEqual(self.client.post('/api/monitor/demo').status_code, 404)
        self.assertIn(self.client.post('/api/runs/local-transfer').status_code, (404, 405))
        self.assertEqual(self.client.get('/api/datasets/sample.csv').status_code, 404)
        self.assertEqual(self.client.get('/downloads/').status_code, 404)

    def test_pwa_routes_and_no_account_data_in_service_worker_cache(self):
        manifest = self.client.get('/manifest.webmanifest')
        self.assertEqual(manifest.status_code, 200)
        self.assertEqual(manifest.mimetype, 'application/manifest+json')
        self.assertEqual(manifest.headers['Cache-Control'], 'no-cache')
        self.assertIn('standalone', manifest.text)
        self.assertIn('icon-192.png', manifest.text)
        manifest.close()
        worker = self.client.get('/service-worker.js')
        self.assertEqual(worker.status_code, 200)
        self.assertEqual(worker.headers['Service-Worker-Allowed'], '/')
        self.assertIn("url.pathname.startsWith('/api/')", worker.text)
        worker.close()
        offline = self.client.get('/offline')
        self.assertIn('RansomShield is offline', offline.text)
        offline.close()

    def test_monitor_target_starts_without_synthetic_seed_files(self):
        self.assertEqual(list((self.root/'decoy').iterdir()), [])

    def test_mlran_labels_are_not_prediction_features(self):
        from app.mlran import evaluate_dataset
        original = Path(__file__).resolve().parents[1] / 'data/mlran/heldout.csv'
        model = Path(self.app.root_path) / 'artifacts/behavioral_model.json'
        baseline = evaluate_dataset(original, model, 'test', 'test')
        with original.open() as stream:
            reader = csv.DictReader(stream)
            fields = reader.fieldnames
            rows = list(reader)
        path = self.root / 'flipped.csv'
        with path.open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            for row in rows:
                row['sample_type'] = str(1-int(row['sample_type']))
                writer.writerow(row)
        flipped = evaluate_dataset(path, model, 'test', 'test')
        self.assertEqual([r['probability'] for r in baseline['predictions']],
                         [r['probability'] for r in flipped['predictions']])


if __name__ == '__main__':
    unittest.main()
