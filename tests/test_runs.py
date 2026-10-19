import csv
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from flask import g

from app import create_app
from app.detector import FEATURE_NAMES
from app.extensions import db
from app.models import AnalysisRun, User


class RunTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = create_app(dict(TESTING=True, WTF_CSRF_ENABLED=False, SQLALCHEMY_DATABASE_URI="sqlite://",
                                   MONITOR_TARGET_PATH=self.root/'decoy', QUARANTINE_PATH=self.root/'quarantine',
                                   RUNS_PATH=self.root/'runs', RESPONSE_WEBHOOK_URL="", RESPONSE_EMAIL_TO=""))
        self.context = self.app.app_context()
        self.context.push()
        self.addCleanup(self.context.pop)
        user = User(full_name="Tester", email="runs@example.invalid", password_hash="unused")
        db.session.add(user)
        db.session.commit()
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session['_user_id'] = str(user.id)
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

    def test_real_simulation_unique_ids_quarantine_and_reports(self):
        first = self.client.post('/api/monitor/demo')
        self.assertEqual(first.status_code, 200, first.json)
        run = first.json['run']
        self.assertEqual(run['result']['model_prediction'], 'suspicious')
        self.assertEqual(run['status'], 'completed')
        files = run['incident']['response']['files']
        self.assertEqual(sum(f['status'] == 'quarantined' for f in files), 27)
        self.assertEqual(sum(f['status'] == 'failed' for f in files), 0)
        second = self.client.post('/api/monitor/demo').json['run']
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
        self.assertEqual(len(suspicious['incident']['response']['files']), 8)
        self.assertTrue(all(f['status'] == 'quarantined' for f in suspicious['incident']['response']['files']))

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

    def test_failed_notifications_do_not_undo_containment(self):
        self.app.config['RESPONSE_WEBHOOK_URL'] = 'https://example.invalid'
        with patch('app.response.urlopen', side_effect=OSError('offline')):
            run = self.client.post('/api/monitor/demo').json['run']
        self.assertEqual(run['status'], 'completed')
        self.assertEqual(run['incident']['response']['notifications']['webhook'], 'failed')
        self.assertTrue(any(f['status'] == 'quarantined' for f in run['incident']['response']['files']))

    def test_run_access_is_owned_and_anonymous_is_denied(self):
        run = self.client.post('/api/monitor/demo').json['run']
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

    def test_model_unavailable_records_failure(self):
        with patch('app.runs.evaluate', side_effect=ValueError('Model unavailable')):
            response = self.client.post('/api/monitor/demo')
        self.assertEqual(response.status_code, 422)
        self.assertEqual(AnalysisRun.query.one().status, 'failed')

    def test_dashboard_renders_and_settings_do_not_expose_secrets(self):
        self.app.config['SMTP_PASSWORD'] = 'never-expose-me'
        self.assertEqual(self.client.get('/dashboard').status_code, 200)
        self.assertNotIn('never-expose-me', self.client.get('/api/notifications').text)
        self.assertIn('Run history', self.client.get('/dashboard').text)

    def test_upload_limits_and_sample_download(self):
        self.assertEqual(self.upload(b'x' * (5 * 1024 * 1024)).status_code, 413)
        response = self.client.get('/api/datasets/sample.csv')
        self.assertEqual(response.status_code, 200)
        self.assertIn('trace_id,window_index,label', response.text)
        response.close()

    def test_csv_formula_is_escaped(self):
        payload = self.fixture().replace(b'fixture', b'=1+1')
        run = self.upload(payload).json['run']
        response = self.client.get(f"/api/runs/{run['id']}/report.csv")
        rows = list(csv.reader(io.StringIO(response.text)))
        self.assertTrue(any(row and row[0] == "'=1+1" for row in rows))

    def test_csrf_required_for_mutation(self):
        self.app.config['WTF_CSRF_ENABLED'] = True
        self.assertEqual(self.client.post('/api/monitor/demo').status_code, 400)

    def test_included_mlran_runs_and_exports_real_published_predictions(self):
        response = self.client.post('/api/runs/mlran')
        self.assertEqual(response.status_code, 200, response.json)
        run = response.json['run']
        self.assertEqual(run['result']['dataset_schema'], 'mlran')
        self.assertEqual(run['result']['windows'], 324)
        self.assertEqual(run['result']['training_overlap_samples'], 0)
        self.assertAlmostEqual(run['result']['metrics']['accuracy'], 301 / 324)
        self.assertEqual(len(run['incident']['response']['files']), 102)
        self.assertIn('XGBoost', run['incident']['details'])
        report = self.client.get(f"/api/runs/{run['id']}/report.csv")
        self.assertIn('active_file_indicators', report.text)

    def test_local_transfer_is_explicitly_not_network_and_has_unique_ids(self):
        first = self.client.post('/api/runs/local-transfer')
        self.assertEqual(first.status_code, 200, first.json)
        run = first.json['run']
        self.assertEqual(run['result']['transfer']['transport'], 'local_demo (no network transfer)')
        self.assertEqual(run['result']['transfer']['integrity'], 'verified')
        second = self.client.post('/api/runs/local-transfer').json['run']
        self.assertNotEqual(run['id'], second['id'])

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
