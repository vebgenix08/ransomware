import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from app import create_app
from app.extensions import db
from app.models import AnalysisRun, User
from app.transfer import receive_one, read_regular
from scripts.send_dataset import send, sftp_quote, destination

ROOT = Path(__file__).resolve().parents[1]


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.inbox = self.root / 'inbox'
        self.inbox.mkdir()
        self.app = create_app(dict(TESTING=True, SQLALCHEMY_DATABASE_URI='sqlite://',
                                  MONITOR_TARGET_PATH=self.root/'decoy', QUARANTINE_PATH=self.root/'quarantine',
                                  RUNS_PATH=self.root/'runs', RESPONSE_WEBHOOK_URL='', RESPONSE_EMAIL_TO=''))
        self.context = self.app.app_context()
        self.context.push()
        self.addCleanup(self.context.pop)
        self.owner = User(full_name='Receiver', email='receiver@example.invalid', password_hash='unused')
        db.session.add(self.owner)
        db.session.commit()

    def publish(self, payload=None, **updates):
        payload = payload if payload is not None else (ROOT/'data/safe_demo.csv').read_bytes()
        identifier = str(uuid4())
        (self.inbox/f'{identifier}.csv').write_bytes(payload)
        manifest = dict(version=1, sha256=hashlib.sha256(payload).hexdigest(), size_bytes=len(payload),
                        dataset_name='Synthetic transfer test', source='unit test')
        manifest.update(updates)
        path = self.inbox/f'{identifier}.ready.json'
        path.write_text(json.dumps(manifest), encoding='utf-8')
        return path

    def test_received_csv_runs_real_model_and_updates_owner_dashboard(self):
        path = self.publish()
        run = receive_one(self.app, self.inbox, self.owner.id, path)
        self.assertEqual(run.status, 'completed')
        self.assertEqual(run.kind, 'laptop_transfer')
        self.assertEqual(run.result['transfer']['integrity'], 'verified')
        self.assertEqual(run.result['model_prediction'], 'suspicious')
        self.assertEqual(run.result['metrics']['accuracy'], 1.0)
        result = json.loads((self.inbox/f'{run.id}.result.json').read_text())
        self.assertEqual(result['quarantined_files'], 8)
        self.assertEqual(result['dataset_sha256'], run.result['transfer']['sha256'])
        client = self.app.test_client()
        with client.session_transaction() as session:
            session['_user_id'] = str(self.owner.id)
            session['_fresh'] = True
        self.assertEqual(client.get('/api/runs').json['runs'][0]['id'], run.id)
        self.assertEqual(client.get(result['report_path']).status_code, 200)

    def test_replaying_manifest_does_not_repeat_analysis_or_notifications(self):
        path = self.publish()
        original = receive_one(self.app, self.inbox, self.owner.id, path)
        with patch('app.transfer.execute') as execute:
            replay = receive_one(self.app, self.inbox, self.owner.id, path)
        execute.assert_not_called()
        self.assertEqual(original.id, replay.id)
        self.assertEqual(AnalysisRun.query.count(), 1)

    def test_checksum_mismatch_rejected_before_model_or_quarantine(self):
        path = self.publish(sha256='0' * 64)
        with patch('app.transfer.execute') as execute:
            run = receive_one(self.app, self.inbox, self.owner.id, path)
        execute.assert_not_called()
        self.assertEqual(run.status, 'failed')
        self.assertIsNone(run.alert_id)
        self.assertIn('integrity check failed', run.result['error'])

    def test_invalid_schema_is_a_failed_run(self):
        run = receive_one(self.app, self.inbox, self.owner.id, self.publish(b'bad,schema\n1,2\n'))
        self.assertEqual(run.status, 'failed')
        self.assertIn('Missing columns', run.result['error'])

    def test_manifest_paths_and_sizes_are_bounded(self):
        with self.assertRaises(ValueError):
            receive_one(self.app, self.inbox, self.owner.id, self.root/'outside.ready.json')
        with self.assertRaises(ValueError):
            receive_one(self.app, self.inbox, self.owner.id, self.inbox/'not-a-uuid.ready.json')
        path = self.publish()
        with self.assertRaises(ValueError):
            read_regular(path, 1)

    def test_oversized_csv_rejected(self):
        path = self.publish(b'x' * (5 * 1024 * 1024 + 1))
        run = receive_one(self.app, self.inbox, self.owner.id, path)
        self.assertEqual(run.status, 'failed')
        self.assertIn('size limit', run.result['error'])

    def test_sender_uses_verified_sftp_and_publishes_ready_marker_last(self):
        captured = []
        def fake_transfer(command, batch):
            captured.append((command, batch))
            return subprocess.CompletedProcess(command, 0, stdout='', stderr='')
        with patch('scripts.send_dataset.transfer', side_effect=fake_transfer), patch('sys.stdout', new_callable=io.StringIO):
            reply = send(ROOT/'data/safe_demo.csv', 'tester@192.168.1.10', 'D:/Projects/ransoware/instance/inbox', 'Fixture', 'test', wait_seconds=0)
        self.assertEqual(reply['status'], 'uploaded_result_pending')
        command, batch = captured[0]
        self.assertIn('-oStrictHostKeyChecking=yes', command)
        self.assertIn('-oBatchMode=yes', command)
        lines = batch.splitlines()
        self.assertTrue(lines[0].startswith('put '))
        self.assertIn('.csv.part', lines[0])
        self.assertIn('.ready.json"', lines[3])
        self.assertEqual(lines[4], 'bye')

    def test_sender_rejects_unsafe_paths_and_reports_transport_failure(self):
        with self.assertRaises(ValueError):
            sftp_quote('bad\nput payload')
        with self.assertRaises(ValueError):
            sftp_quote('wild*.csv')
        with patch('scripts.send_dataset.transfer', return_value=subprocess.CompletedProcess([], 1, stderr='offline')):
            with self.assertRaisesRegex(RuntimeError, 'SFTP upload failed'):
                send(ROOT/'data/safe_demo.csv', 'tester@192.168.1.10', 'inbox', 'Fixture', 'test', wait_seconds=0)


if __name__ == '__main__':
    unittest.main()
