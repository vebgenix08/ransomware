import csv
import tempfile
import unittest
from pathlib import Path

from app.silrad import EXCLUDED_COLUMNS, evaluate_test, train_model


class SilradPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.train = self.root / "train.csv"
        self.test = self.root / "test.csv"
        self.columns = ["event.code", "CommandLine", "task", "class"]

    def write_rows(self, path, rows):
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=self.columns)
            writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def rows():
        return [
            {"event.code": "11", "CommandLine": "notepad.exe", "task": "benign-context", "class": "0"},
            {"event.code": "11", "CommandLine": "wordpad.exe", "task": "benign-context", "class": "0"},
            {"event.code": "23", "CommandLine": "encryptor.exe", "task": "malicious-context", "class": "1"},
            {"event.code": "23", "CommandLine": "locker.exe", "task": "malicious-context", "class": "1"},
        ]

    def test_training_uses_separate_features_and_heldout_evaluation(self):
        self.write_rows(self.train, self.rows() * 2)
        self.write_rows(self.test, self.rows())
        model = self.root / "model"
        metadata = train_model(self.train, model)
        self.assertEqual(metadata["training_rows"], 8)
        self.assertIn("task", EXCLUDED_COLUMNS)
        self.assertNotIn("task", metadata["feature_columns"])
        report = evaluate_test(self.test, model, self.root / "predictions.csv")
        self.assertEqual(report["dataset_schema"], "silrad")
        self.assertEqual(report["windows"], 4)
        self.assertEqual(sum(report["confusion_matrix"].values()), 4)
        with (self.root / "predictions.csv").open(encoding="utf-8", newline="") as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 4)
        self.assertEqual(set(rows[0]), {"row_number", "actual_class", "predicted_class", "probability", "correct"})

    def test_rejects_unrelated_csv_without_silrad_schema(self):
        self.write_rows(self.test, self.rows())
        model = self.root / "model"
        metadata = train_model(self.test, model)
        self.assertTrue(metadata["training_rows"])
        unrelated = self.root / "unrelated.csv"
        unrelated.write_text("name,label\na,1\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "not a SILRAD"):
            train_model(unrelated, model / "other")


if __name__ == "__main__":
    unittest.main()
