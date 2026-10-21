import csv
import tempfile
import unittest
from pathlib import Path

from app.silrad_incremental import FEATURE_COLUMNS, evaluate_test, train_model


class SilradIncrementalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.train = self.root / "train.csv"
        self.test = self.root / "test.csv"
        self.columns = [*FEATURE_COLUMNS, "class"]

    def write_rows(self, path, rows):
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=self.columns)
            writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def rows(count):
        rows = []
        for index in range(count):
            label = index % 2
            rows.append({
                "TargetObject": str(float(label)),
                "task": str(float(label)),
                "CallTrace": str(float(label)),
                "ParentImage": str(float(label)),
                "IntegrityLevel": str(float(label)),
                "class": str(label),
            })
        return rows

    def test_incremental_training_uses_paper_feature_names_and_validation_threshold(self):
        self.write_rows(self.train, self.rows(80))
        self.write_rows(self.test, self.rows(20))
        model_dir = self.root / "model"
        metadata = train_model(self.train, model_dir)
        self.assertEqual(metadata["feature_columns"], list(FEATURE_COLUMNS))
        self.assertEqual(metadata["training_rows"], 80)
        self.assertEqual(metadata["validation"]["rows"], 16)
        self.assertGreaterEqual(metadata["threshold"], 0.01)
        self.assertLessEqual(metadata["threshold"], 0.99)

        report = evaluate_test(self.test, model_dir, self.root / "predictions.csv")
        self.assertEqual(report["dataset_schema"], "silrad")
        self.assertIn("prequential online stream", report["evaluation_role"])
        self.assertEqual(sum(report["confusion_matrix"].values()), 20)
        self.assertEqual(sum(report["frozen_model_evaluation"]["confusion_matrix"].values()), 20)
        with (self.root / "predictions.csv").open(encoding="utf-8", newline="") as stream:
            predictions = list(csv.DictReader(stream))
        self.assertEqual(len(predictions), 20)
        self.assertEqual(set(predictions[0]), {
            "row_number", "actual_class", "predicted_class", "probability",
            "frozen_predicted_class", "frozen_probability", "correct",
        })

    def test_requires_silrad_feature_columns_and_finite_values(self):
        self.write_rows(self.train, self.rows(40))
        malformed = self.root / "malformed.csv"
        malformed.write_text("class,TargetObject\n0,NaN\n1,1\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "missing required feature columns"):
            train_model(malformed, self.root / "bad-model")


if __name__ == "__main__":
    unittest.main()
