# Included datasets

`../../data/mlran/` contains published MLRan research data, a cleaned held-out CSV, and training report. The app uses its separately trained tabular XGBoost model for this schema. Read [mlran/README.md](mlran/README.md) for provenance and limitations.

`../../data/rande_w11_preview.csv` is an unmodified public preview. The application rejects it because its feature definitions do not match either supported model. It is retained for schema research only.

The user-facing synthetic demo CSV, generated decoy files, and demo data generator have been removed. Automated tests may still construct isolated synthetic telemetry rows to verify edge cases; those rows are not loaded into the application.

The temporal telemetry model artifact remains synthetic-trained because live telemetry inference depends on its feature schema and weights. Its output is explicitly experimental and does not establish real-world detection performance. Replacing it responsibly requires compatible, labeled temporal endpoint telemetry and independent validation.
