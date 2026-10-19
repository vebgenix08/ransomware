# RansomShield implementation status

Updated 2026-10-14. Completed means implemented and locally tested, not production
certification or verification across two physical laptops.

| Phase | Status | Evidence / remaining work |
|---|---|---|
| Flask accounts and dashboard | Completed | Existing login/CSRF; dashboard rendering and authenticated API tests |
| TCN + XGBoost synthetic training | Completed | Reproducible trainer, trained TCN kernels and XGBoost artifacts; frozen inference tests |
| Safe simulation and automatic response | Completed | Each invocation has its own UUID/directory; suspicious run quarantines generated test files; missing files audited |
| CSV evaluation and run history | Completed | Labeled two-second telemetry validation; isolated trace history; metrics, hashes, persisted completed/failed runs |
| Incident details and CSV reports | Completed | Run/alert IDs, UTC timestamp, prediction, risk, activity, per-file response and notification status |
| Configurable notifications | Completed locally | Environment-configured HTTPS webhook and STARTTLS SMTP; mocked success/failure tests; disabled until configured |
| Live delivery to user's email/webhook | Planned | Requires actual destination/server credentials and a delivery check |
| MLRan tabular integration | Completed locally | Public CSV acquired; separate XGBoost trained on 2,300 cleaned samples and evaluated on 324 held-out samples; dashboard and transfer ingestion enabled |
| Published-data temporal TCN validation | Planned | MLRan matrix has no temporal sequence; existing TCN remains synthetic-trained |
| Two-laptop transfer automation | Completed locally | SFTP sender, checksum-validating inbox receiver, automatic detection/response, owner dashboard and result receipt; local processing and mocked transport tests |
| Physical two-laptop secure transfer | Planned | Windows SSH Server/key/network setup and Laptop 1 access still needed; actual network transfer not performed |
| Published MLRan held-out evaluation | Completed locally | Accuracy 92.90%, precision 85.29%, recall 91.58%, F1 88.32%; upstream selection bias remains |
| Prospective endpoint validation | Planned | No real-world deployment or family-disjoint validation claimed |
| Production endpoint protection | Planned | Process attribution, endpoint agent, deployment hardening, external validation and durable background jobs |

## Model and response policies

- Run prediction uses the frozen model's probability threshold (currently 0.60).
- Every suspicious simulation/dataset run invokes quarantine of only generated
  test files, unless `AUTO_QUARANTINE=false`; notification delivery is attempted.
- Background monitoring retains its existing 60 risk alert / 85 risk quarantine
  policy. Medium-risk background alerts now also receive notification audits.
- A completed run may have failed notifications or partial quarantine. The UI
  and report show these independently. Deleted test files cannot be quarantined.
- CSV reports satisfy the requested PDF **or** CSV format. PDF export is not implemented.
- Existing live-monitor events are shared workspace telemetry; new run records
  and their associated alerts/reports are restricted to their creating account.

## Verification

Latest local verification: **33 tests passed**, including published MLRan runs,
local sender/receiver processing, label exclusion, transfer processing,
checksum rejection, duplicate suppression and sender batch validation. The prior
dashboard JavaScript plus 123 Alpine expressions passed Node syntax validation. A real
browser interaction/visual check has not been performed.

Training run: 6,000 synthetic sequences, seed 20261014, 4,800 train / 1,200 test.
Held-out hybrid metrics at threshold 0.60: accuracy 96.50%, precision 96.99%,
recall 94.71%, F1 95.83%, false-positive rate 2.17%. The separate 16-window demo
fixture is a workflow smoke test, not an independent benchmark.

Run `.\.venv\Scripts\python.exe -m unittest discover -s tests -v`.
Tests exercise real hybrid inference on controlled benign/suspicious records,
quarantine scope, missing files, repeat runs, malformed datasets, public-schema
rejection, reports, notification outcomes, authentication and run ownership.
