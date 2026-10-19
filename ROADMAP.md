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
| Startup hardening | Completed | Refuses to start without `SECRET_KEY`; waitress by default; `FLASK_DEBUG` opt-in |
| Schema migrations | Completed | Flask-Migrate revisions 0001–0003; existing databases stamped, not recreated |
| Windows event collection | Completed locally | watchdog observations feed a bounded queue with drop counting; per-cycle snapshot diff and 30 s reconciliation |
| Quarantine recovery | Completed | Hash-verified restore; `QUARANTINE_MODE=dry-run` records proposed actions |
| Model registry | Completed | Loaded artifacts recorded by SHA-256; alerts carry the model version and contributing signals |
| Authenticated release downloads | Completed | `/downloads` with manifest checksums, server-side re-verification and download audit log |
| Offline dashboard | Completed | Bootstrap, icons and Alpine vendored; no CDN requests |
| XGBoost-only baseline and false-positive measurement | Planned | Compare against the hybrid; measure alerts per hour of benign activity |
| Process attribution | Planned | Requires ETW or Sysmon; filesystem notifications alone do not supply it |

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
- Quarantine is reversible: `QuarantineItem` stores the original relative path
  and SHA-256, and restore refuses if the hash, path or destination changed.
  `QUARANTINE_MODE=dry-run` validates and records `would_quarantine` without
  moving anything.
- Alerts record `model_version` (`display_name@artifact_sha256[:12]`) and a
  `rule_trace` listing the signals that contributed to the decision.

## Verification

Latest local verification: **46 tests passed**, including release-download
authorisation, traversal and tamper rejection, quarantine restore, dry-run,
hash recording, published MLRan runs, local sender/receiver processing, label
exclusion, transfer processing, checksum rejection, duplicate suppression and
sender batch validation. The dashboard JavaScript has not been re-checked in a
real browser after vendoring the assets.

Training run: 6,000 synthetic sequences, seed 20261014, 4,800 train / 1,200 test.
Held-out hybrid metrics at threshold 0.60: accuracy 96.50%, precision 96.99%,
recall 94.71%, F1 95.83%, false-positive rate 2.17%. The separate 16-window demo
fixture is a workflow smoke test, not an independent benchmark.

Run `.\.venv\Scripts\python.exe -m unittest discover -s tests -v`.
Tests exercise real hybrid inference on controlled benign/suspicious records,
quarantine scope, missing files, repeat runs, malformed datasets, public-schema
rejection, reports, notification outcomes, authentication and run ownership.
