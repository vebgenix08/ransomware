# RansomShield Flask Application

## SMTP email through .env

Fill the project-root `.env` using `.env.example`: `SMTP_HOST`, `SMTP_PORT`,
`SMTP_SECURITY`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `RESPONSE_EMAIL_FROM`, and
`RESPONSE_EMAIL_TO`. Use your provider's SMTP credentials/app password.
Use `starttls` with port 587 or `ssl` with port 465 as required by your provider.
Keep passwords quoted. No plaintext SMTP mode is supported.

Both the web app and receiver automatically load this file when starting,
regardless of their working directory. Existing process environment variables
take precedence. Restart both after changes. `.env` is ignored by Git; never put
real credentials in `.env.example` or the sender ZIP.

Run a suspicious simulation to trigger email. The dashboard shows configuration
as disabled/incomplete/configured and each incident records sent/failed/disabled.
Sent means SMTP acceptance, not inbox delivery. Actual delivery is unverified
until real credentials are provided; automated SMTP tests use mocks.

Multi-page Flask foundation for the RansomShield behavioral ransomware detection research project.

## October 2026 workflow update

Restart the application after updating. New tables are created automatically;
existing users, alerts and events are retained. See [ROADMAP.md](ROADMAP.md) for
verified work and remaining external dependencies.

1. Sign in and open **Dashboard**. Expand **Model training status** to inspect
   training source, timestamp, sample counts and held-out metrics.
2. Click **Simulate activity**. Monitoring need not be running. The server creates
   an isolated synthetic directory, analyzes its recorded activity with the frozen
   TCN + XGBoost model, and automatically quarantines affected test files when the
   prediction is suspicious. Five already-deleted files appear as failed moves.
3. Alternatively, download the safe CSV from the dashboard or use
   `data/safe_demo.csv`, select it, enter its name/source, and click **Analyze CSV**.
   For this fixture use source `locally generated synthetic demonstration`.
4. **Run history** updates immediately and every three seconds, including benign
   and failed evaluations. Each execution has a persistent UUID, incident link,
   risk, prediction, activity totals, metrics and response audit.
5. Download each run/incident's **CSV report**. It contains the requested incident
   fields, per-window observations/predictions, per-file quarantine results,
   notification status, model/dataset hashes and evaluation limitations.

The retrained model uses 6,000 synthetic sequences: 4,800 training and 1,200
held-out testing, seed `20261014`, threshold `0.60`. Held-out hybrid accuracy is
96.50%, precision 96.99%, recall 94.71%, F1 95.83%, false-positive rate 2.17%.
These are synthetic results, not ML-Ran/RanDe-W11 validation. TCN weights and
XGBoost are actually trained; scaling is fit only on the training split.

The unmodified public RanDe-W11 CSV preview is included under `data/`, with source,
license and hash in [data/README.md](data/README.md). Its feature schema is
incompatible with the current model and is explicitly rejected. Published MLRan training is now complete using a separate tabular XGBoost model; no temporal features are fabricated. See the current status below.

### Secure Laptop 1 → Laptop 2 transfer

For **automatic analysis as soon as the CSV arrives**, use the new Windows
[two-laptop setup guide](TWO_LAPTOP_SETUP.md): run `scripts/receive_dataset.py`
on Laptop 2 and `scripts/send_dataset.py` on Laptop 1. The receiver checks the
SHA-256 manifest, creates an account-owned run, invokes the model/response pipeline,
and returns its result over SFTP. `Laptop1_Sender.zip` contains only the standalone
sender, safe synthetic sample and instructions. No model or secrets are bundled.

The plain-copy procedure below is an alternative that requires manual upload:

Use an existing SSH/SFTP service on Laptop 2 over the private Wi-Fi network. Verify
its host-key fingerprint directly on Laptop 2 before accepting it. No transfer
has been performed here because the destination/access details are not supplied.

On Laptop 1, replace `laptop2-user` and `LAPTOP2-IP` with the real SSH destination:

```powershell
Get-FileHash .\data\safe_demo.csv -Algorithm SHA256
scp .\data\safe_demo.csv laptop2-user@LAPTOP2-IP:safe_demo.csv
```

On Laptop 2, compare the received checksum with Laptop 1, start RansomShield
locally, sign in and upload the received CSV through the dashboard:

```powershell
Get-FileHash .\safe_demo.csv -Algorithm SHA256
.\.venv\Scripts\python.exe run.py
```

Only CSV records move between laptops; no malware is executed. The existing Flask
debug server should remain on localhost. SSH/SFTP provides the encrypted transfer;
sharing a Wi-Fi network alone does not encrypt an HTTP upload.

### Run and notification behavior

Notifications remain configurable through the environment variables below, and
the dashboard shows which channels are configured without exposing secrets.
Every suspicious simulation/dataset run attempts notifications. Medium-risk live
monitor alerts now also get notification audits, while the background monitor's
quarantine threshold remains 85. Explicit runs quarantine test files at the model
decision threshold unless `AUTO_QUARANTINE=false`.

`sent` means accepted by the SMTP server or a successful HTTP response; it does
not prove the recipient read the alert. Real delivery requires the user's SMTP
credentials/webhook. Success/failure paths were tested with mocks only.

Uploaded requests are limited to 5 MB and 2,000 windows. Runs are synchronous;
use smaller batches split at trace boundaries. Uploaded path fields are ignored
for quarantine; the application generates harmless stand-ins for suspicious
dataset windows. New run records/reports are owned by their creating account;
legacy background-monitor events remain shared workspace telemetry. There is no
durable worker/retry or interrupted-run recovery yet.

## Current features

- Responsive public landing page
- Light and dark themes saved in the browser
- Account registration with validation and duplicate-email protection
- Secure password hashing
- Session-based sign-in and sign-out
- CSRF-protected forms
- Protected dashboard route
- SQLite user storage
- Safe post-login redirects
- Start and stop controls for the background monitor
- Live CPU, memory, and process-count metrics
- Structured synthetic decoy server under `instance/decoy_server` (Finance, HR, Backup, and Documents)
- Canary-file interaction, files/directories touched, and operation-rate telemetry
- Persisted monitoring events and trained behavioral-model alerts
- Safe ransomware-like create/modify/delete burst using harmless placeholder files; no encryption or malware
- Alert acknowledgement
- Automatic quarantine for high-risk detections (score >= 85), with per-file audit results
- Configurable HTTPS webhook and STARTTLS email notifications
- Frozen-model evaluation against independent telemetry CSV datasets

## Project structure

```text
.
|-- app/
|   |-- templates/
|   |   |-- auth/
|   |   |   |-- signin.html
|   |   |   `-- signup.html
|   |   |-- base.html
|   |   |-- dashboard.html
|   |   `-- index.html
|   |-- __init__.py
|   |-- auth.py
|   |-- extensions.py
|   |-- forms.py
|   |-- models.py
|   `-- routes.py
|-- run.py
`-- requirements.txt
```

All custom CSS and JavaScript remain inside the HTML templates. Bootstrap, Bootstrap Icons, Tailwind CSS, and Alpine.js are loaded from CDNs.

## Run locally

```powershell
.\.venv\Scripts\Activate.ps1
$env:SECRET_KEY = "replace-with-a-long-random-secret"
python run.py
```

Open `http://127.0.0.1:5000`.

The SQLite database is created automatically at `instance/ransomshield.db`. The `instance` directory is ignored by Git.

## Available routes

| Route | Purpose | Access |
|---|---|---|
| `/` | Landing page | Public |
| `/auth/signup` | Create account | Public |
| `/auth/signin` | Sign in | Public |
| `/auth/logout` | Sign out | Authenticated session / POST |
| `/dashboard` | Project dashboard | Sign-in required |
| `/api/monitor/status` | Live monitor status and metrics | Sign-in required |
| `/api/monitor/start` | Start the safe background monitor | Sign-in required / POST |
| `/api/monitor/stop` | Stop the monitor | Sign-in required / POST |
| `/api/monitor/demo` | Analyze an isolated safe simulation with a run ID and response | Sign-in required / POST |
| `/api/runs/dataset` | Upload and evaluate labeled telemetry CSV | Sign-in required / POST |
| `/api/runs` | Recent account-owned runs | Sign-in required |
| `/api/runs/<id>` | Full run evidence | Run owner |
| `/api/runs/<id>/report.csv` | Download run / incident CSV | Run owner |
| `/api/alerts/<id>/report.csv` | Download incident CSV | Sign-in required; run incidents restricted to owner |
| `/api/notifications` | Nonsecret notification configuration status | Sign-in required |
| `/api/events` | Recent monitoring events | Sign-in required |
| `/api/alerts` | Recent alerts | Sign-in required |

The monitor uses a hybrid TCN + XGBoost classifier. A causal TCN summarizes eight consecutive telemetry windows, and XGBoost combines that temporal representation with the latest eleven engineered measurements. Training reports an XGBoost-only ablation beside the hybrid. The checked-in model is trained on safe synthetic sequences and must be validated on representative labeled endpoint data before production use.

The “canary accessed” signal means a canary was observably changed or removed during a polling window. Pure read access is not claimed because portable snapshot polling cannot reliably observe it; a production deployment would require file-system audit telemetry or an endpoint agent.

Retrain the model using the NumPy and XGBoost dependencies in `requirements.txt`:

```powershell
.\.venv\Scripts\python.exe scripts\train_model.py --samples 6000 --seed 20261014
```

The command writes `app/artifacts/behavioral_model.json` and reports held-out accuracy, precision, recall, and F1. Use `--samples` and `--seed` to control the reproducible training run.

For a deployed environment, configure a strong `SECRET_KEY`, HTTPS, secure cookies, database migrations, rate limiting, per-user event ownership, and a production WSGI server.

## Automated response

High-risk file-activity alerts automatically move affected, existing regular files
from the decoy directory into `instance/quarantine/<alert-id>/<original-relative-path>`.
Missing/deleted files and failed moves are recorded. Medium-risk background-monitor
alerts do not move files; explicit simulation/dataset runs use the model threshold
for their generated test files. The dashboard and `/api/alerts` expose response completion, per-file results,
and notification delivery status. The new audit table is created on startup without
altering existing alert records. Restart the application after updating the code.

The default scope remains the synthetic decoy directory. Quarantine is a file move,
not process termination, access revocation, recovery, or a guarantee of containment
against an active attacker. Keep the quarantine directory private and on the same
filesystem; cross-filesystem moves fail safely. Review audit results before manually
restoring any file. Never overwrite an existing original during recovery.

Notifications are disabled until configured. Set environment variables before
starting the application:

```powershell
$env:AUTO_QUARANTINE = "true" # set false for alert-only operation
$env:RESPONSE_WEBHOOK_URL = "https://your-service.example/alerts"
$env:RESPONSE_EMAIL_TO = "analyst@example.com"
$env:RESPONSE_EMAIL_FROM = "ransomshield@example.com"
$env:SMTP_HOST = "smtp.example.com"
$env:SMTP_PORT = "587"
$env:SMTP_USERNAME = "your-smtp-user"
$env:SMTP_PASSWORD = "your-smtp-secret"
```

Either channel can be configured independently. SMTP requires STARTTLS. Outbound
requests have five-second socket timeouts; delivery failures are recorded without
undoing quarantine. Notifications run in the monitoring worker and may delay its
next poll. There is no automatic retry; an incomplete audit needs manual review.
Webhook payloads contain the alert and file results, including local paths, so use
a trusted endpoint. Secrets are read from the environment and are not displayed.

## External dataset evaluation

```powershell
.\.venv\Scripts\python.exe scripts\evaluate_external.py external.csv --dataset-name "Independent telemetry" --source "https://publisher.example/dataset" --output instance\external_evaluation.json
```

The evaluator loads the existing model without training or changing its weights.
Provide CSV columns `trace_id`, `window_index`, `label`, followed by all eleven
`FEATURE_NAMES` in `app/detector.py`. Labels are `0` (benign) or `1` (ransomware).
Each row must describe a **two-second window**, matching the training data; window
indices are consecutive integers within each independent host/run trace. The
evaluator sorts windows, rejects duplicate or missing indices, and clears temporal
history between traces. Each label describes its window, not an entire trace.

Counts must use the monitor's snapshot semantics (created, modified, and deleted
paths per window). `decoy_files_touched` is their sum, `directories_touched` counts
top-level directories, and `operation_rate` is total changes divided by two seconds.
CPU and memory are percentages, process count is a count, and canary indicators
mean observed modification/removal rather than read access. Count fields are not
interchangeable with whole-run API call frequencies. Missing features, negative
values, NaN, and infinity are rejected rather than silently imputed. An optional
`--mapping columns.json` maps canonical column names to source column names, e.g.
`{"created_count": "files_created"}`; it does not change measurement semantics.

The JSON report includes accuracy, precision, recall, F1, false-positive rate,
confusion counts, per-window predictions, dataset/model SHA-256 hashes, provenance,
and the decision threshold (artifact default, optionally set with `--threshold`).
Undefined metrics are `null`. Choose the threshold before external evaluation;
do not tune it on the external test labels. Correlated windows do not constitute
independent experimental samples.

[MLRan](https://github.com/faithfulco/mlran) publishes processed behavioral features
and Cuckoo parsing scripts. Its processed feature matrix is not a drop-in replacement
for this detector's ordered telemetry. A reviewed conversion from compatible source
traces is needed; absent resource/canary measurements cannot be assumed to be zero.
No published dataset has been evaluated by this change, and the existing accuracy
numbers remain synthetic results. This command supplies the evaluation pipeline,
not evidence of external generalization.

Run the automated integration and validation tests with:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Generate the project presentation

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-presentation.txt
.\.venv\Scripts\python.exe scripts\generate_project_ppt.py
```

This creates `RansomShield_Current_Implementation.pptx` with editable PowerPoint shapes and the current verified project status.

## Included published dataset: ready without uploads

The dashboard now offers **Run included MLRan dataset** and **Demo sender ? receiver locally**. Both use the included cleaned held-out MLRan CSV and automatically create run/incident evidence, placeholder quarantine and reports. The local transfer button does not use Wi-Fi or SSH.

MLRan training: 2,300 cleaned training samples and 324 held-out samples, with no sample-ID or exact selected-feature-vector overlap. Accuracy 92.90%, precision 85.29%, recall 91.58%, F1 88.32%. The model uses 202 binary API/file/directory/registry/drop indicators; labels, IDs, signatures, strings and system fingerprints are excluded. See `data/mlran/training_report.json` for counts, hashes and limitations.

This is **XGBoost on published tabular MLRan data**, not TCN validation. The existing synthetic TCN + XGBoost model still handles temporal telemetry. Publisher feature selection and collection bias remain limitations.

Reproduce: `.\.venv\Scripts\python.exe scripts/train_mlran.py`. The published-data download is `data/mlran/heldout.csv`; it can also be sent through the existing sender script. Actual two-device transfer and external notification delivery remain unverified.
