# RansomShield

RansomShield is a local Flask research prototype for directory activity monitoring and labeled CSV evaluation. Live monitoring uses explicit rolling file-change burst rules; it reports an activity anomaly, not a ransomware verdict. The temporal TCN + XGBoost detector was trained on synthetic sequences and is used only for offline telemetry CSV evaluation. Neither path is production endpoint protection.

## Start the application

From the project directory in PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python run.py
```

Open <http://127.0.0.1:5000>, create an account, and sign in. Account credentials are separate from the Gmail notification credentials in `.env`.

For a new installation, install dependencies and create a secret first:

```powershell
python -m pip install -r requirements.txt
python -c "import secrets; print(secrets.token_hex(32))"
```

Copy `.env.example` to `.env`, paste the generated value into `SECRET_KEY`, then start the app. The existing local `.env` is ignored by Git and must never be committed or shared.

## Use the dashboard

- **Run the SILRAD benchmark:** prepare the dataset once using the command below, then select **Run SILRAD held-out test**. The app trains on the publisher's training split and reports results on its separate test split.
- **Monitor a directory:** set `MONITOR_TARGET_PATH` in `.env` to a directory you control, restart the app, then choose **Start monitoring**. The default is the empty `instance/monitor_target` folder. Start with a disposable test folder. Live alerts use a rolling 30-second window: at least 10 distinct deletions, 20 modifications, or 30 distinct changed files with at least 10 modified or deleted. Each alert includes the observed counts. The score is a heuristic activity indicator, not a probability. Alerts have a 60-second cooldown; rule-based alerts never auto-quarantine files.
- **Review results:** the dashboard refreshes events, alerts, and runs automatically. SILRAD predictions can be downloaded as a CSV. Dataset analysis never moves local files.
- **Laptop transfer:** follow [TWO_LAPTOP_SETUP.md](TWO_LAPTOP_SETUP.md) to receive CSVs over SFTP. The receiver validates the transfer manifest and checksum before analysis.
- **VM folder monitoring:** follow [REMOTE_AGENT_SETUP.md](REMOTE_AGENT_SETUP.md) to forward safe file activity summaries from an HTTPS-connected Windows VM.

### SILRAD Sysmon benchmark

The dashboard includes a separate **Run SILRAD held-out test** action. Prepare the local data and project-specific XGBoost model once from the published SILRAD archive:

```powershell
.\.venv\Scripts\python.exe scripts\setup_silrad.py
```

This downloads the publisher's separate training and test CSVs into the ignored `instance/silrad/` folder, trains only on `fasttext-trainmodel.csv`, and evaluates only `fasttext-testmodel.csv`. The held-out test split contains 156,841 labeled Sysmon events; the training split contains 39,999. The app provides an aggregate report and a separate row-prediction CSV without copying raw command lines or other Sysmon text into the database. Results are a dataset benchmark, not a live-computer diagnosis. The model is this project's hashed-text XGBoost adaptation; it does not reproduce the paper's reported algorithm, and its 0.60 threshold is fixed rather than calibrated on the test split.

The current run at the fixed 0.60 threshold produced 10.17% recall (1,986 true positives, 17,543 false negatives) on the publisher's held-out split. That is poor detection coverage, so this model is not suitable for live alerts. The source repository does not declare a redistribution license. The setup script keeps the data and derived model local under `instance/`; do not redistribute them without checking the publisher's terms. Source: [SILRAD dataset](https://github.com/JamilIsp/SILRAD-dataset).

### Dataset formats

The dashboard benchmark uses SILRAD Sysmon event CSVs only. The setup script downloads the publisher's separate train and test splits; arbitrary CSV uploads are not part of this benchmark workflow. Other legacy CSV API routes remain for compatibility but are not shown in the dashboard.

The bundled MLRan dataset is published research data. Its scores are specific to that dataset and inherit its sampling limitations. The TCN telemetry artifact is synthetic-trained and used only for offline CSV runs. No live endpoint detector here has been prospectively validated against real ransomware; burst alerts can still have false positives and misses.

## Email notifications

Email is configured per installation in the local `.env` file. The repository does not include anyone's sender address, recipient, or password. Copy `.env.example` to `.env`, enter values for your email provider, and restart the Flask app and SFTP receiver after editing it.

For Gmail, set values like these in your local `.env`:

```dotenv
APP_NAME=RansomShield
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURITY=starttls
SMTP_USERNAME=your-gmail-address
SMTP_PASSWORD='your-16-character-app-password'
RESPONSE_EMAIL_FROM='RansomShield <your-gmail-address>'
RESPONSE_EMAIL_TO=recipient@example.com
```

Use a Google App Password, not your Google account password. Email alerts are sent as readable plain text and distinguish offline CSV results from live folder activity. Dataset notices state that flagged records do not indicate an infected computer. A `sent` status means Gmail accepted the message; it does not prove inbox delivery or reading. Automated tests mock SMTP and do not send email.

For reusable per-installation email settings and the Firebase/hosting workflow, see [INTEGRATIONS_SETUP.md](INTEGRATIONS_SETUP.md). Firebase Authentication is optional; enable it only after entering that installation's web config and configuring trusted Firebase Admin credentials.

If you are new to Firebase, follow the [click-by-click Firebase setup guide](FIREBASE_SETUP_WALKTHROUGH.md). It starts with a no-billing staging project and Authentication only.

## Quarantine policy

`QUARANTINE_MODE=dry-run` is the default. Dataset alerts never move local files. Live file-burst rules are audit-only and do not auto-quarantine because file-change volume alone does not establish malware.

## Install as a PWA

Run locally at `http://127.0.0.1:5000` or serve over HTTPS, then use the browser's **Install RansomShield** prompt or its install menu. The service worker caches static interface assets and an offline page. It never caches the authenticated dashboard, API responses, uploaded datasets, or incident evidence. Offline mode does not expose cached account data.

## Test the application

Run the automated suite from the project directory:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The suite checks authentication, schema validation, model inference, incident ownership, notification outcomes with mocks, quarantine and restore behavior, SFTP integrity handling, and PWA routes. It does not test real Gmail delivery or a physical two-laptop transfer.

To check Gmail delivery manually, run the SILRAD held-out evaluation from the signed-in dashboard. If it creates a suspicious incident, check the incident's email status and then the configured inbox. A successful SMTP status is not a delivery receipt.

## Project folders

- `app/` Flask routes, models, dashboard, detector, PWA assets, and response logic
- `app/artifacts/` frozen model artifacts
- `data/mlran/` published MLRan data and provenance notes
- `instance/` local database, monitor target, SILRAD files/model, received data, quarantine, and run reports; ignored by Git
- `scripts/` training, evaluation, and SFTP sender/receiver utilities
- `tests/` isolated automated tests

## Known limits

This is a research prototype. Live alerts are conservative rolling file-change rules and can still produce false positives or miss activity. Filesystem monitoring does not provide process attribution or content-based encryption confirmation. No live endpoint malware tests or physical laptop transfer have been verified. Do not rely on it to protect production data or replace endpoint security software.
