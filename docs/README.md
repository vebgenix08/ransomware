# RansomShield

RansomShield is a local Flask research prototype for directory activity monitoring and labeled CSV evaluation. Live monitoring uses explicit rolling file-change burst rules; it reports an activity anomaly, not a ransomware verdict. The temporal TCN + XGBoost detector was trained on synthetic sequences and is used only for offline telemetry CSV evaluation. Neither path is production endpoint protection.

## Download and set up on Windows

These steps assume Git and Python are installed. Run each command in PowerShell. The `.env` file and Firebase private key belong to each installation; they are intentionally not downloaded from Git.

```powershell
git clone https://github.com/vebgenix08/ransomware.git
cd ransomware
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
```

Open `.env` in a text editor. Paste the generated random value after `SECRET_KEY=`. For a basic local run, leave `DATABASE_URL` blank (SQLite is created automatically), keep `AUTH_PROVIDER=local`, and leave SMTP/Firebase fields blank. Save the file. Never commit or share `.env`.

## Run and sign in

From the project folder in PowerShell:

```powershell
.\.venv\Scripts\python.exe run.py
```

Open <http://127.0.0.1:5000>, create an account with an email you can access, and sign in. Keep the terminal open while using the app; press **Ctrl+C** there to stop it. If PowerShell says the address is already in use, another RansomShield server is running on port 5000.

## Configure Firebase and email

Both services are optional for a local first run. Configure only the services you want, in the project-root `.env`, then restart the app.

- **Firebase sign-in:** follow [FIREBASE_SETUP_WALKTHROUGH.md](FIREBASE_SETUP_WALKTHROUGH.md). It explains creating a Firebase project, enabling Email/Password, filling the `FIREBASE_*` web settings, and securely configuring the Firebase Admin service-account file. Keep `AUTH_PROVIDER=local` until every Firebase step is complete; then set it to `firebase`. Never commit or send the Admin JSON key.
- **Email alerts:** configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY`, `SMTP_USERNAME`, `SMTP_PASSWORD`, and `RESPONSE_EMAIL_FROM`. For Gmail, use a Google App Password, not the normal account password. Alerts for signed-in users are sent to their account email; `RESPONSE_EMAIL_TO` is only a fallback. See [INTEGRATIONS_SETUP.md](INTEGRATIONS_SETUP.md) for the exact `.env` example and SMTP settings. Restart the app after saving changes.

An email is sent only when the application creates an alert and email notification is enabled for that account. An SMTP “sent” result means the mail server accepted the message; check Inbox and Spam to confirm arrival. Firebase Firestore, Firebase Storage, and Firebase Hosting are not needed for the current local app. Firebase Authentication does not replace the app's SQLite/PostgreSQL database.

## Use the dashboard

- **Run the online benchmark:** select **Prepare benchmark on server**, wait for setup to finish, then select **Run online benchmark**. The app trains on the published SILRAD data and scores its separate test stream prequentially. On Render, set `SILRAD_DATA_DIR` to a persistent-disk path if you have one; otherwise prepare again after a redeploy that clears local files.
- **Set live alert limits:** in **Monitor files**, stop the server monitor, choose the rolling time window (5–300 seconds), deletion limit, modification limit, total-change limit, and minimum modified/deleted count for a mixed burst, then choose **Save settings**. Limits can be 1–5,000. The settings apply to server-folder, browser-folder, and endpoint-agent alerts. The score is a heuristic, not a probability. Alerts have a 60-second cooldown.
- **Monitor the app server:** set `MONITOR_TARGET_PATH` in `.env`, restart the app, then choose **Start server monitor**. The default is `instance/monitor_target`. Quarantine is manual by default: choose **Quarantine file** beside an existing file listed in a server-folder alert. You can optionally enable **Automatically quarantine changed files when an alert triggers** in **Monitor files**. Automatic mode moves created or modified files still present in the watched server folder, up to the 100 paths displayed in that alert. It cannot move files already deleted. It may move ordinary files if your limits are too low, so test with the automatic option off first. Restore quarantined files from **Email & history**. Browser-picked folders and dataset runs cannot be quarantined by the server.
- **Try the six-step file activity walkthrough:** run `scripts/demo_folder_activity.bat`, enter the server folder watched by the app (or press Enter to use `MONITOR_TARGET_PATH` from `.env`), then start the server-folder monitor and press Enter. The script runs six stages in its own `RansomShield-Guided-Demo-*` folder: create files, modify a few, modify enough to reach the saved limit, create a second set, delete files, then create/modify/delete a mixed set. After each of the first five stages, review Recent activity and press Enter; the script waits out the configured alert window before continuing. It leaves the demo folder in place for review. Automatic quarantine may move modified demo files; restore them from Email & history if needed. Deleted demo files cannot be restored from quarantine.
- **Choose a folder in the dashboard:** on Chrome or Edge over HTTPS (or localhost), select **Choose folder** to monitor a folder on the computer running your browser. The browser polls file names, sizes, and modification times and sends relative-path activity summaries to your account; it does not upload file contents. Monitoring runs only while the dashboard page remains open, can miss short-lived changes between scans, and supports folders with fewer than 5,000 files. The browser grants read access to the folder you select. The server-folder monitor above remains separate and watches only the host machine.
- **Review results:** the dashboard refreshes events, alerts, and runs automatically. Benchmark predictions can be downloaded as a CSV. Dataset analysis never moves local files.
- **Review alerts:** filter by open/resolved state and severity. **Acknowledge** marks an alert reviewed; **Resolve** closes it. Failed email attempts can be retried, but an SMTP-accepted email cannot be resent from the dashboard. The account-level email toggle is on by default and its changes appear in the audit history.
- **Audit history:** the dashboard records sign-ins, email preference changes, monitoring start/stop, dataset analyses, incoming folder activity, and alert actions for the signed-in account. SMTP credentials remain in `.env` and are never displayed or stored in the account record.
- **Laptop transfer:** follow [TWO_LAPTOP_SETUP.md](TWO_LAPTOP_SETUP.md) to receive CSVs over SFTP. The receiver validates the transfer manifest and checksum before analysis.

### RansomShield Online Benchmark

The dashboard includes **Prepare benchmark on server** and **Run online benchmark** actions. The setup fetches the published SILRAD dataset at runtime and stores it under `SILRAD_DATA_DIR` (default `instance/silrad/`). It is not bundled in Git or the Docker image. You can also prepare it locally:

```powershell
.\.venv\Scripts\python.exe scripts\setup_silrad.py
```

The setup downloads the publisher's separate training and test CSVs. The primary benchmark uses an Adaptive Random Forest with ADWIN drift detectors on the publisher's five numeric SILRAD features. It chooses a recall-weighted F2 threshold using only the final 20% of the training file. Test evaluation is prequential: each event is predicted first, then its known SILRAD label updates the model for the next event. The report also includes a frozen-model diagnostic and a static hashed-text XGBoost comparison; these scores use different learning methods and should not be treated as a controlled head-to-head comparison. This offline dataset provides labels; the live endpoint does not have immediate verified labels, so this benchmark does not validate live detection. The implementation follows core SILRAD ideas but is not a bit-for-bit reproduction of the paper. The app provides aggregate results and row predictions without copying raw command lines or other Sysmon text into the database.

The source repository does not declare a redistribution license. The setup script keeps the data and derived models local under `instance/`; do not redistribute them without checking the publisher's terms. Sources: [SILRAD dataset](https://github.com/JamilIsp/SILRAD-dataset), [SILRAD paper](https://arxiv.org/abs/2501.01089).

### Dataset formats

The dashboard benchmark uses the published SILRAD Sysmon event CSVs. The setup script downloads separate train and test splits; arbitrary CSV uploads are not part of this benchmark workflow. Other legacy CSV API routes remain for compatibility but are not shown in the dashboard.

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
# Optional fallback only for alerts without an account owner
RESPONSE_EMAIL_TO=
```

Use a Google App Password, not your Google account password. Alerts for signed-in users go to that account's email; `RESPONSE_EMAIL_TO` is only a fallback for alerts without an account owner. Email alerts are sent as readable plain text and distinguish offline CSV results from live folder activity. Dataset notices state that flagged records do not indicate an infected computer. A `sent` status means Gmail accepted the message; it does not prove inbox delivery or reading. Automated tests mock SMTP and do not send email.

For reusable per-installation email settings and the Firebase/hosting workflow, see [INTEGRATIONS_SETUP.md](INTEGRATIONS_SETUP.md). Firebase Authentication is optional; enable it only after entering that installation's web config and configuring trusted Firebase Admin credentials.

If you are new to Firebase, follow the [click-by-click Firebase setup guide](FIREBASE_SETUP_WALKTHROUGH.md). It starts with a no-billing staging project and Authentication only.

## Quarantine policy

Automatic quarantine is off until enabled in **Monitor files**. A live alert is an activity warning, not proof of malware. In automatic mode, RansomShield moves changed files that still exist from `MONITOR_TARGET_PATH` to the separate `instance/quarantine/` folder and records a SHA-256 hash. Manual per-file quarantine remains available from server-folder alerts. Use **Restore** in **Email & history** to return a file if its hash and original path are unchanged. Browser-picked folder activity and dataset alerts never move files because the server has no write access to those user files. The saved monitor policy is stored locally in `instance/monitor_policy.json`.

## Install as a PWA

Run locally at `http://127.0.0.1:5000` or serve over HTTPS, then use the browser's **Install RansomShield** prompt or its install menu. The service worker caches static interface assets and an offline page. It never caches the authenticated dashboard, API responses, uploaded datasets, or incident evidence. Offline mode does not expose cached account data.

## Test the application

Run the automated suite from the project directory:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The suite checks authentication, schema validation, model inference, incident ownership, notification outcomes with mocks, quarantine and restore behavior, SFTP integrity handling, and PWA routes. It does not test real Gmail delivery or a physical two-laptop transfer.

To check Gmail delivery manually, run the RansomShield Online Benchmark from the signed-in dashboard. If it creates a suspicious incident, check the incident's email status and then the inbox for the signed-in account. A successful SMTP status is not a delivery receipt.

## Project folders

- `app/` Flask routes, models, dashboard, detector, PWA assets, and response logic
- `app/artifacts/` frozen model artifacts
- `data/mlran/` published MLRan data and provenance notes
- `instance/` local database, monitor target, SILRAD files/model, received data, quarantine, and run reports; ignored by Git
- `scripts/` training, evaluation, and SFTP sender/receiver utilities
- `tests/` isolated automated tests

## Documentation

- This README: install, run, use, configure email, and understand current limits.
- [INTEGRATIONS_SETUP.md](INTEGRATIONS_SETUP.md): per-installation environment settings and hosting notes.
- [FIREBASE_SETUP_WALKTHROUGH.md](FIREBASE_SETUP_WALKTHROUGH.md): Firebase Authentication setup.
- [TWO_LAPTOP_SETUP.md](TWO_LAPTOP_SETUP.md): transfer a dataset between Windows devices.
- [data/README.md](data/README.md) and [data/mlran/README.md](data/mlran/README.md): dataset scope, sources, and limitations.

The project presentation and research paper are retained as academic deliverables. Their historical methodology and results may not describe the current implementation; use this README for current application behavior.

## Known limits

This is a research prototype. Live alerts are conservative rolling file-change rules and can still produce false positives or miss activity. Filesystem monitoring does not provide process attribution or content-based encryption confirmation. No live endpoint malware tests or physical laptop transfer have been verified. Do not rely on it to protect production data or replace endpoint security software.
