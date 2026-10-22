# RansomShield

RansomShield is a local Flask research prototype for monitoring file activity and evaluating labeled datasets. Live alerts are based on file activity rules; they are not a confirmed ransomware verdict or a replacement for endpoint security software.

## Download and run on Windows

Install Git and Python, then run these commands in PowerShell:

```powershell
git clone https://github.com/vebgenix08/ransomware.git
cd ransomware
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
```

Open the new `.env` file. Paste the generated value after `SECRET_KEY=`. For a basic local run, leave `DATABASE_URL` blank (the app uses local SQLite), keep `AUTH_PROVIDER=local`, and leave Firebase and SMTP settings blank. Save `.env` and start the app:

```powershell
.\.venv\Scripts\python.exe run.py
```

Open <http://127.0.0.1:5000>, create an account, and sign in. Keep the terminal open while using the app; press **Ctrl+C** in that terminal to stop it. Never commit or share `.env`.

## Optional services

- **Firebase Authentication:** follow [docs/FIREBASE_SETUP_WALKTHROUGH.md](docs/FIREBASE_SETUP_WALKTHROUGH.md). Keep `AUTH_PROVIDER=local` until the Firebase web settings and private Admin credentials are configured. Never commit or share the service-account JSON.
- **Email alerts:** add your provider settings to `.env`. For Gmail, use a Google App Password, not your usual Gmail password. See [docs/INTEGRATIONS_SETUP.md](docs/INTEGRATIONS_SETUP.md). Restart the app after changes. An alert must be created, and email notifications must be enabled for the account, before an email is sent.
- **Monitor a second Windows computer:** configure `AGENT_API_TOKEN` and `AGENT_OWNER_EMAIL` on the app server, then follow [the Windows endpoint-agent guide](docs/WINDOWS_ENDPOINT_AGENT.md). The agent reports file activity and device check-ins; confirmed manual quarantine and restore requests run on the endpoint while its agent is online.

## Documentation

The [RansomShield User Guide](docs/USER_GUIDE.md) explains dashboard workflows, folder monitoring, the SILRAD benchmark, email behavior, testing, and known limitations. Firestore, Firebase Storage, and Firebase Hosting are not needed for the current application.

Use `requirements.txt` for the app. The smaller `scripts/requirements-agent.txt` is for a separate Windows agent computer; `requirements-presentation.txt` is only for regenerating the presentation with `scripts/generate_project_ppt.py`. Neither optional file is needed to run the app.
