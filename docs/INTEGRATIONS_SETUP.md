# Integration and hosting settings

RansomShield is a Python Flask application. It uses SQLite locally unless `DATABASE_URL` points to PostgreSQL. Authentication, email, and endpoint-agent settings belong to each installation; never copy another installer's secrets.

## Local configuration

1. Copy `.env.example` to `.env` in the project root.
2. Generate `SECRET_KEY` with `python -c "import secrets; print(secrets.token_hex(32))"` and add it to `.env`.
3. Fill only the settings for services you are using. Leave `AUTH_PROVIDER=local` unless Firebase sign-in has been configured; see [FIREBASE_SETUP_WALKTHROUGH.md](FIREBASE_SETUP_WALKTHROUGH.md).
4. Restart the Flask app and any separately running receiver or agent after changing settings.

The checked-in `.env.example` is the authoritative list of supported variable names. It includes the database, SMTP, Firebase, webhook, monitor, SILRAD, and endpoint-agent settings. `.env` is local and must not be committed.

## Email alerts

Set the sender's provider details in `.env`:

```dotenv
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURITY=starttls
SMTP_USERNAME=sender@gmail.com
SMTP_PASSWORD='provider-app-password'
RESPONSE_EMAIL_FROM='RansomShield <sender@gmail.com>'
RESPONSE_EMAIL_TO=
```

For Gmail, use an App Password with 2-Step Verification, not the normal account password. For implicit TLS use port `465` and `SMTP_SECURITY=ssl`. Alerts for an owned account go to that account's email; `RESPONSE_EMAIL_TO` is only a fallback when an alert has no account owner. A `sent` status means the SMTP server accepted the message; it does not confirm inbox delivery. Tests mock SMTP and do not send messages.

## Render or another Python host

For a Render Web Service, use the repository root, build command `pip install -r requirements.txt`, and start command `waitress-serve --listen=0.0.0.0:$PORT run:app`. Add the required environment values in Render's Environment settings rather than uploading a developer's `.env` file. Set a strong `SECRET_KEY`; set `DATABASE_URL` to the provider's PostgreSQL URL if data must survive instance replacement; and set `SESSION_COOKIE_SECURE=true` when served over HTTPS. Configure SMTP values separately if email alerts are required.

Use persistent storage for files that must survive redeploys, including prepared SILRAD data. A hosted web service cannot monitor a user's personal computer folder; use the browser folder picker locally. Configure and verify database backups with the database provider. Firebase Hosting alone cannot run the Flask backend.

## Credentials and optional Firebase services

- Never commit or share `.env`, SMTP passwords, database URLs/passwords, OAuth secrets, Firebase service-account private keys, or endpoint-agent tokens.
- Firebase web config values are public-facing identifiers; the server still needs Firebase Admin credentials to verify sign-in tokens. Keep `GOOGLE_APPLICATION_CREDENTIALS` pointed to a private local key or use the host's identity mechanism.
- Firestore, Firebase Storage, and browser push notifications are not required for the current workflows. Do not enable them unless the application is explicitly extended to use them and access, retention, and billing have been planned.
- If any credential has been exposed, rotate it in its provider before using it again.
