# RansomShield integration setup

This guide is for connecting a new RansomShield installation to its own email and Firebase project. Each installation uses its own local `.env` file; do not put credentials in source code or commit them to Git.

## Current architecture

RansomShield is a Flask application. Flask serves the PWA and API, the analysis code runs on the Python backend, and SQLAlchemy stores users, runs, alerts, and response records in a local SQLite database by default. The model evaluation and live folder monitor are separate workflows. Live folder monitoring currently uses review-only file-change rules; it is not a validated ransomware verdict. The trained telemetry model is used for offline CSV evaluation only.

Email is configured per installation through its ignored `.env` file (`SMTP_*`, `RESPONSE_EMAIL_*`). The dashboard reports whether notification settings are complete without showing secrets. Firebase Authentication is implemented as an optional provider. A new installation defaults to local authentication (`AUTH_PROVIDER=local`); set its own `FIREBASE_*` web config values and select `AUTH_PROVIDER=firebase` only after the Firebase Console provider and trusted server credentials are ready. Never copy this developer machine's `.env` into another installation.

## Recommended upgrade architecture

1. **PWA client:** keep the current Flask-rendered interface and installable PWA. Add Firebase's web client SDK for sign-in and push notifications when those features are enabled.
2. **Identity:** use Firebase Authentication for registration, sign-in, verification, and password reset. The client sends its Firebase ID token over HTTPS to Flask. Flask verifies the token with the Firebase Admin SDK and uses the verified Firebase UID as the identity for every API request.
3. **Analysis API:** keep CSV validation, model inference, monitoring policy, incident creation, and response auditing in Flask/Python. Firebase Authentication does not improve the detector's accuracy.
4. **Operational database:** initially keep the current SQLAlchemy schema and migrate SQLite to managed PostgreSQL when multi-user production hosting is ready. This preserves relational ownership and existing migration patterns. Use Firestore only if the team intentionally wants a document database and is ready to redesign queries, ownership rules, and migrations.
5. **Uploads:** keep strict server-side file size/schema validation. If larger datasets need cloud storage, use a private Firebase Storage bucket with per-user rules and upload limits; store only metadata and hashes in the operational database. Do not upload users' real telemetry without an explicit retention and privacy policy.
6. **Notifications:** retain the configurable SMTP adapter for email. Add Firebase Cloud Messaging as an optional PWA push channel; it requires HTTPS, browser permission, a service worker, and VAPID configuration.
7. **Hosting:** deploy the Python backend to a Python-capable service such as Cloud Run. Firebase Hosting can serve a static frontend and route API requests to a backend, but it does not turn the current Flask server into a static app.

### Request and event flow

```text
Browser/PWA -> Firebase Auth -> ID token -> Flask API (verify token)
                                             |-> PostgreSQL: users' runs, alerts, audit records
                                             |-> Python analysis worker / monitored folder agent
                                             |-> SMTP email and optional Firebase push
                                      Optional private Storage: uploaded dataset objects
```

## Values and credentials needed

### Needed to configure Firebase Authentication

Create a Firebase project and register a **Web App**, then provide these non-secret identifiers/config values:

- Firebase project ID
- Web app config: `apiKey`, `authDomain`, `appId`, `messagingSenderId`
- `storageBucket` only if Storage is selected
- The production site hostname(s) to add as authorized domains
- Which sign-in methods to enable: email/password (recommended first) and optional Google sign-in

Firebase web config is intended to be present in a web app, but it is still important to restrict authorized domains, enable appropriate services, and secure Firestore/Storage with rules. Never mistake the web API key for backend authorization.

The Flask backend also needs a trusted Google identity to verify ID tokens. Prefer a least-privilege attached service identity on Cloud Run. For local development, ADC is preferred where configured; a service-account JSON key may be used as a local-development fallback. Store it only under the ignored `instance/secrets/` folder and set `GOOGLE_APPLICATION_CREDENTIALS` in `.env` to its path. Never paste that private JSON, private key, or refresh token into chat, email, Git, or a shared document.

### Needed only for optional Firebase features

- **Firestore:** confirm which collections/data should be cloud-shared and the user/role access policy. Firebase Admin server libraries bypass Firestore Security Rules, so server IAM permissions must also be set correctly.
- **Storage:** decide allowed file types, maximum size, retention/deletion period, and who can read each object. Check [Firebase pricing and plan requirements](https://firebase.google.com/docs/projects/billing/firebase-pricing-plans) before enabling Cloud Storage; requirements and included quotas can change. Set a budget alert before enabling billable services.
- **Web push (FCM):** Firebase project messaging configuration, a VAPID public key for the browser, and a clear opt-in flow. Do not request browser notification permission until the user chooses to enable notifications.
- **Google sign-in:** enable the provider in Firebase Console and configure OAuth consent/authorized domains. Keep any OAuth client secret private if the selected flow requires one.

### Needed for email (already supported)

Set these per installation in `.env`:

```dotenv
APP_NAME=RansomShield
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURITY=starttls
SMTP_USERNAME=sender@gmail.com
SMTP_PASSWORD='provider-app-password'
RESPONSE_EMAIL_FROM='RansomShield <sender@gmail.com>'
RESPONSE_EMAIL_TO=recipient@example.com
```

For Gmail, use an App Password (with 2-Step Verification enabled), not the normal Google account password. Another organization can replace the SMTP host, port, security mode, sender, and recipient with its provider values. Use port 587 with STARTTLS or port 465 with SSL. Leave the recipient blank to disable email alerts. Restart the app and receiver after editing `.env`.

Never share `SMTP_PASSWORD`, Google account passwords, Firebase private keys, OAuth secrets, database passwords, or production webhook URLs in chat. Put them directly in the deployment's secret manager or ignored local `.env` file. The checked-in `.env.example` is a template; each recipient copies it to `.env` and enters their own values.

### Needed if moving the database to a managed service

- A PostgreSQL database/project and connection information, stored as a secret (not in Git)
- A backup/restore plan and a maintenance window for copying the existing SQLite data
- A decision about whether existing local accounts are recreated or migrated; passwords cannot be recovered from password hashes, so users may need to reset them

## Setup and rollout steps

1. **Create a staging Firebase project** separate from production. Register a Web App and enable Email/Password Authentication.
2. **Set allowed domains** for local development and the staging hostname. Add production domains only at production rollout.
3. **Choose the identity transition.** Existing local accounts use Flask password hashes and cannot be silently converted into Firebase passwords. Either invite users to create Firebase accounts and map old data by verified email, or require password reset/re-registration. Do not migrate password hashes into Firebase.
4. **Enable the existing bridge:** the app has an optional Firebase web sign-in flow and Firebase Admin ID-token verification. Set the local `GOOGLE_APPLICATION_CREDENTIALS` path and `AUTH_PROVIDER=firebase`, restart the app, verify a Firebase user, and confirm the backend maps that verified UID to the app's existing user row. Keep a tested recovery path before switching a shared installation.
5. **Add service rules before enabling data services.** Test Firestore/Storage access with the Firebase Emulator Suite and ensure users cannot read another user's records or uploaded files.
6. **Configure email and optional push independently** using the installation's secrets. Test with a staging mailbox and verify message content, not just SMTP acceptance.
7. **Deploy the backend and PWA over HTTPS.** Set secure cookies/CORS/CSRF policy for the chosen deployment topology, configure health checks, backups, logging, and budget alerts.
8. **Run acceptance checks:** account creation, email verification, sign-in/out, password reset, unauthorized API rejection, cross-account data isolation, valid/invalid CSV handling, alert text, email delivery, push opt-in, PWA install/offline behavior, database migration/restore, and rollback.
9. **Promote to production only after review.** Keep the current research limitations visible; do not claim real-world ransomware detection performance from benchmark or synthetic test results.

## What to send next

To configure a new installation, enter that Firebase project's web config in its local `.env`, then configure a trusted server identity as described above. The web config is installation-specific; keep private server credentials local or in the deployment secret manager.

Do not send an SMTP password or Firebase service-account key. If a credential has already been posted in chat or committed, rotate/revoke it before using the integration.
