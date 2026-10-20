# Deploy RansomShield to Google Cloud Run

This app is a Python/Flask server. Use Cloud Run for the server and PostgreSQL for persistent data. Firebase Hosting alone cannot run the Flask app. The Dockerfile in this project prepares the server for Cloud Run.

## Before starting

- Sign in to Google Cloud and select project `ransoware-staging`.
- Link a billing account. Cloud Run, Cloud SQL, and builds can incur charges. Set a budget alert first.
- Keep the database password, Flask secret key, and endpoint-agent token private. Enter them in Google Cloud Secret Manager or Cloud Run's secret settings; do not paste them into chat or commit them.
- The local `.env` file is excluded from the deployment image.

## Create the PostgreSQL database

In Google Cloud Console, open **Cloud SQL → Create instance → PostgreSQL**. Choose a nearby region, create an instance, then create a database and database user. Save the instance connection name, database name, user name, and password privately. Cloud SQL may have ongoing cost even when the web service is idle.

## Deploy the service

First, in **Secret Manager**, create three secrets: `ransomshield-secret`, `ransomshield-database-url`, and `ransomshield-agent-token`. Generate the first and third values on your computer:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

For `ransomshield-database-url`, use the PostgreSQL URL format below with your actual Cloud SQL values. Save the values directly into Secret Manager. Grant the Cloud Run service identity access to read these secrets and the **Cloud SQL Client** role.

```text
postgresql+psycopg://DB_USER:DB_PASSWORD@/DB_NAME?host=/cloudsql/PROJECT_ID:REGION:INSTANCE_ID
```

Install the Google Cloud CLI, open PowerShell in the project folder, then run:

```powershell
gcloud auth login
gcloud config set project ransoware-staging
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com sqladmin.googleapis.com secretmanager.googleapis.com
gcloud run deploy ransomshield --source . --region asia-south1 --add-cloudsql-instances YOUR_INSTANCE_CONNECTION_NAME --allow-unauthenticated --max-instances 1 --set-env-vars APP_NAME=RansomShield,AUTH_PROVIDER=local,SESSION_COOKIE_SECURE=true --set-secrets SECRET_KEY=ransomshield-secret:latest,DATABASE_URL=ransomshield-database-url:latest,AGENT_API_TOKEN=ransomshield-agent-token:latest
```

Replace `YOUR_INSTANCE_CONNECTION_NAME` with the Cloud SQL connection name shown in the database details. URL-encode special characters in the database username or password before saving the database URL secret. The app applies schema migrations when it starts. Keep the service at one maximum instance for the first deployment to avoid concurrent startup migrations.

The deployment command prints an HTTPS service URL. Open it, create/sign in to an account, then start the dashboard monitor. The VM agent can use this URL after you set the same `AGENT_API_TOKEN` on the VM terminal.

## What deployment does not finish

Cloud Run does not watch your laptop folders. Install the endpoint agent on the VM and point it at a dedicated test folder. Configure database backups in Cloud SQL and test a restore. Complete the PWA installation check in a browser. This research app is not validated as production ransomware protection.

Official guides: [deploy Flask to Cloud Run](https://docs.cloud.google.com/run/docs/quickstarts/build-and-deploy/deploy-python-service) and [connect Cloud Run to PostgreSQL](https://docs.cloud.google.com/sql/docs/postgres/connect-instance-cloud-run).
