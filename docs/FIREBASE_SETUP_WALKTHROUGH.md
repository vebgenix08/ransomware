# Firebase setup: click-by-click for RansomShield

This creates a **staging Firebase project for account sign-in only**. Do not set up Firestore, Storage, Hosting, or billing yet. We should connect and verify Authentication first, then add other services only when the app architecture is ready.

Firebase's official web setup guide: <https://firebase.google.com/docs/web/setup>

## Before you start

- Use a Google account you control. You do not need to give anyone your Google login.
- Choose a project name such as `ransomshield-staging`. The display name can be changed, but the **project ID cannot be changed later**, so inspect it before creating the project.
- Keep the project on the **Spark (no-cost) plan**. Email/password Authentication does not require adding a payment card for this initial setup. Do not upgrade billing for this step.
- This is a staging project. We will create a separate production project if/when the app is deployed for real users.

## Part A — Create the Firebase project

1. Open <https://console.firebase.google.com/> and sign in to your Google account.
2. On the Firebase home page, click **Create a project** (or **Add project**).
3. Enter the staging project name you chose (for example, `ransomshield-staging`).
4. Review the generated **Project ID**. If you want to change it, do that now; Firebase does not let you rename the project ID after creation.
5. Click **Continue**.
6. If asked about Gemini or AI assistance, leave it off; it is not needed for this app.
7. If asked to enable Google Analytics, turn it off for now. It is optional and not needed for user sign-in.
8. Click **Create project**, wait for setup to finish, then click **Continue**.

The project overview page should now be open.

## Part B — Register the RansomShield web app

1. On the project overview page, click the **Web** icon. It looks like `</>`.
2. For the app nickname, enter `RansomShield Web - Staging`.
3. Leave **Also set up Firebase Hosting** unchecked if it appears. The current Python/Flask app needs a Python backend; Hosting alone cannot run it.
4. Click **Register app**.
5. Firebase will display the web app setup/code screen. Look for the **Firebase configuration object**, with fields like:

   - `apiKey`
   - `authDomain`
   - `projectId`
   - `storageBucket`
   - `messagingSenderId`
   - `appId`

6. Keep this page open or copy the config object into a temporary local text file. Do not copy a private service-account key; this is a different thing.
7. Click **Continue to console** when ready.

Official instructions for registering a web app: <https://firebase.google.com/docs/web/setup#register-app>.

## Part C — Turn on email/password sign-in

1. In the Firebase Console's left menu, open **Build → Authentication**. If it shows a **Get started** button, click it.
2. Open the **Sign-in method** tab.
3. Select **Email/Password**.
4. Turn on the regular **Email/Password** option. Leave **Email link (passwordless sign-in)** off for now.
5. Click **Save**.
6. Open **Settings** for Authentication and find **Authorized domains**.
7. Confirm `localhost` is listed. If it is not, add `localhost` for local development. Do not add a production domain until the app has one.

Official instructions: <https://firebase.google.com/docs/auth/web/password-auth>.

## Part D — Enter the web config in your local environment

In the project-root `.env` file, set the public web configuration values from Part B. These identify the Firebase web app; they are not server credentials:

Keep `AUTH_PROVIDER=local` until Part E is complete and the server can verify Firebase tokens. Set `AUTH_PROVIDER=firebase` only as part of that final local configuration step.

```text
FIREBASE_API_KEY=your-web-api-key
FIREBASE_AUTH_DOMAIN=your-project-id.firebaseapp.com
FIREBASE_PROJECT_ID=your-project-id
FIREBASE_MESSAGING_SENDER_ID=your-sender-id
FIREBASE_APP_ID=your-web-app-id
```

You may omit `storageBucket` because Storage is not part of this first step. Do not send a screenshot containing your Google account details if you can copy the config text instead.

### Never send these

- Google account password or verification codes
- Firebase service-account JSON or its `private_key`
- SMTP password / Gmail App Password
- OAuth client secret
- Database password

The web config is not the backend credential. Flask will later need a server-side Firebase Admin identity to verify sign-in tokens. We will configure that locally with Application Default Credentials or a protected hosting identity; we will not put a private key in source code or chat. Firebase recommends Application Default Credentials in Google-hosted environments: <https://firebase.google.com/docs/admin/setup>.

## Part E — Configure the server's Firebase identity (keep it private)

The app code is now ready for Firebase Authentication, but local login stays active until the Flask backend can verify Firebase tokens. The web config from Part B is not sufficient for this server-side verification.

For this local development project, the simplest option is a Firebase Admin SDK service-account key. It is a powerful private credential, so keep it on this computer only:

1. In Firebase Console, click the gear icon → **Project settings** → **Service accounts**.
2. Check that the selected project is the staging project you created.
3. In the **Firebase Admin SDK** section, click **Generate new private key**, then confirm.
4. Save the downloaded JSON file into `instance/secrets/firebase-admin.json` inside this repository. Create the `secrets` folder if needed. The `instance/` folder is excluded from Git.
5. Open the local `.env` file in the project root. Set these two entries (use your real absolute path for the key):

   ```dotenv
   AUTH_PROVIDER=firebase
   GOOGLE_APPLICATION_CREDENTIALS="C:/path/to/project/instance/secrets/firebase-admin.json"
   ```

6. Save `.env` and restart RansomShield. If the JSON is missing or invalid, switch back to `AUTH_PROVIDER=local` until the path is corrected.

**Never upload or paste that JSON here.** If it is accidentally shared, delete/revoke the key in Google Cloud IAM and create a replacement. On hosted Google Cloud deployments, use an attached service identity/ADC instead of downloading a key. Firebase's Admin SDK setup explains these credential options: <https://firebase.google.com/docs/admin/setup>.

## What happens after setup

After Parts A–E, restart the app and use **Create account** with an email you can access. The app confirms that Firebase sent a verification link, then redirects to the sign-in page. Open the email and verify the address before signing in. If the email already exists in the local SQLite users table, the verified Firebase account links to that row so existing run history stays attached. Then test sign-in and password reset.

The project tests cover token verification using mocked Firebase claims; a real end-to-end login still requires the Firebase Email/Password provider enabled in the Console and the local private server credential installed.

Existing local accounts have password hashes, not recoverable passwords. They cannot be imported into Firebase with the same passwords. We will need a new Firebase sign-up or a password-reset/re-registration flow and an explicit plan to associate old run history.

## After Authentication works

We can decide separately whether the app needs:

- **PostgreSQL** to replace local SQLite for a hosted multi-user backend.
- **Firestore** for selected cloud records, if we intentionally redesign the data layer and access policy.
- **Cloud Storage** for private uploaded datasets, after setting retention, file size/type limits, and a budget plan.
- **Firebase Cloud Messaging** for optional browser push alerts, after HTTPS deployment and user opt-in.
- **Hosting / Cloud Run** when you're ready to publish the PWA and Python backend.

Do not enable these now. Authentication is the first small, testable upgrade. Firebase pricing and plan details: <https://firebase.google.com/docs/projects/billing/firebase-pricing-plans>.
