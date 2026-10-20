# Windows Laptop 1 → Windows Laptop 2

SMTP update: set email credentials in the project-root `.env` on Laptop 2
(see `.env.example`). Both Flask and the receiver load it automatically on startup.
Restart both after editing. No SMTP keys are needed on Laptop 1.

Laptop 1 sends **CSV records only** through SSH/SFTP over your private Wi-Fi.
Laptop 2 validates the checksum, selects the compatible model, records metrics
and an incident when appropriate, attempts configured notifications, and updates
its dashboard automatically. Dataset evaluation never changes local files.

## What is ready

- `scripts/send_dataset.py`: standalone sender; needs Python 3.9+ and OpenSSH
  client, not Flask, NumPy, XGBoost or the model.
- `scripts/receive_dataset.py`: receiver; uses Laptop 2's project environment,
  database, trained model and existing RansomShield account.
- The sender uploads a CSV snapshot, then atomically publishes its checksum
  manifest last. Partial `.part` uploads never trigger analysis.
- The receiver stores a unique transfer/run UUID and returns a JSON receipt over
  SFTP. Re-reading an already processed manifest does not create duplicate runs.
- Received runs are shown as `laptop_transfer` in the owning account's dashboard.

Local automated tests pass. Actual transfer between your physical laptops has
**not** been tested. During inspection, this Laptop 2 had OpenSSH client tools but
no `sshd` service was found. Enabling the server requires Windows administrator
setup; this change does not install services or change your firewall.

## 1. Laptop 2: one-time SSH setup

Connect both laptops to the same private Wi-Fi. Laptop 2 needs the Windows
**OpenSSH Server** optional feature, its `sshd` service running, and an inbound
SSH rule limited to your intended private-network access. Follow Microsoft's
[Windows OpenSSH setup](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse?pivots=windows-11).

Use a Windows SSH account with access to the inbox folder. This Windows account
is separate from your RansomShield email account.

On Laptop 2, find the Wi-Fi **IPv4 Address** and Windows username:

```powershell
ipconfig
whoami
```

Establish key-based SSH access from Laptop 1 using Microsoft's
[Windows SSH key management guide](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement).
The automated sender uses batch mode, so a password prompt is not supported.
Use a key available to SSH (or its agent) and keep private keys on Laptop 1.

Before the first connection, compare the host fingerprint with Laptop 2's
locally displayed fingerprint. For example, on Laptop 2:

```powershell
ssh-keygen -lf C:\ProgramData\ssh\ssh_host_ed25519_key.pub
```

On Laptop 1, connect once, verify the displayed fingerprint, and exit:

```powershell
sftp WINDOWS_USER@LAPTOP2_IP
```

Do not disable host-key verification. The sender uses `StrictHostKeyChecking=yes`.

## 2. Laptop 2: start dashboard and receiver

Open PowerShell in the project root (the folder containing `run.py`). Start the app:

```powershell
.\.venv\Scripts\python.exe run.py
```

Open `http://127.0.0.1:5000`, register/sign in, and open the dashboard. Keep the
web app on localhost; the transfer uses SSH/SFTP rather than an exposed debug
web server.

In a **second PowerShell terminal**, in the same project folder, run:

```powershell
.\.venv\Scripts\python.exe scripts\receive_dataset.py --email YOUR_RANSOMSHIELD_EMAIL
```

Replace the email with the account you just used. The receiver creates and prints
the inbox path under this installation's `instance/inbox` folder. Keep both terminals
open. Configure SMTP/webhook environment variables in **both terminals** before
starting if you want actual notification attempts; otherwise channels are disabled.

## 3. Laptop 1: send a safe dataset

Copy `scripts/send_dataset.py` and `data/mlran/heldout.csv` to Laptop 1. Install
Python 3.9+ and Windows OpenSSH Client if needed. There is no sender ZIP bundle;
the PWA is installed from the browser, while this optional sender script is run
directly when a second device is available.
Open PowerShell in the extracted folder:

```powershell
python send_dataset.py heldout.csv --to WINDOWS_USER@LAPTOP2_IP --inbox "LAPTOP2_INSTANCE_INBOX_PATH" --dataset-name "MLRan held-out samples" --source "Published MLRan dataset; see upstream source in data/mlran/README.md"
```

Replace the Windows username, Wi-Fi IP and inbox path with Laptop 2's values.
The sender waits up to 120 seconds for a result. It prints the run ID, prediction,
risk, evaluation metrics and notification status. Dataset evaluation never quarantines local files.

`heldout.csv` is the published MLRan held-out dataset, not a generated demo fixture. It is analyzed by the separate tabular XGBoost model; the result describes those published records and does not establish endpoint protection performance. Compatible telemetry CSVs use the experimental synthetic-trained TCN + XGBoost model. RanDe-W11 remains unsupported.

## 4. Laptop 2: inspect the result

Stay signed in with the receiver's RansomShield email. Within the dashboard's
next refresh, the transferred run appears with checksum verification, prediction,
accuracy/precision/recall/F1, incident details, notification status, and CSV report.
Uploaded datasets are evaluated as records only. CSV paths are not trusted and
are never used to select local files for quarantine.

## Troubleshooting

- **Host-key verification failed:** verify the host fingerprint directly on
  Laptop 2, then establish the initial `sftp` connection. Do not bypass this check.
- **Permission denied:** check the Windows SSH username/key and inbox permissions.
- **Connection refused/timed out:** check the IP, private Wi-Fi/client isolation,
  OpenSSH Server service and the intended firewall rule.
- **Uploaded, result pending:** keep the receiver running and check its terminal.
  The upload may already be processing; do not immediately resend and create a
  new execution. A finished receipt is saved as `<run-id>.result.json` in the inbox.
- **Failed integrity/schema check:** view the failed run, correct the input, and
  send again; a new invocation creates a new UUID. Missing model features are
  never silently filled in.
- **Receiver interrupted:** a run already marked `running` is not automatically
  replayed, because quarantine/notifications may have partially occurred. Review
  its audit before creating a new transfer. No durable crash recovery is claimed.

The two devices must remain awake and connected during transfer. The dashboard
updates automatically only while its Flask process runs; the receiver must also
remain running to process new uploads.

## No second laptop available

Use **Run included MLRan dataset** on the dashboard to evaluate the published samples without a second device. This does not test SSH or Wi-Fi. Published samples are evaluated with XGBoost; telemetry CSVs use the experimental TCN + XGBoost model.
