# Monitor a Windows VM

The endpoint agent reports relative file names and create, modify, and delete events. It never sends file contents. Its events are stored in PostgreSQL and evaluated against the 30-second burst rules. The dashboard monitor does not need to be running for remote agent events.

## Setup

1. Host RansomShield at an HTTPS address using a reverse proxy such as Caddy or Nginx. Waitress stays on loopback by default; set `APP_HOST=0.0.0.0` only for a controlled LAN lab, then set up HTTPS before using the agent. The agent deliberately refuses plain HTTP because its token would otherwise travel unencrypted.
2. Set `AGENT_API_TOKEN` in the host `.env` or Render Environment settings. Use a long random value and never commit or share it. If your local `.render.env` is the same file you uploaded to Render, the host-side agent script reads it automatically when run from this project folder. Otherwise, set `RANSOMSHIELD_AGENT_TOKEN` in PowerShell to the exact Render token.

   If you create a new token, update it in both Render and the endpoint environment. Do not commit `.env` or send the token in chat.
3. On the VM, install Python 3.10 or newer. Copy the project folder (or just its `scripts` folder and requirements) to the VM, then install the project requirements:

   ```powershell
   py -m pip install -r requirements.txt
   ```

4. In a VM PowerShell window, set the same token and start the agent. Do not copy the full Render environment file to the VM; it contains unrelated database and email secrets. Replace the folder with a dedicated test folder:

   ```powershell
   $env:RANSOMSHIELD_AGENT_TOKEN = 'paste-the-token-here'
   $env:RANSOMSHIELD_AGENT_NAME = 'windows-vm'
   py scripts\endpoint_agent.py --server https://your-host.example --folder C:\RansomShield\watch
   ```

5. Sign in to RansomShield, then create, edit, or delete a harmless `.txt` file inside the watched VM folder. The event should appear in **Recent events** within a few seconds. Stop the agent with Ctrl+C.

## Limits

This is event forwarding for research and testing. It does not identify which process changed a file, inspect file contents, run the SILRAD model live, or prove ransomware detection. A trusted host with HTTPS is required. Use only a dedicated test folder and harmless files.

## Hosted database

For a hosted deployment, set `DATABASE_URL` to the PostgreSQL connection string from your database provider. Install dependencies from `requirements.txt`, run migrations with `flask --app run db upgrade` (or let the current app startup migration run), and configure provider backups. Keep SQLite for local use. PostgreSQL support alone does not create backups, a public HTTPS deployment, or recovery procedures.
