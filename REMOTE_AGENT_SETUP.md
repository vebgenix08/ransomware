# Monitor a Windows VM

The endpoint agent reports file names and create, modify, and delete events. It never sends file contents. Its events enter the same 30-second burst rules as local folder activity. The dashboard monitor must be running to evaluate those events.

## Setup

1. Host RansomShield at an HTTPS address using a reverse proxy such as Caddy or Nginx. Waitress stays on loopback by default; set `APP_HOST=0.0.0.0` only for a controlled LAN lab, then set up HTTPS before using the agent. The agent deliberately refuses plain HTTP because its token would otherwise travel unencrypted.
2. Create a long random token on the host and set `AGENT_API_TOKEN` in the host `.env`. Example generation command:

   ```powershell
   .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

   Copy the generated value to the host `.env` and restart RansomShield. Do not commit `.env` or send the token in chat.
3. On the VM, install Python 3.10 or newer. Copy the project folder (or just its `scripts` folder and requirements) to the VM, then install the project requirements:

   ```powershell
   py -m pip install -r requirements.txt
   ```

4. In a VM PowerShell window, set the same token and start the agent. Replace the URL and folder with your actual HTTPS host and the folder you want watched:

   ```powershell
   $env:RANSOMSHIELD_AGENT_TOKEN = 'paste-the-token-here'
   $env:RANSOMSHIELD_AGENT_NAME = 'windows-vm'
   py scripts\endpoint_agent.py --server https://your-host.example --folder C:\RansomShield\watch
   ```

5. Sign in to RansomShield, start the dashboard monitor, then create, edit, or delete a harmless `.txt` file inside the watched VM folder. The event should appear in **Recent events**. Stop the agent with Ctrl+C.

## Limits

This is event forwarding for research and testing. It does not identify which process changed a file, inspect file contents, run the SILRAD model live, or prove ransomware detection. A trusted host with HTTPS is required. Use only a dedicated test folder and harmless files.

## Hosted database

For a hosted deployment, set `DATABASE_URL` to the PostgreSQL connection string from your database provider. Install dependencies from `requirements.txt`, run migrations with `flask --app run db upgrade` (or let the current app startup migration run), and configure provider backups. Keep SQLite for local use. PostgreSQL support alone does not create backups, a public HTTPS deployment, or recovery procedures.
