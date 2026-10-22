# Windows endpoint agent

The endpoint agent watches one selected folder on a Windows computer and sends file action, relative path, device/folder label, and event time to RansomShield. It does not send file contents. Keep its terminal window open while monitoring.

You can request remote quarantine from an open endpoint alert. RansomShield asks for confirmation, then queues the command for that device. The agent moves the file into `%LOCALAPPDATA%\RansomShield\quarantine\<device-id>` on the same computer and reports its hash and status. Restore is also a confirmed command. Existing files are never overwritten. The agent must be online to receive commands.

## 1. Configure the RansomShield server

The server must be reachable from the Windows computer. Use the HTTPS address of the deployed app, or a trusted HTTPS address on your network.

On the server, configure these environment values:

```dotenv
AGENT_API_TOKEN=replace-with-a-long-random-secret
AGENT_OWNER_EMAIL=the-email-of-an-existing-ransomshield-account
```

Generate the token with:

```powershell
py -3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

For a local app, add the values to the project-root `.env`. For Render, add them in the service's **Environment** settings. `AGENT_OWNER_EMAIL` must exactly match an account that has already been created in RansomShield. Restart the app after changing these values. Never commit or send the token in a chat.

## 2. Prepare the Windows computer

Install Python 3.10 or newer and Git if needed. Clone or update the RansomShield repository, then open Command Prompt in the project folder:

```cmd
git clone https://github.com/vebgenix08/ransomware.git
cd ransomware
py -3 -m pip install -r scripts\requirements-agent.txt
```

If the repository is already on this computer, use `git pull origin main` instead of cloning it again. If the project virtual environment already has the app requirements installed, the agent batch file uses that environment and you can skip the separate `watchdog` install.

## 3. Start monitoring

Run:

```cmd
scripts\windows_endpoint_agent.bat
```

Enter the server URL, the folder to monitor, and a short device/folder label when prompted. Paste the same `AGENT_API_TOKEN` that is configured on the server; the token is entered invisibly. The agent checks the server and account configuration without creating sample events. Keep the window open. Press **Ctrl+C** to stop.

The agent keeps unsent events in `%LOCALAPPDATA%\RansomShield\agent-events.sqlite3` and retries them after network access returns. The stored event time is preserved so old queued events do not count as a new burst when they are later delivered.

## 4. Check it

1. Sign in to RansomShield and open **Monitor files** or **Recent activity**.
2. On the monitored Windows computer, create a text file inside the selected folder, then edit it.
3. Confirm the activity appears with the device/folder label and a path relative to the selected folder. Check **Devices** for online status and last check-in.
4. Delete only that disposable test file if you want to check deletion reporting.
5. To test quarantine, create a disposable file, trigger an endpoint alert using the configured limits, and choose **Quarantine on device** beside that file. Confirm the displayed source and destination. Start the agent first; then review the result in **Email & history → Files quarantined on Windows devices**. Use **Restore on device** to send it back.

Alerts use the saved live thresholds and cooldown. A single create or edit may appear in activity without creating an alert. The agent sends metadata only; it does not send file contents.

## Security and limits

- Use HTTPS for remote servers. Plain HTTP is allowed only for loopback URLs by default.
- For a trusted private-network test only, add `--allow-insecure-http` after the batch file command. This sends the token without transport encryption; do not use it over the public internet.
- This version uses the server's shared `AGENT_API_TOKEN` and `AGENT_OWNER_EMAIL`. Anyone who obtains that token can report events as an agent, so keep it private and rotate it if exposed.
- The agent monitors and receives commands only while its terminal is running. It is not a Windows service and does not start automatically when the computer boots.
- Quarantine data stays on that endpoint. The server stores command status, relative path, size, and SHA-256; it never receives file content.
- Agents use the shared `AGENT_API_TOKEN` for check-ins, events, and commands. A stolen token can submit events and fetch commands, so protect it, use HTTPS, and rotate it if exposed.
- This is a research prototype. Keep automatic quarantine off for endpoint devices; the endpoint feature is manual and requires explicit confirmation. Test only with disposable files.

