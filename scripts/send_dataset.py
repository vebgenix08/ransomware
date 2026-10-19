"""Laptop 1: transfer CSV over verified SSH/SFTP, then retrieve Laptop 2's result.

Uses only Python's standard library and the OpenSSH sftp client. No model required.
"""
import argparse
import hashlib
import json
import re
import subprocess
import tempfile
import time
from pathlib import Path
from uuid import uuid4

MAX_CSV_BYTES = 5 * 1024 * 1024


def sftp_quote(value):
    value = str(value).replace("\\", "/")
    if any(char in value for char in ('"', '\n', '\r', '\x00', '*', '?', '[', ']')):
        raise ValueError("SFTP paths must not contain quotes, newlines or wildcard characters")
    return '"' + value + '"'


def destination(value):
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*@[A-Za-z0-9][A-Za-z0-9.-]*", value):
        raise argparse.ArgumentTypeError("Use SSH-user@Laptop2-IP or SSH-user@hostname")
    return value


def transfer(command, batch):
    return subprocess.run(command, input=batch, text=True, capture_output=True, timeout=60, check=False)


def send(csv_path, target, remote_inbox, dataset_name, source, wait_seconds=120, port=22):
    destination(target)
    csv_path = Path(csv_path)
    if csv_path.suffix.lower() != ".csv" or not csv_path.is_file():
        raise ValueError("Choose a safe .csv dataset")
    with csv_path.open("rb") as stream:
        payload = stream.read(MAX_CSV_BYTES + 1)
    if not payload or len(payload) > MAX_CSV_BYTES:
        raise ValueError("CSV must contain between 1 byte and 5 MB")
    transfer_id = str(uuid4())
    inbox = remote_inbox.replace("\\", "/").rstrip("/")
    sftp_quote(inbox)
    if not inbox or ".." in inbox.split("/"):
        raise ValueError("Use the exact receiver inbox path without parent traversal")
    manifest = {"version": 1, "sha256": hashlib.sha256(payload).hexdigest(),
                "size_bytes": len(payload), "dataset_name": dataset_name[:200], "source": source[:500]}
    command = ["sftp", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oConnectTimeout=10",
               "-P", str(port), "-b", "-", target]
    with tempfile.TemporaryDirectory(prefix="ransomshield-send-") as temporary:
        root = Path(temporary)
        data_path, manifest_path = root/"dataset.csv", root/"manifest.json"
        data_path.write_bytes(payload)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        remote_csv = f"{inbox}/{transfer_id}.csv"
        remote_ready = f"{inbox}/{transfer_id}.ready.json"
        batch = "\n".join([
            f"put {sftp_quote(data_path)} {sftp_quote(remote_csv + '.part')}",
            f"rename {sftp_quote(remote_csv + '.part')} {sftp_quote(remote_csv)}",
            f"put {sftp_quote(manifest_path)} {sftp_quote(remote_ready + '.part')}",
            f"rename {sftp_quote(remote_ready + '.part')} {sftp_quote(remote_ready)}", "bye", ""])
        result = transfer(command, batch)
        if result.returncode:
            raise RuntimeError("SFTP upload failed. Verify server, SSH key, trusted host fingerprint and inbox permissions. " + result.stderr.strip())
        print(json.dumps({"transfer_id": transfer_id, "sha256": manifest["sha256"], "status": "uploaded"}), flush=True)
        deadline = time.monotonic() + wait_seconds
        result_path = root/"result.json"
        while time.monotonic() < deadline:
            result = transfer(command, f"get {sftp_quote(inbox + '/' + transfer_id + '.result.json')} {sftp_quote(result_path)}\nbye\n")
            if result.returncode == 0:
                reply = json.loads(result_path.read_text(encoding="utf-8"))
                if reply.get("transfer_id") != transfer_id:
                    raise ValueError("Receiver returned the wrong transfer ID")
                if reply.get("status") == "completed" and reply.get("dataset_sha256") != manifest["sha256"]:
                    raise ValueError("Receiver analyzed different CSV bytes")
                return reply
            time.sleep(2)
        return {"transfer_id": transfer_id, "status": "uploaded_result_pending",
                "message": "Upload finished. Check Laptop 2 receiver/dashboard; do not resend just because the result is pending."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path)
    parser.add_argument("--to", required=True, type=destination)
    parser.add_argument("--inbox", required=True, help="Exact SFTP inbox path printed on Laptop 2")
    parser.add_argument("--dataset-name", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--wait", type=int, default=120, help="Seconds to wait for analysis result; 0 uploads only")
    parser.add_argument("--port", type=int, default=22)
    args = parser.parse_args()
    if not 0 <= args.wait <= 3600 or not 1 <= args.port <= 65535:
        parser.error("Wait must be 0..3600 seconds and port 1..65535")
    try:
        result = send(args.csv, args.to, args.inbox, args.dataset_name, args.source, args.wait, args.port)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        parser.exit(1, f"{exc}\n")
    print(json.dumps(result, indent=2))
    if result.get("status") == "failed":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
