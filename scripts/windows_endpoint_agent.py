"""Watch one Windows folder and report file metadata events to RansomShield."""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import getpass
import json
import os
import re
import shutil
import socket
import sqlite3
import sys
import threading
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from uuid import UUID, uuid4

try:
    from watchdog.events import FileSystemEvent, FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError as exc:  # pragma: no cover - exercised by the CLI on a clean machine
    raise SystemExit("Install the agent dependency first: py -3 -m pip install watchdog") from exc


REQUEST_TIMEOUT_SECONDS = 8
MAX_RETRY_SECONDS = 60
DEBOUNCE_SECONDS = 0.4


def endpoint_url(server_url: str, allow_insecure_http: bool = False) -> str:
    """Validate the server URL and return the endpoint-events URL."""
    parsed = urlparse(server_url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a server URL such as https://your-app.onrender.com")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("The server URL must not contain credentials, a query, or a fragment.")
    loopback = parsed.hostname.lower() in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme == "http" and not (loopback or allow_insecure_http):
        raise ValueError("Use HTTPS for remote servers so the agent token is encrypted in transit.")
    return server_url.strip().rstrip("/") + "/api/agent/events"


def safe_agent_name(value: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip(".-")[:64]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name):
        raise ValueError("Agent name must contain letters, numbers, dots, dashes, or underscores.")
    return name


class PendingEventStore:
    """Small durable outbox: accepted events are removed; offline events survive restart."""

    def __init__(self, path: Path):
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with closing(self._connect()) as connection, connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS pending_events ("
                "sequence INTEGER PRIMARY KEY AUTOINCREMENT, "
                "event_id TEXT NOT NULL UNIQUE, payload TEXT NOT NULL)"
            )
            connection.execute("CREATE TABLE IF NOT EXISTS agent_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            connection.execute("CREATE TABLE IF NOT EXISTS command_receipts (command_id TEXT PRIMARY KEY, status TEXT NOT NULL, result TEXT NOT NULL)")

    def _connect(self):
        return sqlite3.connect(self.path, timeout=5)

    def enqueue(self, payload: dict) -> None:
        with self._lock, closing(self._connect()) as connection, connection:
            connection.execute(
                "INSERT OR IGNORE INTO pending_events (event_id, payload) VALUES (?, ?)",
                (payload["event_id"], json.dumps(payload, separators=(",", ":"))),
            )

    def first(self) -> dict | None:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT payload FROM pending_events ORDER BY sequence LIMIT 1"
            ).fetchone()
        return json.loads(row[0]) if row else None

    def acknowledge(self, event_id: str) -> None:
        with self._lock, closing(self._connect()) as connection, connection:
            connection.execute("DELETE FROM pending_events WHERE event_id = ?", (event_id,))

    def count(self) -> int:
        with self._lock, closing(self._connect()) as connection:
            return int(connection.execute("SELECT COUNT(*) FROM pending_events").fetchone()[0])

    def device_id(self) -> str:
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute("SELECT value FROM agent_state WHERE key = 'device_id'").fetchone()
            if row:
                return str(UUID(row[0]))
            value = str(uuid4())
            with connection:
                connection.execute("INSERT INTO agent_state (key, value) VALUES ('device_id', ?)", (value,))
            return value

    def remember_command(self, command_id: str, status: str, result: dict) -> None:
        with self._lock, closing(self._connect()) as connection, connection:
            connection.execute(
                "INSERT OR REPLACE INTO command_receipts (command_id, status, result) VALUES (?, ?, ?)",
                (command_id, status, json.dumps(result, separators=(",", ":"))),
            )

    def first_command_receipt(self):
        with self._lock, closing(self._connect()) as connection:
            row = connection.execute("SELECT command_id, status, result FROM command_receipts ORDER BY rowid LIMIT 1").fetchone()
        return (row[0], row[1], json.loads(row[2])) if row else None

    def acknowledge_command_receipt(self, command_id: str) -> None:
        with self._lock, closing(self._connect()) as connection, connection:
            connection.execute("DELETE FROM command_receipts WHERE command_id = ?", (command_id,))


def default_queue_path() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if base:
        state_root = Path(base)
    else:
        state_root = Path.home() / ".local" / "share"
    return state_root / "RansomShield" / "agent-events.sqlite3"


def default_quarantine_root() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    state_root = Path(base) if base else Path.home() / ".local" / "share"
    return state_root / "RansomShield" / "quarantine"


class AgentEventHandler(FileSystemEventHandler):
    """Translate Watchdog file events into bounded, relative-path API events."""

    def __init__(self, root: Path, agent_name: str, store: PendingEventStore,
                 device_id: str = "", folder_name: str = ""):
        super().__init__()
        self.root = root.resolve()
        self.agent_name = agent_name
        self.device_id = device_id
        self.folder_name = folder_name
        self.store = store
        self._last_seen: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def _record(self, operation: str, raw_path: str) -> None:
        try:
            path = Path(raw_path).resolve(strict=False).relative_to(self.root).as_posix()
        except (OSError, ValueError):
            return
        parts = path.split("/")
        if (not path or len(path) > 400 or any(part in {"", ".", ".."} for part in parts)
                or any(ord(char) < 32 or ord(char) == 127 for char in path)):
            return

        now = time.monotonic()
        key = (operation, path.casefold())
        with self._lock:
            previous = self._last_seen.get(key)
            if previous is not None and now - previous < DEBOUNCE_SECONDS:
                return
            self._last_seen[key] = now
            if len(self._last_seen) > 4096:
                self._last_seen = {
                    seen_key: seen_time for seen_key, seen_time in self._last_seen.items()
                    if now - seen_time < DEBOUNCE_SECONDS
                }

        self.store.enqueue({
            "event_id": str(uuid4()),
            "agent": self.agent_name,
            "device_id": self.device_id,
            "folder_name": self.folder_name,
            "agent_version": "1.0.0",
            "operation": operation,
            "path": path,
            "observed_at": datetime.now(timezone.utc).isoformat(),
        })
        print(f"Queued {operation}: {path}", flush=True)

    def _file_event(self, operation: str, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._record(operation, event.src_path)

    def on_created(self, event: FileSystemEvent) -> None:
        self._file_event("created", event)

    def on_modified(self, event: FileSystemEvent) -> None:
        self._file_event("modified", event)

    def on_deleted(self, event: FileSystemEvent) -> None:
        self._file_event("deleted", event)

    def on_moved(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._record("deleted", event.src_path)
        self._record("created", event.dest_path)


def post_event(url: str, token: str, payload: dict) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        if response.status != 202:
            raise RuntimeError(f"Server returned unexpected HTTP status {response.status}.")
        result = json.loads(response.read().decode("utf-8"))
        if result.get("ok") is not True:
            raise RuntimeError("Server did not accept the event.")


def check_server(url: str, token: str) -> None:
    health_url = url.removesuffix("/api/agent/events") + "/api/agent/health"
    request = Request(health_url, headers={"Authorization": f"Bearer {token}"}, method="GET")
    with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        result = json.loads(response.read().decode("utf-8"))
        if response.status != 200 or result.get("ok") is not True:
            raise RuntimeError("Server did not confirm endpoint-agent readiness.")


def post_json(url: str, token: str, payload: dict, expected_statuses=(200,)) -> dict:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = Request(url, data=body,
                      headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                      method="POST")
    with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        result = json.loads(response.read().decode("utf-8"))
        if response.status not in expected_statuses or result.get("ok") is not True:
            raise RuntimeError("Server rejected the endpoint request.")
        return result


def safe_relative_path(raw: str) -> tuple[str, ...]:
    value = str(raw or "").replace("\\", "/")
    parts = tuple(value.split("/"))
    reserved = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$", re.IGNORECASE)
    invalid_windows_name = any(
        any(char in '<>:"|?*' for char in part) or part.endswith((" ", ".")) or reserved.fullmatch(part)
        for part in parts
    )
    if (not value or len(value) > 400 or value.startswith("/") or invalid_windows_name
            or any(part in {"", ".", ".."} or any(ord(char) < 32 for char in part) for part in parts)):
        raise ValueError("The requested path is not a safe relative file path.")
    return parts


def _assert_no_reparse_path(root: Path, path: Path, allow_missing_leaf: bool = False) -> Path:
    root = Path(root)
    if root.exists() or root.is_symlink():
        root_info = root.lstat()
        if root.is_symlink() or getattr(root_info, "st_file_attributes", 0) & 0x400:
            raise ValueError("The allowed folder cannot be a link or Windows reparse point.")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("The allowed path must be a directory.")
    candidate = root.joinpath(*path.parts) if not path.is_absolute() else path
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("The requested path escapes its allowed folder.") from exc
    if not relative.parts:
        raise ValueError("A folder path is required.")
    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        if not current.exists() and not current.is_symlink():
            if allow_missing_leaf and index == len(relative.parts) - 1:
                break
            raise FileNotFoundError("The requested file no longer exists.")
        info = current.lstat()
        if current.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Links and Windows reparse points cannot be quarantined or restored.")
    resolved = current.resolve(strict=not allow_missing_leaf)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("The requested path escapes its allowed folder.") from exc
    return current


def _hash_file(path: Path) -> tuple[str, int]:
    import hashlib
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def execute_endpoint_command(command: dict, root: Path, quarantine_root: Path, device_id: str) -> dict:
    """Run only explicit quarantine/restore requests within the selected root."""
    command_id = str(UUID(str(command.get("command_id", ""))))
    action = command.get("action")
    payload = command.get("payload") or {}
    if not isinstance(payload, dict):
        raise ValueError("Command payload is invalid.")
    root = root.resolve(strict=True)
    device_quarantine = quarantine_root / device_id
    if action == "quarantine":
        parts = safe_relative_path(payload.get("path", ""))
        source = root.joinpath(*parts)
        destination_root = device_quarantine / command_id
        destination = destination_root.joinpath(*parts)
        quarantine_root.mkdir(parents=True, exist_ok=True)
        _assert_no_reparse_path(quarantine_root, Path(device_id), allow_missing_leaf=True)
        destination_root.mkdir(parents=True, exist_ok=True)
        if (destination.is_file() and not destination.is_symlink()
                and not source.exists() and not source.is_symlink()):
            digest, size = _hash_file(destination)
            return {"status": "quarantined", "path": "/".join(parts),
                    "quarantine_key": f"{command_id}/" + "/".join(parts), "sha256": digest, "size_bytes": size}
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("A file already exists at the local quarantine destination.")
        source = _assert_no_reparse_path(root, Path(*parts))
        if not source.is_file():
            raise ValueError("Only regular files can be quarantined.")
        digest, size = _hash_file(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        _assert_no_reparse_path(quarantine_root, Path(device_id) / command_id / Path(*parts), allow_missing_leaf=True)
        try:
            os.replace(source, destination)
        except OSError:
            # Cross-volume moves use a verified temporary copy before deleting the source.
            temporary = destination.with_name(destination.name + ".ransomshield-partial")
            if temporary.exists():
                temporary.unlink()
            with source.open("rb") as src, temporary.open("xb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
                dst.flush()
                os.fsync(dst.fileno())
            if _hash_file(temporary) != (digest, size):
                temporary.unlink(missing_ok=True)
                raise OSError("Quarantine copy verification failed; original file was kept.")
            os.replace(temporary, destination)
            source.unlink()
        digest, size = _hash_file(destination)
        return {"status": "quarantined", "path": "/".join(parts),
                "quarantine_key": f"{command_id}/" + "/".join(parts), "sha256": digest, "size_bytes": size}
    if action == "restore":
        key = str(payload.get("quarantine_key", ""))
        key_parts = safe_relative_path(key)
        original_parts = safe_relative_path(payload.get("path", ""))
        if key_parts[0] != str(UUID(str(payload.get("quarantine_command_id", "")))):
            raise ValueError("Restore source does not match its quarantine record.")
        destination = root.joinpath(*original_parts)
        source_candidate = device_quarantine.joinpath(*key_parts)
        if (not source_candidate.exists() and not source_candidate.is_symlink()
                and destination.is_file() and not destination.is_symlink()):
            digest, size = _hash_file(destination)
            expected_digest = str(payload.get("expected_sha256", ""))
            if expected_digest and digest != expected_digest:
                raise ValueError("The restored file hash does not match its quarantine record.")
            return {"status": "restored", "path": "/".join(original_parts), "sha256": digest, "size_bytes": size}
        source = _assert_no_reparse_path(device_quarantine, Path(*key_parts))
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("A file already exists at the original location; it was not overwritten.")
        parent = root
        for part in original_parts[:-1]:
            parent = parent / part
            if parent.exists() or parent.is_symlink():
                info = parent.lstat()
                if parent.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400 or not parent.is_dir():
                    raise ValueError("The restore folder contains a link or is not a directory.")
            else:
                parent.mkdir()
        _assert_no_reparse_path(root, Path(*original_parts), allow_missing_leaf=True)
        destination.parent.mkdir(parents=True, exist_ok=True)
        digest, size = _hash_file(source)
        expected_digest = str(payload.get("expected_sha256", ""))
        expected_size = payload.get("expected_size_bytes")
        if expected_digest and digest != expected_digest:
            raise ValueError("The quarantined file was changed; restore was refused.")
        if expected_size is not None and (not isinstance(expected_size, int) or size != expected_size):
            raise ValueError("The quarantined file size does not match its record; restore was refused.")
        try:
            os.replace(source, destination)
        except OSError:
            temporary = destination.with_name(destination.name + ".ransomshield-partial")
            if temporary.exists():
                temporary.unlink()
            with source.open("rb") as src, temporary.open("xb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
                dst.flush()
                os.fsync(dst.fileno())
            if _hash_file(temporary) != (digest, size):
                temporary.unlink(missing_ok=True)
                raise OSError("Restore copy verification failed; quarantined file was kept.")
            os.replace(temporary, destination)
            source.unlink()
        return {"status": "restored", "path": "/".join(original_parts), "sha256": digest, "size_bytes": size}
    raise ValueError("Unsupported endpoint command.")


def heartbeat_loop(base_url: str, token: str, device_id: str, agent_name: str,
                   folder_name: str, stop: threading.Event) -> None:
    url = base_url.rstrip("/") + "/api/agent/heartbeat"
    while not stop.is_set():
        try:
            post_json(url, token, {"device_id": device_id, "agent": agent_name,
                                   "folder_name": folder_name, "agent_version": "1.0.0"})
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, RuntimeError) as exc:
            print(f"Device check-in pending ({exc})", file=sys.stderr, flush=True)
        stop.wait(30)


def command_loop(base_url: str, token: str, device_id: str, root: Path,
                 quarantine_root: Path, store: PendingEventStore, stop: threading.Event) -> None:
    commands_url = base_url.rstrip("/") + "/api/agent/commands"
    retry_delay = 1
    while not stop.is_set():
        try:
            receipt = store.first_command_receipt()
            if receipt:
                command_id, status, result = receipt
                post_json(f"{base_url.rstrip('/')}/api/agent/commands/{command_id}/result", token,
                          {"device_id": device_id, "status": status, "result": result})
                store.acknowledge_command_receipt(command_id)
            request = Request(f"{commands_url}?device_id={device_id}",
                               headers={"Authorization": f"Bearer {token}"}, method="GET")
            with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                body = json.loads(response.read().decode("utf-8"))
            for command in body.get("commands", []):
                command_id = str(UUID(str(command.get("command_id", ""))))
                try:
                    result = execute_endpoint_command(command, root, quarantine_root, device_id)
                    status = "completed"
                except (OSError, ValueError, TypeError) as exc:
                    result = {"status": "failed", "message": str(exc)[:500]}
                    status = "failed"
                store.remember_command(command_id, status, result)
            retry_delay = 1
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, RuntimeError) as exc:
            print(f"Endpoint command check pending; retrying in {retry_delay}s ({exc})", file=sys.stderr, flush=True)
            stop.wait(retry_delay)
            retry_delay = min(retry_delay * 2, MAX_RETRY_SECONDS)
            continue
        stop.wait(5)


def sender_loop(url: str, token: str, store: PendingEventStore, stop: threading.Event) -> None:
    retry_delay = 1
    while not stop.is_set():
        payload = store.first()
        if payload is None:
            stop.wait(0.25)
            continue
        try:
            post_event(url, token, payload)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, RuntimeError) as exc:
            print(f"Send pending; will retry in {retry_delay}s ({exc})", file=sys.stderr, flush=True)
            stop.wait(retry_delay)
            retry_delay = min(retry_delay * 2, MAX_RETRY_SECONDS)
            continue
        store.acknowledge(payload["event_id"])
        retry_delay = 1


def prompt_or(value: str | None, prompt: str) -> str:
    return value.strip() if value and value.strip() else input(prompt).strip()


def run_agent(args: argparse.Namespace) -> int:
    server = prompt_or(args.server, "RansomShield server URL (for example https://your-app.onrender.com): ")
    url = endpoint_url(server, args.allow_insecure_http)
    raw_root = prompt_or(str(args.folder) if args.folder else None, "Folder to monitor: ").strip('"')
    root = Path(raw_root).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("The selected folder does not exist or is not a directory.")

    default_name = f"{socket.gethostname()}-{root.name}"
    raw_name = prompt_or(args.agent, f"Device and folder label [{default_name}]: ") or default_name
    agent_name = safe_agent_name(raw_name)
    token = os.environ.get("RANSHIELD_AGENT_TOKEN", "").strip()
    if not token:
        token = getpass.getpass("Endpoint-agent token (input hidden): ").strip()
    if not token:
        raise ValueError("The endpoint-agent token cannot be empty.")

    queue_path = (args.queue_path or default_queue_path()).expanduser().resolve()
    try:
        queue_path.relative_to(root)
    except ValueError:
        pass
    else:
        raise ValueError("The private event queue must be outside the folder being monitored.")
    quarantine_root = default_quarantine_root().expanduser().resolve()
    if quarantine_root == root or root in quarantine_root.parents or quarantine_root in root.parents:
        raise ValueError("Local quarantine must be separate from the selected folder.")
    store = PendingEventStore(queue_path)
    device_id = store.device_id()
    handler = AgentEventHandler(root, agent_name, store, device_id, root.name)
    observer = Observer()
    observer.schedule(handler, str(root), recursive=True)
    stop = threading.Event()
    worker = threading.Thread(target=sender_loop, args=(url, token, store, stop), daemon=True)
    base_url = server.rstrip("/")
    heartbeat_worker = threading.Thread(target=heartbeat_loop,
                                        args=(base_url, token, device_id, agent_name, root.name, stop), daemon=True)
    command_worker = threading.Thread(target=command_loop,
                                      args=(base_url, token, device_id, root, quarantine_root, store, stop), daemon=True)

    check_server(url, token)
    post_json(base_url + "/api/agent/heartbeat", token,
              {"device_id": device_id, "agent": agent_name, "folder_name": root.name,
               "agent_version": "1.0.0"})
    observer.start()
    worker.start()
    heartbeat_worker.start()
    command_worker.start()
    print("RansomShield endpoint agent is monitoring file names and actions only.")
    print(f"Device/folder label: {agent_name}")
    print(f"Folder: {root}")
    print(f"Server: {server.rstrip('/')}")
    print("Server connection and agent account verified.")
    print(f"Pending events waiting to send: {store.count()}")
    print("The server receives file paths and actions, never file contents.")
    print(f"Local quarantine folder: {quarantine_root / device_id}")
    print("Keep this window open for monitoring and approved quarantine/restore requests. Press Ctrl+C to stop.", flush=True)
    try:
        while observer.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nStopping endpoint agent...", flush=True)
    finally:
        observer.stop()
        observer.join(timeout=5)
        stop.set()
        worker.join(timeout=REQUEST_TIMEOUT_SECONDS + 1)
        heartbeat_worker.join(timeout=REQUEST_TIMEOUT_SECONDS + 1)
        command_worker.join(timeout=REQUEST_TIMEOUT_SECONDS + 1)
    pending = store.count()
    if pending:
        print(f"Stopped with {pending} unsent event(s) saved locally for the next run.")
    else:
        print("Stopped. All queued events were accepted by the server.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", help="RansomShield base URL; prompted if omitted")
    parser.add_argument("--folder", type=Path, help="Folder to monitor; prompted if omitted")
    parser.add_argument("--agent", help="Device/folder label; defaults to computer-folder name")
    parser.add_argument("--queue-path", type=Path, help=argparse.SUPPRESS)
    parser.add_argument(
        "--allow-insecure-http", action="store_true",
        help="Allow an unencrypted HTTP URL for a trusted private-network test only.",
    )
    args = parser.parse_args()
    try:
        return run_agent(args)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Agent could not start: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
