"""Send safe filesystem activity summaries from a Windows endpoint to RansomShield."""
import argparse
import json
import os
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen
from uuid import uuid4

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class AgentHandler(FileSystemEventHandler):
    def __init__(self, root: Path, endpoint: str, token: str, name: str):
        self.root = root.resolve()
        self.endpoint = endpoint.rstrip("/") + "/api/agent/events"
        self.token = token
        self.name = name

    def _send(self, operation, path):
        try:
            relative = Path(path).resolve().relative_to(self.root).as_posix()
        except (ValueError, OSError):
            return
        payload = json.dumps({"event_id": str(uuid4()), "agent": self.name,
                              "operation": operation, "path": relative}).encode()
        request = Request(self.endpoint, data=payload, method="POST", headers={
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "User-Agent": "RansomShield-Endpoint-Agent/1.0",
        })
        for attempt in range(3):
            try:
                with urlopen(request, timeout=10) as response:
                    if response.status not in (200, 202):
                        print(f"Server rejected event: HTTP {response.status}", file=sys.stderr)
                    return
            except (URLError, TimeoutError) as exc:
                if attempt == 2:
                    print(f"Could not send event ({type(exc).__name__}); event was not queued.", file=sys.stderr)
                else:
                    time.sleep(1 + attempt)

    def on_created(self, event):
        if not event.is_directory:
            self._send("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._send("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._send("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._send("deleted", event.src_path)
            self._send("created", event.dest_path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, help="RansomShield HTTPS origin, e.g. https://shield.example.com")
    parser.add_argument("--folder", required=True, type=Path, help="Folder to monitor on this endpoint")
    parser.add_argument("--name", default=os.environ.get("RANSOMSHIELD_AGENT_NAME", "windows-vm"))
    args = parser.parse_args()
    token = os.environ.get("RANSOMSHIELD_AGENT_TOKEN", "")
    if not token:
        parser.error("Set RANSHIELD_AGENT_TOKEN in this terminal before starting the agent.")
    if not args.server.lower().startswith("https://"):
        parser.error("The endpoint requires HTTPS so the agent token is encrypted in transit.")
    root = args.folder.resolve()
    if not root.is_dir():
        parser.error(f"Folder does not exist: {root}")
    handler = AgentHandler(root, args.server, token, args.name)
    observer = Observer()
    observer.schedule(handler, str(root), recursive=True)
    observer.start()
    print(f"Monitoring {root} and sending event summaries to {args.server}. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
