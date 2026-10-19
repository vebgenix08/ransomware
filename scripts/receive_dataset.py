"""Laptop 2: watch the SFTP inbox and automatically analyze safe CSV records."""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import create_app
from app.models import User
from app.transfer import receive_one, receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", required=True, help="Existing RansomShield account that will own received runs")
    parser.add_argument("--inbox", type=Path, default=Path(__file__).resolve().parents[1]/"instance/inbox")
    parser.add_argument("--once", action="store_true", help="Process current uploads and exit")
    args = parser.parse_args()
    app = create_app()
    args.inbox.mkdir(parents=True, exist_ok=True)
    inbox = args.inbox.resolve()
    with app.app_context():
        user = User.query.filter_by(email=args.email.strip().lower()).first()
        if user is None:
            parser.error("Create/sign in to this RansomShield account on Laptop 2 first")
        owner_id = user.id
    print(f"Laptop 2 receiver ready. SFTP inbox: {inbox.as_posix()}", flush=True)
    print("Leave this terminal open. Ctrl+C stops the receiver. Dashboard: http://127.0.0.1:5000/dashboard", flush=True)
    seen = set()
    try:
        while True:
            for manifest in sorted(inbox.glob("*.ready.json")):
                if manifest.name in seen:
                    continue
                try:
                    with app.app_context():
                        run = receive_one(app, inbox, owner_id, manifest)
                        if run is not None:
                            print(json.dumps(receipt(run)), flush=True)
                            seen.add(manifest.name)
                except (OSError, ValueError) as exc:
                    print(f"Upload rejected ({manifest.name}): {exc}", file=sys.stderr, flush=True)
                    seen.add(manifest.name)
            if args.once:
                break
            time.sleep(2)
    except KeyboardInterrupt:
        print("Receiver stopped.")


if __name__ == "__main__":
    main()
