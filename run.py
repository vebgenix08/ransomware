import os
from pathlib import Path

from dotenv import dotenv_values
from waitress import serve

from app import create_app


ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT / ".env"
FILE_ENV = dotenv_values(ENV_FILE, interpolate=False)


def setting(name, default=""):
    return os.environ.get(name, FILE_ENV.get(name, default))


app = create_app()


if __name__ == "__main__":
    debug = setting("FLASK_DEBUG", "false").lower() == "true"
    host = "127.0.0.1" if debug else setting("APP_HOST", "127.0.0.1")
    port = 5000 if debug else int(setting("PORT", "5000"))
    display_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    print(f"RansomShield is starting at http://{display_host}:{port}", flush=True)
    if debug:
        # Development only. Never expose this server outside localhost.
        # Watch .env too, so environment changes reload the app and are applied.
        app.run(
            debug=True,
            use_reloader=True,
            reloader_type="stat",
            extra_files=[str(ENV_FILE)],
            host=host,
            port=port,
        )
    else:
        serve(app, host=host, port=port)
