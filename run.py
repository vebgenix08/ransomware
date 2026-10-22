import os

from waitress import serve

from app import create_app


app = create_app()


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    host = "127.0.0.1" if debug else os.environ.get("APP_HOST", "127.0.0.1")
    port = 5000 if debug else int(os.environ.get("PORT", "5000"))
    display_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    print(f"RansomShield is starting at http://{display_host}:{port}", flush=True)
    if debug:
        # Development only. Never expose this server outside localhost.
        app.run(debug=True, host=host, port=port)
    else:
        serve(app, host=host, port=port)
