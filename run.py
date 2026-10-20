import os

from waitress import serve

from app import create_app


app = create_app()


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    if debug:
        # Development only. Never expose this server outside localhost.
        app.run(debug=True, host="127.0.0.1", port=5000)
    else:
        serve(app, host=os.environ.get("APP_HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")))
