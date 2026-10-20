from flask import Blueprint, current_app, render_template
from flask_login import login_required


main = Blueprint("main", __name__)


@main.get("/manifest.webmanifest")
def manifest():
    response = current_app.send_static_file("manifest.webmanifest")
    response.headers["Content-Type"] = "application/manifest+json"
    response.headers["Cache-Control"] = "no-cache"
    return response


@main.get("/service-worker.js")
def service_worker():
    response = current_app.send_static_file("service-worker.js")
    response.headers["Service-Worker-Allowed"] = "/"
    response.headers["Cache-Control"] = "no-cache"
    return response


@main.get("/offline")
def offline():
    return current_app.send_static_file("offline.html")


@main.get("/")
def index():
    return render_template("index.html")


@main.get("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")
