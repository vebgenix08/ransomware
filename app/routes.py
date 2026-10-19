from flask import Blueprint, render_template
from flask_login import login_required


main = Blueprint("main", __name__)


@main.get("/")
def index():
    return render_template("index.html")


@main.get("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")
