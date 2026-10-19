from urllib.parse import urljoin, urlparse
from typing import Optional

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_user, logout_user

from .extensions import db
from .forms import SigninForm, SignupForm
from .models import User


auth = Blueprint("auth", __name__, url_prefix="/auth")


def is_safe_redirect_target(target: Optional[str]) -> bool:
    """Allow only redirects that remain on the current host."""
    if not target:
        return False

    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    return redirect_url.scheme in {"http", "https"} and host_url.netloc == redirect_url.netloc


@auth.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = SignupForm()
    if form.validate_on_submit():
        user = User(
            full_name=form.full_name.data.strip(),
            email=form.email.data.strip().lower(),
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash("Your account has been created successfully.", "success")
        return redirect(url_for("main.dashboard"))

    return render_template("auth/signup.html", form=form)


@auth.route("/signin", methods=["GET", "POST"])
def signin():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = SigninForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash(f"Welcome back, {user.full_name}.", "success")
            next_page = request.args.get("next")
            if is_safe_redirect_target(next_page):
                return redirect(next_page)
            return redirect(url_for("main.dashboard"))

        flash("The email address or password is incorrect.", "danger")

    return render_template("auth/signin.html", form=form)


@auth.post("/logout")
def logout():
    if current_user.is_authenticated:
        logout_user()
        flash("You have been signed out.", "success")
    return redirect(url_for("main.index"))
