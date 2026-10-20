from urllib.parse import urljoin, urlparse
from typing import Optional

import secrets

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_user, logout_user
from firebase_admin.exceptions import FirebaseError
from google.auth.exceptions import DefaultCredentialsError
from sqlalchemy.exc import IntegrityError

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
    firebase_mode = current_app.config["AUTH_PROVIDER"] == "firebase"
    if firebase_mode:
        if request.method == "POST":
            return jsonify(error="Use the Firebase sign-up form in this browser."), 400
        return render_template("auth/signup.html", form=form, firebase_mode=True)

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
    firebase_mode = current_app.config["AUTH_PROVIDER"] == "firebase"
    if firebase_mode:
        if request.method == "POST":
            return jsonify(error="Use the Firebase sign-in form in this browser."), 400
        return render_template("auth/signin.html", form=form, firebase_mode=True)

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


@auth.post("/firebase/session")
def firebase_session():
    """Exchange a verified Firebase ID token for the app's normal Flask session."""
    if current_app.config["AUTH_PROVIDER"] != "firebase":
        return jsonify(error="Firebase sign-in is not enabled for this installation."), 404

    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        return jsonify(error="Sign-in token is missing. Please sign in again."), 401
    token = authorization[7:].strip()
    if not token or len(token) > 8192:
        return jsonify(error="Sign-in token is invalid. Please sign in again."), 401

    try:
        from .firebase_auth import verify_firebase_id_token
        claims = verify_firebase_id_token(current_app, token)
    except DefaultCredentialsError:
        current_app.logger.error("Firebase Admin credentials are not configured for this server.")
        return jsonify(error="Firebase server credentials are not configured. Ask the app administrator to finish setup."), 503
    except FirebaseError:
        return jsonify(error="Firebase could not verify this sign-in. Please sign in again."), 401
    except Exception:
        current_app.logger.exception("Firebase token verification is unavailable.")
        return jsonify(error="Firebase sign-in is temporarily unavailable. Please try again."), 503

    firebase_uid = claims.get("uid")
    email = (claims.get("email") or "").strip().lower()
    if not firebase_uid or not email or claims.get("email_verified") is not True:
        return jsonify(error="Verify your email address before continuing."), 403

    user = User.query.filter_by(firebase_uid=firebase_uid).first()
    email_owner = User.query.filter_by(email=email).first()
    if user and email_owner and email_owner.id != user.id:
        return jsonify(error="This verified email is already linked to another app account. Contact the administrator."), 409
    if not user:
        if email_owner and email_owner.firebase_uid not in (None, firebase_uid):
            return jsonify(error="This email is already linked to a different Firebase account."), 409
        user = email_owner or User(email=email, full_name="")
        if not user.id:
            user.set_password(secrets.token_urlsafe(48))
            db.session.add(user)
        user.firebase_uid = firebase_uid

    display_name = (claims.get("name") or "").strip()
    if display_name:
        user.full_name = display_name[:100]
    elif not user.full_name:
        user.full_name = email.split("@", 1)[0][:100] or "RansomShield user"
    user.email = email
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify(error="This account could not be linked safely. Contact the administrator."), 409

    login_user(user, remember=False, fresh=True)
    return jsonify(ok=True, next=url_for("main.dashboard"))


@auth.post("/logout")
def logout():
    if current_user.is_authenticated:
        logout_user()
        flash("You have been signed out.", "success")
    return redirect(url_for("main.index"))
