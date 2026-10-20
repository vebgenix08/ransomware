"""Firebase Admin helpers, loaded lazily so local-auth installs need no cloud credentials."""


def verify_firebase_id_token(app, token: str) -> dict:
    """Verify a client Firebase ID token using trusted server credentials (ADC)."""
    import firebase_admin
    from firebase_admin import auth

    try:
        firebase_app = firebase_admin.get_app("ransoware-auth")
    except ValueError:
        firebase_app = firebase_admin.initialize_app(
            options={"projectId": app.config["FIREBASE_PROJECT_ID"]},
            name="ransoware-auth",
        )
    return auth.verify_id_token(token, app=firebase_app, check_revoked=True)
