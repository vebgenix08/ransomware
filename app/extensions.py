from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect


db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
migrate = Migrate()

login_manager.login_view = "auth.signin"
login_manager.login_message = "Please sign in to access your dashboard."
login_manager.login_message_category = "info"


@login_manager.user_loader
def load_user(user_id: str):
    from .models import User

    return db.session.get(User, int(user_id))
