"""Small helper for account-scoped security audit records."""
from flask_login import current_user

from .extensions import db
from .models import AuditLog


def record_audit(action: str, **details) -> None:
    if not current_user.is_authenticated:
        return
    # Callers should pass only non-secret identifiers, never credentials or file contents.
    db.session.add(AuditLog(user_id=current_user.id, action=action, details=details))
