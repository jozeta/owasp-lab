from flask import session

from app.core.models import User


def get_current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return User.query.get(user_id)
