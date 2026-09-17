from flask import session

from app.core.models import User
from app.extensions import db


def get_current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return db.session.get(User, user_id)
