import secrets
from datetime import datetime

from flask import request

from app.categories.a07_auth_failures.models import AuthSession
from app.extensions import db

SID_COOKIE = "a07_session_id"


def get_or_create_session():
    # VULNERABLE: resolves the session id from a URL query parameter as an
    # alternative to the cookie, and ADOPTS any client-supplied value as a
    # real session if it doesn't already exist -- rather than only
    # trusting ids the server itself minted. This exact logic was
    # live-verified during brainstorming: it's what makes both the
    # session-in-url and session-fixation examples genuinely work.
    sid = request.args.get("sid") or request.cookies.get(SID_COOKIE)
    if sid is None:
        sid = secrets.token_hex(16)
    session_row = db.session.get(AuthSession, sid)
    if session_row is None:
        session_row = AuthSession(id=sid, username=None, mfa_verified=False, created_at=datetime.utcnow())
        db.session.add(session_row)
        db.session.commit()
    return session_row
