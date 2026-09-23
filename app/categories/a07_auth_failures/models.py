from datetime import datetime

from app.extensions import db


class A07Account(db.Model):
    __tablename__ = "a07_accounts"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class AuthSession(db.Model):
    __tablename__ = "a07_auth_sessions"

    id = db.Column(db.String(32), primary_key=True)
    username = db.Column(db.String(80), nullable=True)
    mfa_verified = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # Generic per-session "pending MFA code" slot, set at login time and
    # checked at verify time by any MFA example that needs one. Reused
    # across multiple examples rather than each inventing its own column.
    pending_mfa_code = db.Column(db.String(6), nullable=True)
