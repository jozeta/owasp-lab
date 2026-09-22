from datetime import datetime

from app.extensions import db


class SecurityEvent(db.Model):
    __tablename__ = "a09_security_events"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(64), nullable=False)
    detail = db.Column(db.String(255), nullable=False)
    logged_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
