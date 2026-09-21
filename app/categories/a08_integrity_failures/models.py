from datetime import datetime

from app.extensions import db


class RceProof(db.Model):
    __tablename__ = "a08_rce_proofs"

    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255), nullable=False)
    triggered_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
