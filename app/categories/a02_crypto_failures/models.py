from app.extensions import db


class LegacyCredential(db.Model):
    __tablename__ = "legacy_credentials"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    weak_password_hash = db.Column(db.String(32), nullable=False)
