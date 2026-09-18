from app.extensions import db


class InjectionAccount(db.Model):
    __tablename__ = "injection_accounts"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)  # plaintext on purpose -- see A03 Easy
    is_admin = db.Column(db.Boolean, nullable=False, default=False)


class Secret(db.Model):
    __tablename__ = "a03_secrets"

    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(120), nullable=False)
    value = db.Column(db.String(255), nullable=False)


class Comment(db.Model):
    __tablename__ = "a03_comments"

    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(80), nullable=False)
    body = db.Column(db.Text, nullable=False)
