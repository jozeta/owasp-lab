from app.extensions import db


class Settings(db.Model):
    __tablename__ = "settings"

    id = db.Column(db.Integer, primary_key=True)
    show_explanations = db.Column(db.Boolean, nullable=False, default=True)
    show_exploit_instructions = db.Column(db.Boolean, nullable=False, default=True)

    @classmethod
    def get(cls):
        settings = cls.query.first()
        if settings is None:
            settings = cls(show_explanations=True, show_exploit_instructions=True)
            db.session.add(settings)
            db.session.commit()
        return settings


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(120), nullable=False)
    bio = db.Column(db.Text, nullable=False, default="")
    private_notes = db.Column(db.Text, nullable=False, default="")
    role = db.Column(db.String(20), nullable=False, default="user")
