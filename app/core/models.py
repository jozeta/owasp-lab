from datetime import datetime

from app.extensions import db


class Settings(db.Model):
    __tablename__ = "settings"

    id = db.Column(db.Integer, primary_key=True)
    show_explanations = db.Column(db.Boolean, nullable=False, default=True)
    show_exploit_instructions = db.Column(db.Boolean, nullable=False, default=False)
    scoring_enabled = db.Column(db.Boolean, nullable=False, default=False)

    @classmethod
    def get(cls):
        settings = cls.query.first()
        if settings is None:
            settings = cls(
                show_explanations=True,
                show_exploit_instructions=False,
                scoring_enabled=False,
            )
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


class ExampleProgress(db.Model):
    __tablename__ = "example_progress"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    example_id = db.Column(db.String(80), nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    hints_used = db.Column(db.Integer, nullable=False, default=0)
    points_awarded = db.Column(db.Integer, nullable=True)

    __table_args__ = (
        db.UniqueConstraint("user_id", "example_id", name="uq_progress_user_example"),
    )


def compute_points(example, hints_used):
    """Points earned for completing `example` after using `hints_used` hints.

    Base points come from difficulty (30 Hard / 20 Medium / 10 Easy). Each
    hint forfeits one even share of an (hint_count + 1)-share pool, so
    finishing always earns at least one share.
    """
    hint_count = len(example.hints)
    if hint_count == 0:
        return example.base_points()
    shares = hint_count + 1
    used = min(hints_used, hint_count)
    return (example.base_points() * (shares - used)) // shares
