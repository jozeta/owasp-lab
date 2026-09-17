from app.core.models import Settings, User
from app.extensions import db


def test_settings_get_creates_and_returns_singleton(app):
    with app.app_context():
        first = Settings.get()
        second = Settings.get()
        assert first.id == second.id
        assert first.show_explanations is True
        assert first.show_exploit_instructions is True


def test_user_model_round_trips_fields(app):
    with app.app_context():
        user = User(
            username="testuser",
            email="testuser@example.test",
            password_hash="hashed-value",
            display_name="Test User",
            bio="",
            private_notes="",
            role="user",
        )
        db.session.add(user)
        db.session.commit()

        fetched = User.query.filter_by(username="testuser").first()
        assert fetched.id == user.id
        assert fetched.email == "testuser@example.test"
        assert fetched.role == "user"
