from app.core.models import Settings, User
from app.core.seed import seed_database


def test_settings_page_loads(client):
    response = client.get("/settings")
    assert response.status_code == 200
    assert b"show_explanations" in response.data


def test_settings_page_updates_toggles(app, client):
    client.post("/settings", data={})
    with app.app_context():
        settings = Settings.get()
        assert settings.show_explanations is False
        assert settings.show_exploit_instructions is False

    client.post(
        "/settings",
        data={"show_explanations": "on", "show_exploit_instructions": "on"},
    )
    with app.app_context():
        settings = Settings.get()
        assert settings.show_explanations is True
        assert settings.show_exploit_instructions is True


def test_reset_lab_restores_seeded_users(app, client):
    seed_database(app)
    with app.app_context():
        from app.extensions import db

        alice = User.query.filter_by(username="alice").first()
        alice.role = "admin"
        db.session.commit()

    client.post("/settings/reset")

    with app.app_context():
        alice = User.query.filter_by(username="alice").first()
        assert alice.role == "user"
