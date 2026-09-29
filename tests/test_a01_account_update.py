from app.core.models import User
from app.extensions import db


def test_account_update_applies_legitimate_field(app, client, login):
    alice_id = login("alice")
    client.post("/a01/account/update", data={"display_name": "Alice Updated", "bio": "new bio"})
    with app.app_context():
        alice = db.session.get(User, alice_id)
        assert alice.display_name == "Alice Updated"
        assert alice.bio == "new bio"


def test_account_update_mass_assignment_escalates_role(app, client, login):
    alice_id = login("alice")
    with app.app_context():
        assert db.session.get(User, alice_id).role == "user"

    client.post(
        "/a01/account/update",
        data={"display_name": "Alice", "bio": "hiking", "role": "admin"},
    )

    with app.app_context():
        assert db.session.get(User, alice_id).role == "admin"


def test_account_update_link_appears_in_overview_once_registered(client):
    response = client.get("/a01/")
    assert response.status_code == 200
    assert b"Account Update" in response.data
    assert b"Role Escalation" in response.data
    assert b'href="/a01/account/update' in response.data


def test_account_update_shows_vulnerable_vs_secure_code(client, login):
    login("alice")
    response = client.get("/a01/account/update")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"ALLOWED_FIELDS" in response.data


def test_account_update_shows_detect_content(app, client, login):
    login("alice")
    with app.app_context():
        from app.core.models import Settings

        settings = Settings.get()
        settings.show_exploit_instructions = True
        settings.scoring_enabled = False
        db.session.commit()
    response = client.get("/a01/account/update")
    assert response.status_code == 200
    assert b"private_notes=PROBE" in response.data
