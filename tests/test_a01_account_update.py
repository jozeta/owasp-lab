from app.core.models import User


def test_account_update_applies_legitimate_field(app, client, login):
    alice_id = login("alice")
    client.post("/a01/account/update", data={"display_name": "Alice Updated", "bio": "new bio"})
    with app.app_context():
        alice = User.query.get(alice_id)
        assert alice.display_name == "Alice Updated"
        assert alice.bio == "new bio"


def test_account_update_mass_assignment_escalates_role(app, client, login):
    alice_id = login("alice")
    with app.app_context():
        assert User.query.get(alice_id).role == "user"

    client.post(
        "/a01/account/update",
        data={"display_name": "Alice", "bio": "hiking", "role": "admin"},
    )

    with app.app_context():
        assert User.query.get(alice_id).role == "admin"


def test_account_update_link_appears_in_overview_once_registered(client):
    response = client.get("/a01/")
    assert response.status_code == 200
    assert b"Account Update" in response.data
    assert b"Role Escalation" in response.data
    assert b'href="/a01/account/update' in response.data
