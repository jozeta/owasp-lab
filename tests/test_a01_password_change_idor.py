from app.core.models import User
from app.core.seed import seed_database
from app.extensions import db


def test_password_change_api_updates_arbitrary_user_by_email(app, client):
    with app.app_context():
        seed_database(app)
        bob = User.query.filter_by(username="bob").first()
        bob_id = bob.id
        bob_email = bob.email
        original_hash = bob.password_hash

    # No login, no session at all -- the endpoint trusts the "email"
    # field in the request body to pick which account to update, never
    # checking it against any authenticated identity.
    response = client.post(
        "/a01/api/password-change",
        json={"email": bob_email, "new_password": "attacker-chosen-password"},
    )
    assert response.status_code == 200

    with app.app_context():
        bob = db.session.get(User, bob_id)
        assert bob.password_hash != original_hash


def test_password_change_api_rejects_unknown_email(client):
    response = client.post(
        "/a01/api/password-change",
        json={"email": "nobody@nowhere.test", "new_password": "x"},
    )
    assert response.status_code == 404


def test_password_change_api_page_renders(client):
    response = client.get("/a01/api/password-change")
    assert response.status_code == 200
    assert b"IDOR on Password-Change API" in response.data
