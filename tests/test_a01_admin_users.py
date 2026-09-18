from app.core.models import User
from app.extensions import db


def test_admin_users_reachable_by_non_admin(client, login):
    login("alice")
    response = client.get("/a01/admin/users")
    assert response.status_code == 200
    assert b"bob" in response.data


def test_admin_users_role_change_has_no_role_check(app, client, login):
    login("alice")
    with app.app_context():
        bob = User.query.filter_by(username="bob").first()
        bob_id = bob.id
        assert bob.role == "user"

    response = client.post("/a01/admin/users", data={"user_id": bob_id, "role": "admin"})
    assert response.status_code == 200

    with app.app_context():
        assert db.session.get(User, bob_id).role == "admin"


def test_admin_users_link_appears_in_overview_once_registered(client):
    response = client.get("/a01/")
    assert response.status_code == 200
    assert b"Hidden Admin Panel" in response.data
    assert b'href="/a01/admin/users' in response.data
