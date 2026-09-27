from app.core.models import User
from app.core.seed import seed_database
from app.extensions import db


def _login_as(client, user_id):
    with client.session_transaction() as sess:
        sess["user_id"] = user_id


def test_single_admin_role_is_rejected(app, client):
    with app.app_context():
        seed_database(app)
        alice = User.query.filter_by(username="alice").first()
        user_id = alice.id
    _login_as(client, user_id)

    response = client.post("/a01/update-preferences", data={"role": "admin"})
    assert response.status_code == 403

    with app.app_context():
        alice = db.session.get(User, user_id)
        assert alice.role != "admin"


def test_duplicate_role_parameter_bypasses_the_check(app, client):
    with app.app_context():
        seed_database(app)
        alice = User.query.filter_by(username="alice").first()
        user_id = alice.id
    _login_as(client, user_id)

    # Simulates HTTP Parameter Pollution: the same field submitted twice,
    # in this exact order -- the check must see "user" (pass) while the
    # write must apply "admin" (the last occurrence).
    response = client.post(
        "/a01/update-preferences",
        data="role=user&role=admin",
        content_type="application/x-www-form-urlencoded",
    )
    assert response.status_code == 200

    with app.app_context():
        alice = db.session.get(User, user_id)
        assert alice.role == "admin"
