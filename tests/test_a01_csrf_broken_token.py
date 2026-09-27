from app.core.models import User
from app.core.seed import seed_database
from app.extensions import db


def _login_as(client, user_id):
    with client.session_transaction() as sess:
        sess["user_id"] = user_id


def test_change_display_name_page_renders_with_a_real_token(app, client):
    with app.app_context():
        seed_database(app)
        alice = User.query.filter_by(username="alice").first()
        user_id = alice.id
    _login_as(client, user_id)

    response = client.get("/a01/change-display-name")
    assert response.status_code == 200
    assert b"csrf_token" in response.data


def test_change_display_name_rejects_when_token_missing(app, client):
    with app.app_context():
        seed_database(app)
        alice = User.query.filter_by(username="alice").first()
        user_id = alice.id
    _login_as(client, user_id)

    client.get("/a01/change-display-name")  # establish the real session token
    response = client.post(
        "/a01/change-display-name",
        data={"display_name": "Attacker-Set-Name"},  # no csrf_token field at all
    )
    assert response.status_code == 200

    with app.app_context():
        alice = db.session.get(User, user_id)
        assert alice.display_name != "Attacker-Set-Name"


def test_change_display_name_succeeds_with_wrong_token_value(app, client):
    with app.app_context():
        seed_database(app)
        alice = User.query.filter_by(username="alice").first()
        user_id = alice.id
    _login_as(client, user_id)

    client.get("/a01/change-display-name")  # establish the REAL session token
    # Simulates an attacker's cross-site form: it can never know the real
    # per-session token, but this route only checks that SOME value was
    # submitted, not that it matches -- any non-empty string works.
    response = client.post(
        "/a01/change-display-name",
        data={
            "display_name": "Attacker-Set-Name",
            "csrf_token": "attacker-guessed-wrong-value",
        },
    )
    assert response.status_code == 200

    with app.app_context():
        alice = db.session.get(User, user_id)
        assert alice.display_name == "Attacker-Set-Name"
