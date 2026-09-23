from app.core.models import User
from app.core.seed import seed_database
from app.extensions import db


def _login_as(client, user_id):
    with client.session_transaction() as sess:
        sess["user_id"] = user_id


def test_change_email_page_renders_for_logged_in_user(app, client):
    with app.app_context():
        seed_database(app)
        alice = User.query.filter_by(username="alice").first()
        user_id = alice.id
    _login_as(client, user_id)

    response = client.get("/a01/change-email")
    assert response.status_code == 200
    assert b"Change email address" in response.data


def test_change_email_has_no_csrf_token(app, client):
    with app.app_context():
        seed_database(app)
        alice = User.query.filter_by(username="alice").first()
        user_id = alice.id
    _login_as(client, user_id)

    response = client.get("/a01/change-email")
    assert b"csrf_token" not in response.data
    assert b'name="csrf"' not in response.data


def test_change_email_succeeds_with_no_token_simulating_csrf(app, client):
    with app.app_context():
        seed_database(app)
        alice = User.query.filter_by(username="alice").first()
        user_id = alice.id
    _login_as(client, user_id)

    # Simulates an attacker's cross-site auto-submitting form: no CSRF
    # token field, no Origin/Referer check on the server, just the
    # victim's own session cookie (which `client` already carries).
    response = client.post(
        "/a01/change-email",
        data={"new_email": "attacker@evil.test"},
        follow_redirects=True,
    )
    assert response.status_code == 200

    with app.app_context():
        alice = db.session.get(User, user_id)
        assert alice.email == "attacker@evil.test"
