from app.core.models import User
from app.core.seed import seed_database


def _login_as(client, app, username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        user_id = user.id
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
    return user_id


def test_anonymous_visitor_is_redirected_to_switch_user(app, client):
    seed_database(app)
    response = client.get("/instructor")
    assert response.status_code == 302
    assert "/switch-user" in response.headers["Location"]


def test_non_admin_user_gets_403(app, client):
    seed_database(app)
    _login_as(client, app, "alice")
    response = client.get("/instructor")
    assert response.status_code == 403


def test_admin_sees_every_seeded_user_including_zero_progress(app, client):
    seed_database(app)
    _login_as(client, app, "admin")
    response = client.get("/instructor")
    assert response.status_code == 200
    body = response.data.decode()
    for username in ("alice", "bob", "carol", "admin"):
        assert username in body


def test_admin_view_shows_never_for_users_with_no_activity(app, client):
    seed_database(app)
    _login_as(client, app, "admin")
    response = client.get("/instructor")
    assert b"Never" in response.data
