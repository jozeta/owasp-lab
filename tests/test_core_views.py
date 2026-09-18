from app.core.models import User
from app.core.seed import seed_database


def test_home_page_loads(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"OWASP Top 10" in response.data
    assert b"Intentionally vulnerable lab." in response.data


def test_switch_user_lists_seeded_users(app, client):
    seed_database(app)
    response = client.get("/switch-user")
    assert response.status_code == 200
    assert b"alice" in response.data


def test_switch_user_sets_session_and_redirects(app, client):
    seed_database(app)
    with app.app_context():
        alice_id = User.query.filter_by(username="alice").first().id

    response = client.post("/switch-user", data={"user_id": alice_id}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Logged in as alice" in response.data


def test_logout_clears_session(app, client):
    seed_database(app)
    with app.app_context():
        alice_id = User.query.filter_by(username="alice").first().id
    client.post("/switch-user", data={"user_id": alice_id})

    response = client.post("/logout", follow_redirects=True)
    assert response.status_code == 200
    assert b"Logged in as alice" not in response.data


def test_switch_user_rejects_unsafe_redirect_target(app, client):
    seed_database(app)
    with app.app_context():
        alice_id = User.query.filter_by(username="alice").first().id

    response = client.post(
        "/switch-user?next=https://evil.example/phish",
        data={"user_id": alice_id},
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/"


def test_switch_user_allows_safe_relative_redirect_target(app, client):
    seed_database(app)
    with app.app_context():
        alice_id = User.query.filter_by(username="alice").first().id

    response = client.post(
        "/switch-user?next=/a01/profile/2",
        data={"user_id": alice_id},
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/a01/profile/2"
