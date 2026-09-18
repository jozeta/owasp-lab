from app.core.models import User
from app.core.seed import seed_database
from app.extensions import db


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


def test_home_page_lists_categories_sorted_by_short_id(client):
    response = client.get("/")
    assert response.status_code == 200
    body = response.data.decode()
    a01_index = body.index("A01")
    a02_index = body.index("A02")
    assert a01_index < a02_index


def test_force_reset_restores_tampered_data_via_get(app, client):
    seed_database(app)
    with app.app_context():
        alice = User.query.filter_by(username="alice").first()
        alice.role = "admin"
        alice.bio = "tampered"
        db.session.commit()

    response = client.get("/force-reset")
    assert response.status_code == 200
    assert b"force-reset" in response.data.lower()

    with app.app_context():
        alice = User.query.filter_by(username="alice").first()
        assert alice.role == "user"
        assert alice.bio != "tampered"


def test_force_reset_clears_session(app, client):
    seed_database(app)
    with app.app_context():
        alice_id = User.query.filter_by(username="alice").first().id
    client.post("/switch-user", data={"user_id": alice_id})

    client.get("/force-reset")

    response = client.get("/", follow_redirects=True)
    assert b"Logged in as alice" not in response.data


def test_force_reset_does_not_require_template_rendering(client, monkeypatch):
    import app.core.views as core_views

    def boom(*args, **kwargs):
        raise RuntimeError("template layer is broken")

    monkeypatch.setattr(core_views, "render_template", boom)

    response = client.get("/force-reset")
    assert response.status_code == 200


def test_home_page_category_links_include_tooltip_attributes(client):
    response = client.get("/")
    assert response.status_code == 200
    body = response.data.decode()
    assert 'data-bs-toggle="tooltip"' in body
    assert "Access control that is not enforced on the server" in body


def test_home_page_includes_theme_toggle_button(client):
    response = client.get("/")
    assert response.status_code == 200
    assert 'id="theme-toggle"' in response.data.decode()


def test_html_tag_does_not_hardcode_light_theme(client):
    response = client.get("/")
    body = response.data.decode()
    assert 'data-bs-theme="light"' not in body


def test_tools_page_loads(client):
    response = client.get("/tools")
    assert response.status_code == 200
    body = response.data.decode()
    assert "sqlmap" in body
    assert "curl" in body
    assert 'href="https://curl.se/download.html"' in body
