import hashlib

from app.core.seed import seed_database


def _token_for(username):
    from app.categories.a02_crypto_failures.routes import RESET_TOKEN_SALT

    return hashlib.md5(f"{username}:{RESET_TOKEN_SALT}".encode()).hexdigest()[:10]


def test_forgot_password_does_not_reveal_token(app, client):
    seed_database(app)

    response = client.post("/a02/forgot-password", data={"username": "admin"})
    assert response.status_code == 200
    assert _token_for("admin").encode() not in response.data


def test_predictable_token_allows_password_reset_and_takeover(app, client):
    seed_database(app)

    token = _token_for("admin")
    reset_response = client.post(
        f"/a02/reset-password/{token}",
        data={"new_password": "hacked123"},
    )
    assert reset_response.status_code == 200
    assert b"Password updated" in reset_response.data

    login_response = client.post(
        "/a02/legacy-login",
        data={"username": "admin", "password": "hacked123"},
    )
    assert b"takeover confirmed" in login_response.data


def test_reset_password_rejects_invalid_token(app, client):
    seed_database(app)

    response = client.post(
        "/a02/reset-password/not-a-real-token",
        data={"new_password": "whatever"},
    )
    assert response.status_code == 200
    assert b"invalid or expired" in response.data


def test_reset_token_link_appears_in_overview_once_registered(client):
    response = client.get("/a02/")
    assert response.status_code == 200
    assert b"Predictable Password Reset Token" in response.data
    assert b'href="/a02/forgot-password"' in response.data


def test_reset_token_attack_chain_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    forgot_response = client.post("/a02/forgot-password", data={"username": "admin"})
    assert forgot_response.status_code == 200
    assert b"Explanation" not in forgot_response.data
    assert b"Exploitation" not in forgot_response.data

    token = _token_for("admin")
    reset_response = client.post(
        f"/a02/reset-password/{token}",
        data={"new_password": "hacked123"},
    )
    assert reset_response.status_code == 200
    assert b"Password updated" in reset_response.data
    assert b"Explanation" not in reset_response.data
    assert b"Exploitation" not in reset_response.data

    login_response = client.post(
        "/a02/legacy-login",
        data={"username": "admin", "password": "hacked123"},
    )
    assert login_response.status_code == 200
    assert b"takeover confirmed" in login_response.data
    assert b"Explanation" not in login_response.data
    assert b"Exploitation" not in login_response.data
