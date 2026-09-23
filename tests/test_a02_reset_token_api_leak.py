import hashlib

from app.categories.a02_crypto_failures.routes import generate_reset_token
from app.core.seed import seed_database


def test_forgot_password_api_page_renders(client):
    response = client.get("/a02/api/forgot-password")
    assert response.status_code == 200
    assert b"Reset Token Leaked in API Response" in response.data


def test_forgot_password_api_returns_token_directly_in_json(app, client):
    seed_database(app)
    response = client.post("/a02/api/forgot-password", json={"username": "admin"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["resetToken"] == generate_reset_token("admin")


def test_leaked_token_actually_works_for_takeover(app, client):
    seed_database(app)
    response = client.post("/a02/api/forgot-password", json={"username": "admin"})
    token = response.get_json()["resetToken"]

    reset_response = client.post(
        f"/a02/reset-password/{token}", data={"new_password": "attacker-new-password"}
    )
    assert reset_response.status_code == 200

    login_response = client.post(
        "/a02/legacy-login", data={"username": "admin", "password": "attacker-new-password"}
    )
    assert b"success" in login_response.data


def test_forgot_password_api_rejects_unknown_username(app, client):
    seed_database(app)
    response = client.post("/a02/api/forgot-password", json={"username": "nobody"})
    assert response.status_code == 404
