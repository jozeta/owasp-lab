from app.core.seed import seed_database


def test_login_page_renders(client):
    response = client.get("/a07/mfa-login-magic-value")
    assert response.status_code == 200
    assert b"MFA Bypass via Magic" in response.data


def test_verify_page_does_not_display_the_code(app, client):
    seed_database(app)
    client.post(
        "/a07/mfa-login-magic-value", data={"username": "dana", "password": "welcome1"}
    )
    response = client.get("/a07/mfa-verify-magic-value")
    assert response.status_code == 200
    assert b"Your code is" not in response.data


def test_magic_value_000000_bypasses_without_knowing_real_code(app, client):
    seed_database(app)
    client.post(
        "/a07/mfa-login-magic-value", data={"username": "dana", "password": "welcome1"}
    )
    response = client.post(
        "/a07/mfa-verify-magic-value", data={"code": "000000"}, follow_redirects=True
    )
    assert response.status_code == 200
    assert b"Welcome, dana" in response.data


def test_magic_value_null_string_also_bypasses(app, client):
    seed_database(app)
    client.post(
        "/a07/mfa-login-magic-value", data={"username": "dana", "password": "welcome1"}
    )
    response = client.post(
        "/a07/mfa-verify-magic-value", data={"code": "null"}, follow_redirects=True
    )
    assert response.status_code == 200
    assert b"Welcome, dana" in response.data


def test_wrong_non_magic_code_still_fails(app, client):
    seed_database(app)
    client.post(
        "/a07/mfa-login-magic-value", data={"username": "dana", "password": "welcome1"}
    )
    response = client.post("/a07/mfa-verify-magic-value", data={"code": "123123"})
    assert response.status_code == 200
    assert b"Incorrect code" in response.data
