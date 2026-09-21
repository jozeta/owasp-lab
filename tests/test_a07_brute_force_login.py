from app.core.seed import seed_database


def test_brute_force_login_rejects_wrong_password(app, client):
    seed_database(app)
    response = client.post(
        "/a07/customer-login", data={"username": "dana", "password": "wrong-guess"}
    )
    assert response.status_code == 200
    assert b"Invalid username or password" in response.data


def test_brute_force_login_accepts_correct_password(app, client):
    seed_database(app)
    response = client.post(
        "/a07/customer-login",
        data={"username": "dana", "password": "welcome1"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Logged in as" in response.data
    assert b"dana" in response.data


def test_brute_force_login_has_no_rate_limiting(app, client):
    seed_database(app)
    # 20 consecutive wrong-password attempts against the same username --
    # every single one must return the normal "invalid" response, never a
    # 429, a lockout message, or any other sign of throttling.
    for _ in range(20):
        response = client.post(
            "/a07/customer-login", data={"username": "dana", "password": "wrong-guess"}
        )
        assert response.status_code == 200
        assert b"Invalid username or password" in response.data
    # immediately after 20 failed attempts, the correct password still
    # works on the very next try -- proving nothing was ever locked out
    response = client.post(
        "/a07/customer-login",
        data={"username": "dana", "password": "welcome1"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Logged in as" in response.data


def test_brute_force_login_link_appears_in_overview_once_registered(client):
    response = client.get("/a07/")
    assert response.status_code == 200
    assert b"No Rate Limiting Enables Brute Force" in response.data
    assert b'href="/a07/customer-login"' in response.data
