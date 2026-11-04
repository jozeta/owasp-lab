from app.core.seed import seed_database


def _login(client, endpoint, username, password):
    return client.post(endpoint, data={"username": username, "password": password})


def test_mfa_bypass_still_reaches_dashboard_without_entering_a_code(app, client):
    # The ONE example whose intended lesson is this exact gap must keep
    # working with zero code verification.
    seed_database(app)
    _login(client, "/a07/mfa-login", "dana", "welcome1")
    response = client.get("/a07/mfa-dashboard")
    assert response.status_code == 200
    assert b"Welcome, dana" in response.data


def test_mfa_bruteforce_login_then_skip_to_dashboard_is_rejected(app, client):
    seed_database(app)
    _login(client, "/a07/mfa-login-bruteforce", "dana", "welcome1")
    response = client.get("/a07/mfa-dashboard", follow_redirects=True)
    assert b"Welcome, dana" not in response.data


def test_mfa_unbound_login_then_skip_to_dashboard_is_rejected(app, client):
    seed_database(app)
    _login(client, "/a07/mfa-login-unbound", "dana", "welcome1")
    response = client.get("/a07/mfa-dashboard", follow_redirects=True)
    assert b"Welcome, dana" not in response.data


def test_mfa_magic_value_login_then_skip_to_dashboard_is_rejected(app, client):
    seed_database(app)
    _login(client, "/a07/mfa-login-magic-value", "dana", "welcome1")
    response = client.get("/a07/mfa-dashboard", follow_redirects=True)
    assert b"Welcome, dana" not in response.data
