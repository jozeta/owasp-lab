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


# --- Cross-flow VERIFY-route and code-reveal bypasses (final-review finding) ---
#
# Task 9 scoped the shared DASHBOARDS by active_mfa_flow, but the verify
# routes and code-reveal endpoints themselves stayed unscoped: a session
# that logged in via one flow could use a DIFFERENT flow's verify step (or
# code-reveal endpoint) to get mfa_verified=True, because every flow shares
# the same AuthSession row. Each test below proves a specific cross-flow
# shortcut no longer works.


def test_bruteforce_login_then_bypass_verify_code_is_rejected(app, client):
    # mfa-brute-force must actually be brute-forced -- the openly-shown
    # mfa-bypass code must not work as a shortcut for it.
    seed_database(app)
    _login(client, "/a07/mfa-login-bruteforce", "dana", "welcome1")
    response = client.post("/a07/mfa-verify", data={"code": "482913"}, follow_redirects=True)
    assert b"Welcome, dana" not in response.data
    final_dashboard = client.get("/a07/mfa-dashboard", follow_redirects=True)
    assert b"Welcome, dana" not in final_dashboard.data


def test_bruteforce_login_then_magic_value_verify_is_rejected(app, client):
    seed_database(app)
    _login(client, "/a07/mfa-login-bruteforce", "dana", "welcome1")
    response = client.post(
        "/a07/mfa-verify-magic-value", data={"code": "000000"}, follow_redirects=True
    )
    assert b"Welcome, dana" not in response.data
    final_dashboard = client.get("/a07/mfa-dashboard", follow_redirects=True)
    assert b"Welcome, dana" not in final_dashboard.data


def test_bruteforce_login_then_leaked_code_api_does_not_leak_its_code(app, client):
    # The leaked-code API must not operate on -- or hand back -- a
    # different flow's pending code at all.
    seed_database(app)
    _login(client, "/a07/mfa-login-bruteforce", "dana", "welcome1")
    response = client.post("/a07/mfa-leaked-code/api/send-code")
    assert response.status_code != 200 or response.get_json() is None
    verify_with_bruteforce_code_at_bruteforce_route = client.get("/a07/mfa-dashboard", follow_redirects=True)
    assert b"Welcome, dana" not in verify_with_bruteforce_code_at_bruteforce_route.data


def test_bruteforce_login_then_reusable_code_verify_does_not_show_its_code(app, client):
    seed_database(app)
    _login(client, "/a07/mfa-login-bruteforce", "dana", "welcome1")
    response = client.get("/a07/mfa-reusable-code/verify", follow_redirects=True)
    assert b"Your code is" not in response.data
    assert b"shown here since this lab doesn't send real SMS/email" not in response.data


def test_unbound_login_then_bypass_verify_code_is_rejected(app, client):
    seed_database(app)
    _login(client, "/a07/mfa-login-unbound", "dana", "welcome1")
    response = client.post("/a07/mfa-verify", data={"code": "482913"}, follow_redirects=True)
    assert b"Welcome, dana" not in response.data


def test_unbound_login_then_magic_value_verify_is_rejected(app, client):
    seed_database(app)
    _login(client, "/a07/mfa-login-unbound", "dana", "welcome1")
    response = client.post(
        "/a07/mfa-verify-magic-value", data={"code": "000000"}, follow_redirects=True
    )
    assert b"Welcome, dana" not in response.data


def test_leaked_code_login_then_bypass_verify_does_not_unlock_its_own_dashboard(app, client):
    seed_database(app)
    _login(client, "/a07/mfa-leaked-code/login", "dana", "welcome1")
    client.post("/a07/mfa-verify", data={"code": "482913"})
    response = client.get("/a07/mfa-leaked-code/dashboard", follow_redirects=True)
    assert b"Welcome, dana" not in response.data


def test_leaked_code_login_then_magic_value_verify_does_not_unlock_its_own_dashboard(app, client):
    seed_database(app)
    _login(client, "/a07/mfa-leaked-code/login", "dana", "welcome1")
    client.post("/a07/mfa-verify-magic-value", data={"code": "000000"})
    response = client.get("/a07/mfa-leaked-code/dashboard", follow_redirects=True)
    assert b"Welcome, dana" not in response.data


def test_reusable_code_login_then_bypass_verify_does_not_unlock_its_own_dashboard(app, client):
    seed_database(app)
    _login(client, "/a07/mfa-reusable-code/login", "morgan", "Summer2023!")
    client.post("/a07/mfa-verify", data={"code": "482913"})
    response = client.get("/a07/mfa-reusable-code/dashboard", follow_redirects=True)
    assert b"Welcome, morgan" not in response.data


def test_reusable_code_login_then_magic_value_verify_does_not_unlock_its_own_dashboard(app, client):
    seed_database(app)
    _login(client, "/a07/mfa-reusable-code/login", "morgan", "Summer2023!")
    client.post("/a07/mfa-verify-magic-value", data={"code": "000000"})
    response = client.get("/a07/mfa-reusable-code/dashboard", follow_redirects=True)
    assert b"Welcome, morgan" not in response.data
