from app.core.seed import seed_database


def test_mfa_login_step_one_does_not_grant_dashboard_access_without_step_two(app, client):
    seed_database(app)
    client.post("/a07/mfa-login", data={"username": "dana", "password": "welcome1"})
    # Deliberately skip /a07/mfa-verify entirely.
    response = client.get("/a07/mfa-dashboard")
    # VULNERABLE by omission: this assertion documents the bug -- the
    # dashboard is reachable even though mfa_verify was never called.
    assert response.status_code == 200
    assert b"Welcome, dana" in response.data


def test_mfa_verify_with_correct_code_also_reaches_dashboard(app, client):
    seed_database(app)
    client.post("/a07/mfa-login", data={"username": "dana", "password": "welcome1"})
    verify_response = client.post("/a07/mfa-verify", data={"code": "482913"}, follow_redirects=True)
    assert verify_response.status_code == 200
    assert b"Welcome, dana" in verify_response.data


def test_mfa_verify_rejects_wrong_code(app, client):
    seed_database(app)
    client.post("/a07/mfa-login", data={"username": "dana", "password": "welcome1"})
    response = client.post("/a07/mfa-verify", data={"code": "000000"})
    assert response.status_code == 200
    assert b"Incorrect code" in response.data


def test_mfa_dashboard_redirects_when_never_logged_in_at_all(client):
    response = client.get("/a07/mfa-dashboard", follow_redirects=True)
    assert response.status_code == 200
    assert b"Log in" in response.data or b"Username" in response.data


def test_mfa_bypass_link_appears_in_overview_once_registered(client):
    response = client.get("/a07/")
    assert response.status_code == 200
    assert b"Bypassable Multi-Factor Authentication" in response.data
    assert b'href="/a07/mfa-login"' in response.data
