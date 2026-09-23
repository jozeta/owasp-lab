import re

from app.core.seed import seed_database


def _login(client, username, password):
    return client.post(
        "/a07/mfa-reusable-code/login", data={"username": username, "password": password}
    )


def test_mfa_reusable_login_page_renders(client):
    response = client.get("/a07/mfa-reusable-code/login")
    assert response.status_code == 200
    assert b"MFA Code Reusability" in response.data


def test_verify_page_shows_demo_code(app, client):
    seed_database(app)
    _login(client, "morgan", "Summer2023!")
    response = client.get("/a07/mfa-reusable-code/verify")
    assert response.status_code == 200
    assert b"shown here since this lab doesn't send real SMS/email" in response.data


def test_same_code_can_be_submitted_twice(app, client):
    seed_database(app)
    _login(client, "morgan", "Summer2023!")
    verify_page = client.get("/a07/mfa-reusable-code/verify")
    match = re.search(rb"<strong>(\d{6})</strong>", verify_page.data)
    assert match is not None
    code = match.group(1).decode()

    first = client.post(
        "/a07/mfa-reusable-code/verify", data={"code": code}, follow_redirects=True
    )
    assert first.status_code == 200
    assert b"morgan" in first.data

    # VULNERABLE: the exact same code, submitted again, is still accepted --
    # nothing invalidates it after its first successful use.
    second = client.post(
        "/a07/mfa-reusable-code/verify", data={"code": code}, follow_redirects=True
    )
    assert second.status_code == 200
    assert b"Incorrect code" not in second.data
    assert b"morgan" in second.data
