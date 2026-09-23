from app.categories.a07_auth_failures.models import AuthSession
from app.core.seed import seed_database


def test_login_page_renders(client):
    response = client.get("/a07/mfa-login-bruteforce")
    assert response.status_code == 200
    assert b"MFA Brute-Force" in response.data


def test_verify_page_does_not_display_the_code(app, client):
    seed_database(app)
    client.post(
        "/a07/mfa-login-bruteforce", data={"username": "dana", "password": "welcome1"}
    )
    response = client.get("/a07/mfa-verify-bruteforce")
    assert response.status_code == 200
    assert b"Your code is" not in response.data


def test_no_lockout_after_many_wrong_attempts_then_correct_code_still_works(app, client):
    seed_database(app)
    client.post(
        "/a07/mfa-login-bruteforce", data={"username": "dana", "password": "welcome1"}
    )

    for _ in range(20):
        response = client.post("/a07/mfa-verify-bruteforce", data={"code": "000000"})
        assert response.status_code == 200
        assert b"Incorrect code" in response.data

    with app.app_context():
        session_row = (
            AuthSession.query.filter_by(username="dana")
            .order_by(AuthSession.created_at.desc())
            .first()
        )
        real_code = session_row.pending_mfa_code

    response = client.post(
        "/a07/mfa-verify-bruteforce", data={"code": real_code}, follow_redirects=True
    )
    assert response.status_code == 200
    assert b"Welcome, dana" in response.data
