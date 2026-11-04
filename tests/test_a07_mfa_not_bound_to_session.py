from app.categories.a07_auth_failures.routes import PENDING_MFA_CODES_BY_USERNAME
from app.core.seed import seed_database


def test_login_page_renders(client):
    response = client.get("/a07/mfa-login-unbound")
    assert response.status_code == 200
    assert b"MFA Code Not Bound to Session" in response.data


def test_code_generated_for_one_session_works_through_a_totally_different_session(app):
    seed_database(app)
    victim_client = app.test_client()
    attacker_client = app.test_client()

    victim_client.post(
        "/a07/mfa-login-unbound", data={"username": "dana", "password": "welcome1"}
    )

    with app.app_context():
        real_code = PENDING_MFA_CODES_BY_USERNAME["dana"]

    # attacker_client shares no cookies with victim_client and never
    # entered dana's password anywhere -- it's a completely separate,
    # unrelated session.
    response = attacker_client.post(
        "/a07/mfa-verify-unbound",
        data={"username": "dana", "code": real_code},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Welcome, dana" in response.data


def test_session_already_in_a_different_flow_cannot_use_unbound_verify(app):
    seed_database(app)
    attacker_client = app.test_client()

    # The attacker's session is NOT fresh -- it already authenticated
    # through a completely different MFA flow (bruteforce), so its
    # active_mfa_flow is "bruteforce", not None or "unbound". The fix for
    # the over-scoping bug must still block this: only a genuinely fresh
    # session (active_mfa_flow is None) or one already in the unbound flow
    # may use mfa-verify-unbound.
    attacker_client.post(
        "/a07/mfa-login-bruteforce", data={"username": "morgan", "password": "Summer2023!"}
    )

    with app.app_context():
        PENDING_MFA_CODES_BY_USERNAME["dana"] = "482913"

    response = attacker_client.post(
        "/a07/mfa-verify-unbound",
        data={"username": "dana", "code": "482913"},
        follow_redirects=True,
    )
    assert b"Welcome, dana" not in response.data


def test_wrong_code_for_the_right_username_still_fails(app):
    seed_database(app)
    client = app.test_client()
    client.post(
        "/a07/mfa-login-unbound", data={"username": "dana", "password": "welcome1"}
    )
    response = client.post(
        "/a07/mfa-verify-unbound", data={"username": "dana", "code": "000000"}
    )
    assert response.status_code == 200
    assert b"Incorrect code" in response.data
