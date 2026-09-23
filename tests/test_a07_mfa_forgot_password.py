from werkzeug.security import generate_password_hash

from app.categories.a07_auth_failures.models import A07Account, AuthSession
from app.extensions import db


def test_mfa_forgot_password_page_renders(client):
    response = client.get("/a07/mfa-forgot-password")
    assert response.status_code == 200
    assert b"Password Reset Silently Disables 2FA" in response.data


def test_mfa_forgot_password_rejects_unknown_username(client):
    response = client.post("/a07/mfa-forgot-password", data={"username": "nobody", "new_password": "x"})
    assert response.status_code == 200
    assert b"No account" in response.data


def test_password_reset_marks_mfa_verified_without_entering_code(app, client):
    with app.app_context():
        account = A07Account(
            username="dana2fa",
            password_hash=generate_password_hash("original-pw", method="pbkdf2:sha256"),
        )
        db.session.add(account)
        db.session.commit()

    response = client.post(
        "/a07/mfa-forgot-password",
        data={"username": "dana2fa", "new_password": "attacker-new-pw"},
    )
    assert response.status_code == 200

    # The verification-code step (/a07/mfa-verify) was never touched at
    # all, yet the session is now marked MFA-verified purely from
    # resetting the password.
    with app.app_context():
        session_row = AuthSession.query.filter_by(username="dana2fa").first()
        assert session_row is not None
        assert session_row.mfa_verified is True
