from werkzeug.security import check_password_hash, generate_password_hash

from app.categories.a07_auth_failures.models import A07Account
from app.extensions import db


def test_register_page_renders(client):
    response = client.get("/a07/register")
    assert response.status_code == 200
    assert b"Password Reset via Username Collision" in response.data


def test_register_stores_username_with_whitespace_exactly(app, client):
    client.post("/a07/register", data={"username": "admin ", "password": "attacker-pw"})
    with app.app_context():
        account = A07Account.query.filter_by(username="admin ").first()
        assert account is not None


def test_username_collision_password_reset_hits_victim_account(app, client):
    with app.app_context():
        victim = A07Account(
            username="admin",
            password_hash=generate_password_hash("victim-original-pw", method="pbkdf2:sha256"),
        )
        db.session.add(victim)
        db.session.commit()
        victim_id = victim.id

    # Attacker registers with the victim's username plus a trailing space --
    # a technically distinct, brand-new account.
    response = client.post(
        "/a07/register", data={"username": "admin ", "password": "attacker-pw"}, follow_redirects=True
    )
    assert response.status_code == 200

    # Attacker (now logged in via session as "admin ") requests a password
    # reset "for themselves".
    response = client.post(
        "/a07/forgot-password", data={"new_password": "attacker-chosen-password"}, follow_redirects=True
    )
    assert response.status_code == 200

    with app.app_context():
        victim_after = db.session.get(A07Account, victim_id)
        assert check_password_hash(victim_after.password_hash, "attacker-chosen-password")

    # The attacker's own, distinct "admin " account is untouched.
    with app.app_context():
        attacker_account = A07Account.query.filter_by(username="admin ").first()
        assert check_password_hash(attacker_account.password_hash, "attacker-pw")
