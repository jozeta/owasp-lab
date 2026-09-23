import unicodedata

from werkzeug.security import generate_password_hash

from app.categories.a07_auth_failures.models import A07Account
from app.extensions import db


def test_account_lookup_page_renders(client):
    response = client.get("/a07/account-lookup")
    assert response.status_code == 200
    assert b"Account Takeover via Unicode Normalization" in response.data


def test_lookalike_character_normalizes_to_target_username():
    lookalike_username = "demⓞ"
    assert unicodedata.normalize("NFKC", lookalike_username) == "demo"


def test_unicode_lookalike_username_collides_with_real_account(app, client):
    with app.app_context():
        victim = A07Account(
            username="demo", password_hash=generate_password_hash("victim-pw", method="pbkdf2:sha256")
        )
        db.session.add(victim)
        db.session.commit()

    lookalike_username = "demⓞ"  # NFKC-normalizes to "demo"
    client.post("/a07/register", data={"username": lookalike_username, "password": "attacker-pw"})

    # Submit the lookalike username (not the plain "demo") to the lookup endpoint.
    # The lookalike NFKC-normalizes to "demo" and collides with the victim's account.
    response = client.post("/a07/account-lookup", data={"username": lookalike_username}, follow_redirects=True)
    assert response.status_code == 200
    # Check the actual rendered success line (not just a bare substring --
    # the lookup form's own placeholder text could satisfy a weaker check
    # vacuously, regardless of whether a match was actually found).
    assert b"Matched and logged in as: <strong>demo</strong>" in response.data

    # The attacker's session is now authenticated AS the victim's real account.
    account_response = client.get("/a07/account")
    assert b"Logged in as" in account_response.data
    assert b"demo" in account_response.data
