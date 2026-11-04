from app.categories.a02_crypto_failures.routes import generate_reset_token
from app.core.seed import seed_database


def test_reset_password_referrer_page_shows_no_token_by_default(client):
    response = client.get("/a02/reset-password-referrer")
    assert response.status_code == 200
    assert generate_reset_token("admin").encode() not in response.data


def test_posting_with_no_token_at_all_does_not_reset_the_password(client):
    response = client.post(
        "/a02/reset-password-referrer", data={"new_password": "attacker-chosen"}
    )
    assert response.status_code == 200
    assert b"invalid or expired" in response.data.lower()


def test_posting_with_a_genuinely_leaked_token_resets_the_password(app, client):
    # The intended flow: a real token (as if legitimately emailed to the
    # account owner) ends up in this page's URL, gets leaked via Referer
    # (covered by test_external_sink_captures_and_displays_referer_with_token
    # below), and the attacker then uses it here to complete the reset.
    seed_database(app)
    token = generate_reset_token("admin")
    response = client.post(
        f"/a02/reset-password-referrer?token={token}",
        data={"new_password": "attacker-chosen"},
    )
    assert response.status_code == 200
    assert b"Password reset." in response.data

    login_response = client.post(
        "/a02/legacy-login",
        data={"username": "admin", "password": "attacker-chosen"},
    )
    assert b"takeover confirmed" in login_response.data


def test_reset_password_referrer_page_sets_no_referrer_policy(client):
    response = client.get("/a02/reset-password-referrer")
    assert "Referrer-Policy" not in response.headers


def test_reset_password_referrer_page_links_to_external_sink(client):
    response = client.get("/a02/reset-password-referrer")
    assert b"/a02/external-referrer-sink" in response.data


def test_external_sink_captures_and_displays_referer_with_token(client):
    token = generate_reset_token("admin")
    reset_url = f"/a02/reset-password-referrer?token={token}"

    # Simulates a browser following the "Security Tips" link on the reset
    # page: the browser automatically attaches the current page's full URL
    # (token included) as the Referer header, since nothing sets a
    # Referrer-Policy to prevent it.
    response = client.get(
        "/a02/external-referrer-sink",
        headers={"Referer": f"http://localhost{reset_url}"},
    )
    assert response.status_code == 200
    assert token.encode() in response.data
