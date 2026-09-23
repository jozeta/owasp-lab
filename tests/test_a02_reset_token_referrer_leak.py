from app.categories.a02_crypto_failures.routes import generate_reset_token


def test_reset_password_referrer_page_renders_with_default_token(client):
    response = client.get("/a02/reset-password-referrer")
    assert response.status_code == 200
    assert generate_reset_token("admin").encode() in response.data


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
