def test_cors_credentials_page_sets_loyalty_cookie(client):
    response = client.get("/a05/cors-credentials")
    assert response.status_code == 200
    assert b"Permissive CORS with Credentials" in response.data
    set_cookie_headers = response.headers.getlist("Set-Cookie")
    assert any("a05_loyalty_token" in h for h in set_cookie_headers)
    assert any("SameSite=None" in h for h in set_cookie_headers)
    assert any("Secure" in h for h in set_cookie_headers)


def test_loyalty_api_reflects_any_origin(client):
    response = client.get(
        "/a05/api/loyalty-status", headers={"Origin": "https://totally-different-evil-site.example"}
    )
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "https://totally-different-evil-site.example"
    assert response.headers["Access-Control-Allow-Credentials"] == "true"


def test_loyalty_api_returns_the_real_cookie_value_to_any_origin(client):
    client.get("/a05/cors-credentials")  # sets the cookie
    response = client.get(
        "/a05/api/loyalty-status", headers={"Origin": "https://attacker.example"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["loyalty_token"] != "(no token set -- visit /a05/cors-credentials first)"
    assert len(data["loyalty_token"]) == 16  # secrets.token_hex(8)


def test_loyalty_api_no_cors_headers_without_an_origin_header(client):
    response = client.get("/a05/api/loyalty-status")
    assert response.status_code == 200
    assert "Access-Control-Allow-Origin" not in response.headers


def test_cors_credentials_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get(
        "/a05/api/loyalty-status", headers={"Origin": "https://attacker.example"}
    )
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "https://attacker.example"

    page_response = client.get("/a05/cors-credentials")
    assert page_response.status_code == 200
    assert b"Explanation" not in page_response.data
    assert b"Exploitation" not in page_response.data


def test_cors_credentials_link_appears_in_overview_once_registered(client):
    response = client.get("/a05/")
    assert response.status_code == 200
    assert b"Permissive CORS with Credentials" in response.data
    assert b'href="/a05/cors-credentials"' in response.data
