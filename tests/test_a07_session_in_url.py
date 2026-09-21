from app.core.seed import seed_database


def test_share_session_link_page_renders(app, client):
    seed_database(app)
    response = client.get("/a07/share-session-link")
    assert response.status_code == 200
    assert b"share_url" not in response.data  # sanity: no raw Jinja leaked
    assert b"sid=" in response.data


def test_session_id_in_url_alone_authenticates_with_no_cookie_at_all(app, client):
    seed_database(app)

    client.post("/a07/customer-login", data={"username": "dana", "password": "welcome1"})
    share_response = client.get("/a07/share-session-link")
    body = share_response.data.decode()
    start = body.index("/a07/account?sid=")
    end = body.index('"', start)
    share_url = body[start:end]
    assert "sid=" in share_url

    # Drop every cookie this client is holding, then visit ONLY the URL --
    # no cookie interaction of any kind, proving the URL parameter alone
    # is a complete, standalone credential.
    client.delete_cookie("a07_session_id")
    response = client.get(share_url)
    assert response.status_code == 200
    assert b"Logged in as" in response.data
    assert b"dana" in response.data


def test_session_in_url_link_appears_in_overview_once_registered(client):
    response = client.get("/a07/")
    assert response.status_code == 200
    assert b"Session Identifier Exposed in URL" in response.data
    assert b'href="/a07/share-session-link"' in response.data
