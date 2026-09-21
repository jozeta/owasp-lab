from app.core.seed import seed_database


def test_logout_clears_the_callers_own_cookie(app, client):
    seed_database(app)
    client.post("/a07/customer-login", data={"username": "dana", "password": "welcome1"})
    client.post("/a07/logout")
    response = client.get("/a07/account")
    assert b"Not logged in" in response.data


def test_old_session_id_survives_logout_for_a_separate_holder(app, client):
    seed_database(app)
    client.post("/a07/customer-login", data={"username": "dana", "password": "welcome1"})
    account_response = client.get("/a07/account")
    body = account_response.data.decode()
    start = body.index("<code>") + len("<code>")
    end = body.index("</code>", start)
    old_sid = body[start:end]

    client.post("/a07/logout")
    # The legitimate holder's own client now sees "not logged in" (its
    # cookie was cleared) -- but a SEPARATE request presenting a manually
    # preserved copy of the old id must still work, proving the
    # server-side record was never actually invalidated.
    client.set_cookie("a07_session_id", old_sid, domain="localhost")
    response = client.get("/a07/account")
    assert b"Logged in as" in response.data
    assert b"dana" in response.data


def test_session_survives_logout_link_appears_in_overview_once_registered(client):
    response = client.get("/a07/")
    assert response.status_code == 200
    assert b"Session Not Invalidated on Logout" in response.data
    assert b'href="/a07/session-survives-logout"' in response.data
