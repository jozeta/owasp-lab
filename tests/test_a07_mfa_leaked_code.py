from app.core.seed import seed_database


def _login(client, username, password):
    return client.post(
        "/a07/mfa-leaked-code/login", data={"username": username, "password": password}
    )


def test_mfa_leaked_login_page_renders(client):
    response = client.get("/a07/mfa-leaked-code/login")
    assert response.status_code == 200
    assert b"MFA Code Leaked to Client" in response.data


def test_verify_page_does_not_show_code_on_page(app, client):
    seed_database(app)
    _login(client, "dana", "welcome1")
    response = client.get("/a07/mfa-leaked-code/verify")
    assert response.status_code == 200
    assert b"shown here" not in response.data


def test_send_code_api_leaks_real_code_in_json(app, client):
    seed_database(app)
    _login(client, "dana", "welcome1")
    response = client.post("/a07/mfa-leaked-code/api/send-code")
    assert response.status_code == 200
    data = response.get_json()
    assert "debug_code" in data
    assert len(data["debug_code"]) == 6
    assert data["debug_code"].isdigit()


def test_leaked_code_from_api_completes_mfa(app, client):
    seed_database(app)
    _login(client, "dana", "welcome1")
    send_response = client.post("/a07/mfa-leaked-code/api/send-code")
    leaked_code = send_response.get_json()["debug_code"]

    verify_response = client.post(
        "/a07/mfa-leaked-code/verify", data={"code": leaked_code}, follow_redirects=True
    )
    assert verify_response.status_code == 200
    assert b"dana" in verify_response.data
