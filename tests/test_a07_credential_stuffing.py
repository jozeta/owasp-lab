from app.core.seed import seed_database


def test_credential_stuffing_rejects_wrong_password(app, client):
    seed_database(app)
    response = client.post(
        "/a07/loyalty-portal-login", data={"username": "morgan", "password": "wrong"}
    )
    assert response.status_code == 200
    assert b"Invalid username or password" in response.data


def test_credential_stuffing_accepts_correct_pairs_across_accounts(app, client):
    seed_database(app)
    combo_list = [
        ("morgan", "Summer2023!"),
        ("priya", "letmein123"),
        ("theo", "qwerty1!"),
    ]
    for username, password in combo_list:
        response = client.post(
            "/a07/loyalty-portal-login",
            data={"username": username, "password": password},
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert b"Logged in as" in response.data
        assert username.encode() in response.data


def test_credential_stuffing_has_no_rate_limiting_across_many_attempts(app, client):
    seed_database(app)
    # A stuffing run tries many username:password pairs in a row --
    # simulate 15 wrong guesses across different usernames, then confirm
    # a correct pair still works immediately afterward.
    for i in range(15):
        client.post(
            "/a07/loyalty-portal-login",
            data={"username": f"nonexistent{i}", "password": "guess"},
        )
    response = client.post(
        "/a07/loyalty-portal-login",
        data={"username": "theo", "password": "qwerty1!"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Logged in as" in response.data


def test_credential_stuffing_link_appears_in_overview_once_registered(client):
    response = client.get("/a07/")
    assert response.status_code == 200
    assert b"Credential Stuffing Across Multiple Accounts" in response.data
    assert b'href="/a07/loyalty-portal-login"' in response.data
