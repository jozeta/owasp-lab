from app.core.seed import seed_database


def test_lookup_account_exact_match_returns_one_user(app, client):
    with app.app_context():
        seed_database(app)

    response = client.post("/a01/lookup-account", data={"username": "alice"})
    assert response.status_code == 200
    assert b"alice" in response.data
    assert b"bob" not in response.data


def test_lookup_account_wildcard_returns_every_user(app, client):
    with app.app_context():
        seed_database(app)

    response = client.post("/a01/lookup-account", data={"username": "%"})
    assert response.status_code == 200
    assert b"alice" in response.data
    assert b"bob" in response.data
    assert b"carol" in response.data
    assert b"admin" in response.data
