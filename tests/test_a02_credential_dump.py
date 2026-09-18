from app.core.seed import seed_database


def test_credential_dump_lists_all_legacy_credentials(app, client):
    seed_database(app)

    response = client.get("/a02/credential-dump")
    assert response.status_code == 200
    assert b"alice" in response.data
    assert b"admin" in response.data


def test_credential_dump_link_appears_in_overview_once_registered(client):
    response = client.get("/a02/")
    assert response.status_code == 200
    assert b"Leaked Credential Dump" in response.data
    assert b'href="/a02/credential-dump"' in response.data
