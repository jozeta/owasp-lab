def test_filtered_host_lookup_accepts_a_host(client):
    response = client.post("/a03/filtered-host-lookup", data={"host": "localhost"})
    assert response.status_code == 200
    assert b"Blocked: hostname contains a disallowed character." not in response.data


def test_filtered_host_lookup_blocks_semicolon(client):
    response = client.post(
        "/a03/filtered-host-lookup", data={"host": "localhost;echo BLOCKED_PROOF"}
    )
    assert response.status_code == 200
    assert b"Blocked: hostname contains a disallowed character." in response.data
    assert b"BLOCKED_PROOF" not in response.data


def test_filtered_host_lookup_blocks_ampersand(client):
    response = client.post(
        "/a03/filtered-host-lookup", data={"host": "localhost&echo BLOCKED_PROOF"}
    )
    assert response.status_code == 200
    assert b"Blocked: hostname contains a disallowed character." in response.data
    assert b"BLOCKED_PROOF" not in response.data


def test_filtered_host_lookup_blocks_pipe(client):
    response = client.post(
        "/a03/filtered-host-lookup", data={"host": "localhost|echo BLOCKED_PROOF"}
    )
    assert response.status_code == 200
    assert b"Blocked: hostname contains a disallowed character." in response.data
    assert b"BLOCKED_PROOF" not in response.data


def test_filtered_host_lookup_newline_bypasses_the_blacklist(client):
    # The blacklist checks only ";", "&", "|" -- a literal newline is
    # never checked for, and /bin/sh treats it exactly like a semicolon.
    response = client.post(
        "/a03/filtered-host-lookup",
        data={"host": "localhost\necho NEWLINE_BYPASS_PROOF"},
    )
    assert response.status_code == 200
    assert b"Blocked: hostname contains a disallowed character." not in response.data
    assert b"NEWLINE_BYPASS_PROOF" in response.data


def test_filtered_host_lookup_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post(
        "/a03/filtered-host-lookup",
        data={"host": "localhost\necho NEWLINE_BYPASS_PROOF"},
    )
    assert response.status_code == 200
    assert b"NEWLINE_BYPASS_PROOF" in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_filtered_host_lookup_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Hostname Lookup Filter Bypass" in response.data
    assert b'href="/a03/filtered-host-lookup"' in response.data
