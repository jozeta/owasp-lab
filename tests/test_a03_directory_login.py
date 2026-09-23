def test_directory_login_succeeds_with_correct_credentials(client, mock_ldap):
    response = client.post(
        "/a03/directory-login", data={"username": "alice", "password": "alice123"}
    )
    assert response.status_code == 200
    assert b"Alice Example" in response.data


def test_directory_login_fails_with_wrong_password(client, mock_ldap):
    response = client.post(
        "/a03/directory-login", data={"username": "alice", "password": "wrongpass"}
    )
    assert response.status_code == 200
    assert b"Invalid username or password" in response.data


def test_directory_login_wildcard_password_bypasses_authentication(client, mock_ldap):
    response = client.post(
        "/a03/directory-login", data={"username": "root_admin", "password": "*"}
    )
    assert response.status_code == 200
    assert b"Root Administrator" in response.data


def test_directory_login_secure_pattern_neutralizes_wildcard_bypass(mock_ldap):
    from ldap3 import SUBTREE
    from ldap3.utils.conv import escape_filter_chars

    from app.categories.a03_injection import ldap_client

    safe_password = escape_filter_chars("*")
    filt = f"(&(uid=root_admin)(userPassword={safe_password}))"
    conn = ldap_client.get_ldap_connection()
    conn.search(ldap_client.LDAP_BASE_DN, filt, SUBTREE, attributes=["cn"])
    entries = list(conn.entries)
    conn.unbind()
    assert entries == []


def test_directory_login_still_works_with_teaching_text_hidden(app, client, mock_ldap):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post(
        "/a03/directory-login", data={"username": "alice", "password": "alice123"}
    )
    assert response.status_code == 200
    assert b"Alice Example" in response.data
    assert b"Vulnerable vs. Secure" in response.data
    assert b'<div class="card-header">Detect</div>' not in response.data


def test_directory_login_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"LDAP Injection" in response.data
    assert b'href="/a03/directory-login"' in response.data
