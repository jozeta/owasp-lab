import string


def test_directory_search_reports_match_for_existing_prefix(client, mock_ldap):
    response = client.post(
        "/a03/directory-search", data={"target": "root_admin", "query": "r"}
    )
    assert response.status_code == 200
    assert b"Match found" in response.data


def test_directory_search_reports_no_match_for_wrong_prefix(client, mock_ldap):
    response = client.post(
        "/a03/directory-search", data={"target": "root_admin", "query": "z"}
    )
    assert response.status_code == 200
    assert b"No match" in response.data


def test_directory_search_blind_extraction_recovers_full_secret(client, mock_ldap):
    alphabet = string.ascii_lowercase + string.digits + "-"
    extracted = ""
    for _ in range(40):
        found_char = None
        for ch in alphabet:
            response = client.post(
                "/a03/directory-search",
                data={"target": "root_admin", "query": extracted + ch},
            )
            if b"Match found" in response.data:
                found_char = ch
                break
        if found_char is None:
            break
        extracted += found_char
    assert extracted == "recovery-code-x7k2p9"


def test_directory_search_secure_pattern_rejects_injection_attempt(mock_ldap):
    from ldap3 import SUBTREE
    from ldap3.utils.conv import escape_filter_chars

    from app.categories.a03_injection import ldap_client

    injected = escape_filter_chars(")(uid=*")
    filt = f"(&(uid=root_admin)(description={injected}*))"
    conn = ldap_client.get_ldap_connection()
    conn.search(ldap_client.LDAP_BASE_DN, filt, SUBTREE, attributes=["uid"])
    entries = list(conn.entries)
    conn.unbind()
    assert entries == []


def test_directory_search_still_works_with_teaching_text_hidden(app, client, mock_ldap):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post(
        "/a03/directory-search", data={"target": "root_admin", "query": "r"}
    )
    assert response.status_code == 200
    assert b"Match found" in response.data
    assert b"Vulnerable vs. Secure" in response.data
    assert b'<div class="card-header">Detect</div>' not in response.data


def test_directory_search_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Blind" in response.data
    assert b'href="/a03/directory-search"' in response.data
