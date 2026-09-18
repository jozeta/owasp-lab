from app.core.seed import seed_database


def test_check_username_reports_available_for_unknown_user(app, client):
    seed_database(app)
    response = client.get(
        "/a03/check-username", query_string={"username": "definitely-not-a-real-user"}
    )
    assert response.status_code == 200
    assert b"available" in response.data.lower()


def test_check_username_reports_taken_for_known_user(app, client):
    seed_database(app)
    response = client.get("/a03/check-username", query_string={"username": "alice"})
    assert response.status_code == 200
    assert b"already taken" in response.data.lower()


def test_check_username_sqli_flips_result_via_boolean_injection(app, client):
    # Proves the raw SQL is injectable using a portable boolean payload.
    # The real exploitation instructions use PostgreSQL's pg_sleep() for a genuine
    # timing side-channel -- that's verified live against Postgres in the plan's
    # final Docker-verification task, not here (SQLite has no pg_sleep).
    seed_database(app)
    payload = "definitely-not-a-real-user' OR '1'='1"
    response = client.get("/a03/check-username", query_string={"username": payload})
    assert response.status_code == 200
    assert b"already taken" in response.data.lower()


def test_check_username_sqli_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    payload = "definitely-not-a-real-user' OR '1'='1"
    response = client.get("/a03/check-username", query_string={"username": payload})
    assert response.status_code == 200
    assert b"already taken" in response.data.lower()
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_check_username_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Blind Time-Based SQL Injection" in response.data
    assert b'href="/a03/check-username"' in response.data
