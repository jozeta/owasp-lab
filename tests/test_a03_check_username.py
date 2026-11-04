import pytest
from sqlalchemy.exc import DBAPIError

from app.core.seed import seed_database


def test_check_username_response_is_identical_for_unknown_and_known_user(app, client):
    seed_database(app)

    unknown_response = client.get(
        "/a03/check-username", query_string={"username": "definitely-not-a-real-user"}
    )
    known_response = client.get("/a03/check-username", query_string={"username": "alice"})

    assert unknown_response.status_code == 200
    assert known_response.status_code == 200
    # Check against the exact removed oracle phrases, not a bare "available"
    # substring match -- base.html's unrelated theme-detection script
    # contains the literal word "unavailable" ("localStorage unavailable")
    # on every page in this app, which would make a loose substring check
    # a false positive here.
    assert b"is <strong>available</strong>" not in unknown_response.data
    assert b"already taken" not in known_response.data.lower()
    assert b"Checked." in unknown_response.data
    assert b"Checked." in known_response.data


def test_check_username_still_executes_raw_sql_unparameterized(app, client):
    # The injection point itself must remain genuinely vulnerable -- only
    # the visible available/taken signal was removed. A lone unescaped
    # quote breaks the raw concatenated query, proving it's still built
    # by string concatenation, not bound parameters. Under Flask's TESTING
    # config, an unhandled exception propagates to the test client caller
    # directly (verified empirically: TESTING=True disables Flask's
    # default exception-to-500 conversion, same as test_a03_roster.py's
    # column-count-discovery test) rather than becoming a 500 response --
    # so this asserts on the raised exception, not a response object.
    seed_database(app)
    with pytest.raises(DBAPIError):
        client.get("/a03/check-username", query_string={"username": "o'brien"})


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
    assert b"Checked." in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_check_username_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Blind Time-Based SQL Injection" in response.data
    assert b'href="/a03/check-username"' in response.data


def test_check_username_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a03/check-username")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b":username" in response.data


def test_check_username_shows_detect_content(app, client):
    with app.app_context():
        from app.core.models import Settings
        from app.extensions import db

        settings = Settings.get()
        settings.show_exploit_instructions = True
        settings.scoring_enabled = False
        db.session.commit()
    response = client.get("/a03/check-username")
    assert response.status_code == 200
    assert b"Enter a single quote on its own" in response.data
