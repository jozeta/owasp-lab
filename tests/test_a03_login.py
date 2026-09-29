from app.core.seed import seed_database


def test_login_with_correct_credentials_succeeds(app, client):
    seed_database(app)
    response = client.post(
        "/a03/login", data={"username": "alice", "password": "alice123"}, follow_redirects=True
    )
    assert response.status_code == 200
    assert b"Logged in as <strong>alice</strong>" in response.data


def test_login_rejects_wrong_password(app, client):
    seed_database(app)
    response = client.post(
        "/a03/login", data={"username": "alice", "password": "wrong"}, follow_redirects=True
    )
    assert response.status_code == 200
    assert b"Invalid username or password" in response.data


def test_login_sqli_bypasses_authentication(app, client):
    seed_database(app)
    response = client.post(
        "/a03/login",
        data={"username": "' OR '1'='1' -- ", "password": "anything"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"authentication bypassed" in response.data.lower()


def test_login_sqli_as_admin_via_comment(app, client):
    seed_database(app)
    response = client.post(
        "/a03/login",
        data={"username": "admin' -- ", "password": "anything"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Logged in as <strong>admin</strong> (admin)" in response.data


def test_login_sqli_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post(
        "/a03/login",
        data={"username": "' OR '1'='1' -- ", "password": "anything"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"authentication bypassed" in response.data.lower()
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_login_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Authentication Bypass via SQL Injection" in response.data
    assert b'href="/a03/login"' in response.data


def test_login_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a03/login")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b":username AND password = :password" in response.data


def test_login_shows_detect_content(app, client):
    with app.app_context():
        from app.core.models import Settings
        from app.extensions import db

        settings = Settings.get()
        settings.show_exploit_instructions = True
        settings.scoring_enabled = False
        db.session.commit()
    response = client.get("/a03/login")
    assert response.status_code == 200
    assert b"username containing a single quote" in response.data
