def test_admin_login_page_loads(client):
    response = client.get("/a05/admin-login")
    assert response.status_code == 200
    assert b"Forgotten Admin Panel with Default Credentials" in response.data


def test_admin_login_rejects_wrong_credentials(client):
    response = client.post(
        "/a05/admin-login", data={"username": "admin", "password": "wrong"}
    )
    assert response.status_code == 200
    assert b"Invalid username or password." in response.data


def test_admin_login_accepts_default_credentials_and_grants_access(client):
    response = client.post(
        "/a05/admin-login",
        data={"username": "admin", "password": "DataVault@2019"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Renata Solis" in response.data
    assert b"childhood pet's name" in response.data


def test_admin_panel_redirects_to_login_when_not_authenticated(client):
    response = client.get("/a05/admin-panel")
    assert response.status_code == 302
    assert response.headers["Location"] == "/a05/admin-login"


def test_admin_login_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post(
        "/a05/admin-login",
        data={"username": "admin", "password": "DataVault@2019"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Renata Solis" in response.data

    page_response = client.get("/a05/admin-login")
    assert page_response.status_code == 200
    assert b"Explanation" not in page_response.data
    assert b"Exploitation" not in page_response.data


def test_admin_login_link_appears_in_overview_once_registered(client):
    response = client.get("/a05/")
    assert response.status_code == 200
    assert b"Forgotten Admin Panel with Default Credentials" in response.data
    assert b'href="/a05/admin-login"' in response.data
