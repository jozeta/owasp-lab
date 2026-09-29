from app.core.seed import seed_database


def test_switch_user_page_still_renders(app, client):
    seed_database(app)
    response = client.get("/switch-user")
    assert response.status_code == 200
    assert b"Choose Who You're Logged In As" in response.data


def test_settings_page_still_renders(app, client):
    seed_database(app)
    response = client.get("/settings")
    assert response.status_code == 200


def test_tools_page_still_renders(app, client):
    seed_database(app)
    response = client.get("/tools")
    assert response.status_code == 200


def test_about_page_still_renders(app, client):
    seed_database(app)
    response = client.get("/about")
    assert response.status_code == 200
