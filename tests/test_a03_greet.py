def test_greet_default_message(client):
    response = client.get("/a03/greet")
    assert response.status_code == 200
    assert b"Hello, friend!" in response.data


def test_greet_reflects_unescaped_script(client):
    response = client.get("/a03/greet", query_string={"name": "<script>alert(1)</script>"})
    assert response.status_code == 200
    assert b"<script>alert(1)</script>" in response.data


def test_greet_xss_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get("/a03/greet", query_string={"name": "<script>alert(1)</script>"})
    assert response.status_code == 200
    assert b"<script>alert(1)</script>" in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_greet_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Reflected XSS in Greeting Page" in response.data
    assert b'href="/a03/greet"' in response.data


def test_greet_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a03/greet")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"autoescaping" in response.data


def test_greet_shows_detect_content(client):
    response = client.get("/a03/greet")
    assert response.status_code == 200
    assert b"before ever running JavaScript" in response.data
