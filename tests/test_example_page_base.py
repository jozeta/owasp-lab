from app.core.models import Settings
from app.extensions import db


def test_example_page_shows_vulnerable_vs_secure_with_both_toggles_off(app, client, login):
    login("alice")
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get("/a01/profile/1")
    assert response.status_code == 200
    body = response.data.decode()
    assert "Vulnerable vs. Secure" in body
    assert "Vulnerable" in body
    assert "Secure" in body


def test_example_page_hides_detect_with_exploit_instructions_off(app, client, login):
    login("alice")
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = True
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get("/a01/profile/1")
    assert response.status_code == 200
    assert b"Detect" not in response.data


def test_example_page_shows_detect_with_exploit_instructions_on(app, client, login):
    login("alice")
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = True
        settings.show_exploit_instructions = True
        db.session.commit()

    response = client.get("/a01/profile/1")
    assert response.status_code == 200
    assert b"Detect" in response.data
