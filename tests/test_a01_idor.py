from app.core.models import Settings, User
from app.extensions import db


def test_idor_requires_login(client):
    response = client.get("/a01/profile/1")
    assert response.status_code == 302
    assert "/switch-user" in response.headers["Location"]


def test_idor_exposes_another_users_private_notes(app, client, login):
    login("alice")
    with app.app_context():
        bob = User.query.filter_by(username="bob").first()
        bob_id = bob.id
        bob_notes = bob.private_notes

    response = client.get(f"/a01/profile/{bob_id}")
    assert response.status_code == 200
    assert bob_notes.encode() in response.data


def test_idor_still_leaks_data_with_teaching_text_hidden(app, client, login):
    login("alice")
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

        bob = User.query.filter_by(username="bob").first()
        bob_id = bob.id
        bob_notes = bob.private_notes

    response = client.get(f"/a01/profile/{bob_id}")
    assert response.status_code == 200
    assert bob_notes.encode() in response.data
    assert b"textbook Insecure Direct" not in response.data
    assert b"Change the URL to a different id" not in response.data


def test_idor_link_appears_in_overview_once_registered(client):
    response = client.get("/a01/")
    assert response.status_code == 200
    assert b"View Another User" in response.data
    assert b"Profile (IDOR)" in response.data
    assert b'href="/a01/profile' in response.data


def test_idor_shows_vulnerable_vs_secure_with_teaching_text_hidden(app, client, login):
    from app.core.models import Settings

    login("alice")
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get("/a01/profile/1")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"abort(403)" in response.data


def test_idor_shows_detect_content(app, client, login):
    login("alice")
    with app.app_context():
        settings = Settings.get()
        settings.show_exploit_instructions = True
        db.session.commit()
    response = client.get("/a01/profile/1")
    assert response.status_code == 200
    assert b"200 OK" in response.data
