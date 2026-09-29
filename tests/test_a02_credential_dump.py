import hashlib

from app.core.seed import seed_database


def test_credential_dump_lists_all_legacy_credentials(app, client):
    seed_database(app)

    response = client.get("/a02/credential-dump")
    assert response.status_code == 200
    assert b"alice" in response.data
    assert b"admin" in response.data

    admin_hash = hashlib.md5(b"admin-training-pw1").hexdigest()
    assert admin_hash.encode() in response.data


def test_credential_dump_link_appears_in_overview_once_registered(client):
    response = client.get("/a02/")
    assert response.status_code == 200
    assert b"Leaked Credential Dump" in response.data
    assert b'href="/a02/credential-dump"' in response.data


def test_credential_dump_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get("/a02/credential-dump")
    assert response.status_code == 200
    assert b"admin" in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_credential_dump_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a02/credential-dump")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"generate_password_hash" in response.data


def test_credential_dump_shows_detect_content(app, client):
    with app.app_context():
        from app.core.models import Settings
        from app.extensions import db

        settings = Settings.get()
        settings.show_exploit_instructions = True
        settings.scoring_enabled = False
        db.session.commit()
    response = client.get("/a02/credential-dump")
    assert response.status_code == 200
    assert b"signature of raw MD5" in response.data
