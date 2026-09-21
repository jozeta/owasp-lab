def test_backup_exposure_teaching_page_loads(client):
    response = client.get("/a05/backup-exposure")
    assert response.status_code == 200
    assert b"Exposed Database Backup File" in response.data


def test_backup_file_is_downloadable_with_no_auth(client):
    response = client.get("/a05/backups/db_backup_2024-01-15.sql.bak")
    assert response.status_code == 200
    assert b"DATABASE_URL" in response.data
    assert b"postgresql://app_prod:Tr0ub4dor&3@10.0.4.12:5432/storefront" in response.data
    assert b"STRIPE_SECRET_KEY" in response.data
    assert b"sk_live_51MisconfigDemoFakeKey000111222" in response.data


def test_backup_exposure_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get("/a05/backups/db_backup_2024-01-15.sql.bak")
    assert response.status_code == 200
    assert b"sk_live_51MisconfigDemoFakeKey000111222" in response.data

    page_response = client.get("/a05/backup-exposure")
    assert page_response.status_code == 200
    assert b"Explanation" not in page_response.data
    assert b"Exploitation" not in page_response.data


def test_backup_exposure_link_appears_in_overview_once_registered(client):
    response = client.get("/a05/")
    assert response.status_code == 200
    assert b"Exposed Database Backup File" in response.data
    assert b'href="/a05/backup-exposure"' in response.data
