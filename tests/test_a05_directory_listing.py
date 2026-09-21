def test_directory_listing_teaching_page_loads(client):
    response = client.get("/a05/directory-listing")
    assert response.status_code == 200
    assert b"Directory Listing Exposed" in response.data


def test_uploads_index_lists_every_filename(client):
    response = client.get("/a05/uploads/")
    assert response.status_code == 200
    assert b'<a href="/a05/uploads/Q3_payroll_export.csv">Q3_payroll_export.csv</a>' in response.data
    assert b'<a href="/a05/uploads/meeting_notes.txt">meeting_notes.txt</a>' in response.data
    assert b'<a href="/a05/uploads/site_backup_old.zip">site_backup_old.zip</a>' in response.data


def test_uploads_payroll_file_leaks_sensitive_data(client):
    response = client.get("/a05/uploads/Q3_payroll_export.csv")
    assert response.status_code == 200
    assert b"412-88-7734" in response.data
    assert b"Dana Whitfield" in response.data


def test_uploads_unknown_filename_404s(client):
    response = client.get("/a05/uploads/does-not-exist.txt")
    assert response.status_code == 404


def test_directory_listing_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get("/a05/uploads/")
    assert response.status_code == 200
    assert b"Q3_payroll_export.csv" in response.data

    page_response = client.get("/a05/directory-listing")
    assert page_response.status_code == 200
    assert b"Explanation" not in page_response.data
    assert b"Exploitation" not in page_response.data


def test_directory_listing_link_appears_in_overview_once_registered(client):
    response = client.get("/a05/")
    assert response.status_code == 200
    assert b"Directory Listing Exposed" in response.data
    assert b'href="/a05/directory-listing"' in response.data
