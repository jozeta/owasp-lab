import os

from app import BASE_DIR


def test_legacy_widgets_page_renders(client):
    response = client.get("/a06/legacy-widgets")
    assert response.status_code == 200
    assert b"jquery-1.12.4.js" in response.data


def test_vendored_jquery_is_served_and_is_the_real_vulnerable_version(client):
    response = client.get("/static/vendor/jquery-vulnerable/jquery-1.12.4.js")
    assert response.status_code == 200
    assert b"jQuery JavaScript Library v1.12.4" in response.data


def test_vendored_jquery_file_on_disk_matches_the_vulnerable_release():
    path = os.path.join(BASE_DIR, "static", "vendor", "jquery-vulnerable", "jquery-1.12.4.js")
    with open(path, encoding="utf-8") as f:
        header = f.read(200)
    assert "jQuery JavaScript Library v1.12.4" in header
