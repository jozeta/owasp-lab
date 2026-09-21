import os

from app import BASE_DIR


def test_notification_preferences_page_renders(client):
    response = client.get("/a06/notification-preferences")
    assert response.status_code == 200
    body = response.data.decode()
    assert "prefs-json" in body
    assert "vendor/lodash-vulnerable/lodash-4.17.11.js" in body


def test_notification_preferences_wires_up_the_vulnerable_defaults_deep_call(client):
    response = client.get("/a06/notification-preferences")
    body = response.data.decode()
    assert "vendor/lodash-vulnerable/lodash-4.17.11.js" in body
    assert "_.defaultsDeep({}, DEFAULT_PREFS, userPrefs)" in body
    assert "vendor/lodash-vulnerable/lodash-4.17.12" not in body


def test_vendored_lodash_file_is_present_and_substantial():
    path = os.path.join(BASE_DIR, "static", "vendor", "lodash-vulnerable", "lodash-4.17.11.js")
    assert os.path.getsize(path) > 300_000, "vendored lodash file looks truncated or missing"
    with open(path, encoding="utf-8") as f:
        header = f.read(300)
    assert "lodash" in header.lower()


def test_vendored_lodash_file_is_the_real_vulnerable_release():
    path = os.path.join(BASE_DIR, "static", "vendor", "lodash-vulnerable", "lodash-4.17.11.js")
    with open(path, encoding="utf-8") as f:
        contents = f.read()
    assert "var VERSION = '4.17.11';" in contents


def test_vendored_lodash_is_served_and_is_the_real_vulnerable_version(client):
    response = client.get("/static/vendor/lodash-vulnerable/lodash-4.17.11.js")
    assert response.status_code == 200
    assert b"var VERSION = '4.17.11';" in response.data
