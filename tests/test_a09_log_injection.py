import os

import pytest

from app.categories.a09_logging_monitoring_failures.routes import LOG_FILE_PATH


@pytest.fixture(autouse=True)
def _clean_log_file():
    if os.path.exists(LOG_FILE_PATH):
        os.remove(LOG_FILE_PATH)
    yield
    if os.path.exists(LOG_FILE_PATH):
        os.remove(LOG_FILE_PATH)


def test_update_display_name_page_renders(client):
    response = client.get("/a09/update-display-name")
    assert response.status_code == 200
    assert b"Audit Log Forged" in response.data


def test_plain_display_name_logs_a_single_line(client):
    response = client.post("/a09/update-display-name", data={"display_name": "Johan"})
    assert response.status_code == 200

    log_response = client.get("/a09/download-log")
    assert "display name updated to 'Johan'" in log_response.data.decode()


def test_display_name_with_embedded_newline_forges_an_independent_log_line(client):
    forged_line = "[2026-01-01 00:00:00] ADMIN: granted superuser role to attacker"
    payload = f"Johan\n{forged_line}"

    response = client.post("/a09/update-display-name", data={"display_name": payload})
    assert response.status_code == 200

    log_response = client.get("/a09/download-log")
    log_lines = log_response.data.decode().splitlines()
    # the forged line appears as its OWN, independent line -- not merely
    # as a substring embedded inside the legitimate log entry
    # Note: the line has a trailing quote from the f-string format
    assert forged_line + "'" in log_lines


def test_forged_line_also_visible_via_security_events_dashboard(client):
    forged_line = "[2026-01-01 00:00:00] ADMIN: granted superuser role to attacker"
    payload = f"Johan\n{forged_line}"
    client.post("/a09/update-display-name", data={"display_name": payload})

    response = client.get("/a09/security-events")
    assert forged_line.encode() in response.data
