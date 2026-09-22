import os

import pytest

from app.categories.a09_logging_monitoring_failures.routes import LOG_FILE_PATH


@pytest.fixture(autouse=True)
def _clean_log_file():
    # LOG_FILE_PATH is a real file on disk, not wiped by the in-memory test
    # DB -- clean it before and after every test in this file so tests
    # never see another test's leftover content. This fixture is local to
    # this test file, not tests/conftest.py, which stays off-limits.
    if os.path.exists(LOG_FILE_PATH):
        os.remove(LOG_FILE_PATH)
    yield
    if os.path.exists(LOG_FILE_PATH):
        os.remove(LOG_FILE_PATH)


def _read_log_file():
    if not os.path.exists(LOG_FILE_PATH):
        return ""
    with open(LOG_FILE_PATH) as f:
        return f.read()


def test_support_login_succeeds_with_correct_credentials(client):
    response = client.post(
        "/a09/support-login", data={"username": "support", "password": "letmein123"}
    )
    assert response.status_code == 200
    assert b"Invalid username or password" not in response.data


def test_failed_support_login_leaks_plaintext_password_to_log_file(client):
    marker_password = "test-marker-9f3c2b1a-do-not-reuse"
    client.post(
        "/a09/support-login",
        data={"username": "attacker", "password": marker_password},
    )

    log_contents = _read_log_file()
    assert marker_password in log_contents

    response = client.get("/a09/security-events")
    assert marker_password.encode() in response.data


def test_sensitive_data_in_logs_link_appears_in_overview_once_registered(client):
    response = client.get("/a09/")
    assert response.status_code == 200
    assert b"Sensitive Data Leaked Into Log Files" in response.data
    assert b'href="/a09/support-login"' in response.data
