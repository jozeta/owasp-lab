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


def test_log_exposure_demo_plants_a_secret_in_the_log_file(client):
    response = client.get("/a09/log-exposure-demo")
    assert response.status_code == 200

    with open(LOG_FILE_PATH) as f:
        log_contents = f.read()
    assert "PLANTED-DEMO-SECRET" in log_contents


def test_download_log_route_requires_no_authentication(client):
    client.get("/a09/log-exposure-demo")

    response = client.get("/a09/download-log")
    assert response.status_code == 200
    assert b"PLANTED-DEMO-SECRET" in response.data


def test_log_file_world_readable_link_appears_in_overview_once_registered(client):
    response = client.get("/a09/")
    assert response.status_code == 200
    assert b"Unauthenticated Log File Exposure" in response.data
    assert b'href="/a09/log-exposure-demo"' in response.data
