import os

import pytest

from app.categories.a03_injection.routes import ARGUMENT_INJECTION_PROOF_PATH


@pytest.fixture(autouse=True)
def _clean_proof_file():
    if os.path.exists(ARGUMENT_INJECTION_PROOF_PATH):
        os.remove(ARGUMENT_INJECTION_PROOF_PATH)
    yield
    if os.path.exists(ARGUMENT_INJECTION_PROOF_PATH):
        os.remove(ARGUMENT_INJECTION_PROOF_PATH)


def test_export_archive_page_renders(client):
    response = client.get("/a03/export-archive")
    assert response.status_code == 200
    assert b"Argument Injection" in response.data


def test_ordinary_filename_creates_archive_without_injection(client):
    response = client.post("/a03/export-archive", data={"filename": "notes.txt"})
    assert response.status_code == 200
    assert "uid=" not in response.data.decode()
    assert not os.path.exists(ARGUMENT_INJECTION_PROOF_PATH)


def test_argument_injection_via_use_compress_program_executes_real_command(client):
    payload = '--use-compress-program=sh -c "id > /tmp/a03_argument_injection_proof.txt"'

    response = client.post("/a03/export-archive", data={"filename": payload})
    assert response.status_code == 200

    # the injected command genuinely executed on the real filesystem --
    # not merely that the route accepted the input without erroring
    assert os.path.exists(ARGUMENT_INJECTION_PROOF_PATH)
    with open(ARGUMENT_INJECTION_PROOF_PATH) as f:
        proof_content = f.read()
    assert "uid=" in proof_content

    body = response.data.decode()
    assert "uid=" in body
