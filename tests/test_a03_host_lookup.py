def test_host_lookup_accepts_a_host(client):
    response = client.post("/a03/host-lookup", data={"host": "localhost"})
    assert response.status_code == 200


def test_host_lookup_command_injection_executes_arbitrary_command(client):
    response = client.post(
        "/a03/host-lookup", data={"host": "localhost; echo INJECTION_PROOF_12345"}
    )
    assert response.status_code == 200
    assert b"INJECTION_PROOF_12345" in response.data


def test_host_lookup_command_injection_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post(
        "/a03/host-lookup", data={"host": "localhost; echo INJECTION_PROOF_12345"}
    )
    assert response.status_code == 200
    assert b"INJECTION_PROOF_12345" in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_host_lookup_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"OS Command Injection in Host Lookup Tool" in response.data
    assert b'href="/a03/host-lookup"' in response.data


def test_host_lookup_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a03/host-lookup")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"shell=False" in response.data


def test_host_lookup_shows_detect_content(client):
    response = client.get("/a03/host-lookup")
    assert response.status_code == 200
    assert b"without running anything destructive" in response.data
