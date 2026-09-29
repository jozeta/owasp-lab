def test_account_preview_page_renders(client):
    response = client.get("/a06/account-preview")
    assert response.status_code == 200
    body = response.data.decode()
    assert "api-key-value" in body
    assert "sk_live_4f8a2c91b3d7e0f6a1c5" in body
    assert "vendor/jquery-vulnerable/jquery-1.12.4.js" in body


def test_account_preview_wires_up_the_same_vulnerable_html_call(client):
    response = client.get("/a06/account-preview")
    body = response.data.decode()
    assert "vendor/jquery-vulnerable/jquery-1.12.4.js" in body
    assert "$('#comment-preview').html(raw)" in body
    assert "jquery-vulnerable/jquery-3" not in body


def test_account_preview_shows_the_python_collector_command(app, client):
    with app.app_context():
        from app.core.models import Settings
        from app.extensions import db

        settings = Settings.get()
        settings.show_exploit_instructions = True
        settings.scoring_enabled = False
        db.session.commit()
    response = client.get("/a06/account-preview")
    body = response.data.decode()
    assert "python3 -m http.server 9000" in body
