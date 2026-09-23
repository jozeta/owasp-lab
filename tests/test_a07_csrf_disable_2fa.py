from app.core.seed import seed_database


def _complete_real_mfa_login(app, client):
    seed_database(app)
    client.post("/a07/mfa-login", data={"username": "dana", "password": "welcome1"})
    client.post("/a07/mfa-verify", data={"code": "482913"})


def test_mfa_settings_page_renders(client):
    response = client.get("/a07/mfa-settings")
    assert response.status_code == 200
    assert b"CSRF on Disabling 2FA" in response.data


def test_settings_shows_enabled_after_real_mfa_flow(app, client):
    _complete_real_mfa_login(app, client)
    response = client.get("/a07/mfa-settings")
    assert b"currently enabled" in response.data.lower()


def test_disable_form_has_no_csrf_token(app, client):
    _complete_real_mfa_login(app, client)
    response = client.get("/a07/mfa-settings")
    # Checks the actual HTML form field (an `<input name="...">` attribute),
    # not the page's explanatory vulnerable/secure code samples, which
    # legitimately mention "csrf_token" as example Python source text.
    assert b'name="csrf_token"' not in response.data
    assert b'name="csrf"' not in response.data


def test_forged_post_disables_2fa_with_no_token_or_reauth(app, client):
    _complete_real_mfa_login(app, client)

    # Simulates a forged cross-site POST: no CSRF token field at all, no
    # password/code re-confirmation -- just the victim's existing session
    # cookie, which a browser attaches automatically to same-origin AND
    # cross-origin form submissions alike.
    response = client.post("/a07/mfa/disable", follow_redirects=True)
    assert response.status_code == 200

    settings_after = client.get("/a07/mfa-settings")
    assert b"currently enabled" not in settings_after.data.lower()
