def test_admin_tools_panel_page_renders(client):
    response = client.get("/a06/admin-tools-panel")
    assert response.status_code == 200
    body = response.data.decode()
    assert "admin-tools-panel" in body
    assert "vendor/lodash-vulnerable/lodash-4.17.11.js" in body


def test_admin_tools_panel_is_hidden_by_default(client):
    response = client.get("/a06/admin-tools-panel")
    body = response.data.decode()
    assert 'id="admin-tools-panel"' in body
    assert 'style="display:none"' in body


def test_admin_tools_panel_wires_up_the_same_vulnerable_defaults_deep_call(client):
    response = client.get("/a06/admin-tools-panel")
    body = response.data.decode()
    assert "vendor/lodash-vulnerable/lodash-4.17.11.js" in body
    assert "_.defaultsDeep({}, DEFAULT_PREFS, userPrefs)" in body
    assert "checkAdminAccess" in body
