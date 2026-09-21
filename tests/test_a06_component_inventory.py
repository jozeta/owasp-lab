from importlib.metadata import version


def test_component_inventory_renders(client):
    response = client.get("/a06/component-inventory")
    assert response.status_code == 200
    body = response.data.decode()
    assert "jQuery (Legacy Widgets bundle)" in body
    assert "1.12.4" in body
    assert "Lodash (Legacy Widgets bundle)" in body
    assert "4.17.11" in body


def test_component_inventory_shows_the_real_installed_flask_version(client):
    response = client.get("/a06/component-inventory")
    body = response.data.decode()
    assert version("flask") in body
