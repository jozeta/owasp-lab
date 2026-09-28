from app.core.seed import seed_database


def test_home_page_references_icon_sprite(app, client):
    seed_database(app)
    response = client.get("/")
    assert b"category-icons.svg" in response.data


def test_nav_brand_uses_shield_icon(app, client):
    seed_database(app)
    response = client.get("/")
    assert b"#icon-shield" in response.data


def test_nav_no_longer_forces_bg_dark(app, client):
    seed_database(app)
    response = client.get("/")
    body = response.data.decode()
    assert 'class="navbar navbar-expand-lg bg-dark"' not in body
    assert 'navbar-dark' not in body
