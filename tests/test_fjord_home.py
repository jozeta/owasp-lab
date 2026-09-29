from app.core.seed import seed_database


def test_home_page_category_cards_have_icons(app, client):
    seed_database(app)
    response = client.get("/")
    body = response.data.decode()
    for n in range(1, 11):
        assert f"#icon-a{n:02d}" in body


def test_home_page_category_cards_have_dash_card_class(app, client):
    seed_database(app)
    response = client.get("/")
    assert b"dash-card" in response.data


def test_home_page_progress_bars_animate_on_load(app, client):
    seed_database(app)
    response = client.get("/")
    assert b"fjord-fill" in response.data
