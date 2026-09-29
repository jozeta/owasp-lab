from app.core.models import Settings
from app.core.seed import seed_database
from app.extensions import db


def test_stat_strip_has_three_tiles_when_scoring_enabled(app, client):
    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.scoring_enabled = True
        db.session.commit()

    response = client.get("/")
    body = response.data.decode()
    assert 'class="stat-strip"' in body
    assert "stat-strip-2col" not in body
    assert "Score" in body


def test_stat_strip_has_two_tiles_when_scoring_disabled(app, client):
    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.scoring_enabled = False
        db.session.commit()

    response = client.get("/")
    body = response.data.decode()
    assert 'class="stat-strip stat-strip-2col"' in body
    assert "Score" not in body


def test_nav_category_links_use_the_quiet_navcat_style(app, client):
    seed_database(app)
    response = client.get("/")
    assert b'class="nav-link navcat-link' in response.data
