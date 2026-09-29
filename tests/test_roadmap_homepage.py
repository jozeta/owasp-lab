from datetime import datetime

from app.core.models import ExampleProgress, User
from app.core.nav import CATEGORIES
from app.core.seed import seed_database
from app.extensions import db


def _login_as(client, app, username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        user_id = user.id
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
    return user_id


def test_home_page_has_roadmap_with_all_ten_nodes(app, client):
    seed_database(app)
    response = client.get("/")
    body = response.data.decode()
    assert '<div class="roadmap">' in body
    assert body.count('class="roadmap-node"') == 10


def test_roadmap_nodes_link_to_their_overview_pages(app, client):
    seed_database(app)
    response = client.get("/")
    body = response.data.decode()
    for category in CATEGORIES:
        assert f'href="/{category.short_id.lower()}/"' in body


def test_roadmap_node_shows_correct_percent_and_icon(app, client):
    seed_database(app)
    user_id = _login_as(client, app, "alice")
    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")

    with app.app_context():
        db.session.add(
            ExampleProgress(
                user_id=user_id,
                example_id=a10.examples[0].id,
                completed_at=datetime.utcnow(),
                points_awarded=a10.examples[0].base_points(),
            )
        )
        db.session.commit()

    response = client.get("/")
    body = response.data.decode()
    expected_percent = round(1 / len(a10.examples) * 100)
    assert f"--pct: {expected_percent}" in body
    assert "#icon-a10" in body


def test_roadmap_shows_badge_marker_only_when_earned(app, client):
    seed_database(app)
    user_id = _login_as(client, app, "alice")
    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")

    response = client.get("/")
    assert b"text-bg-success" not in response.data

    with app.app_context():
        for example in a10.examples:
            db.session.add(
                ExampleProgress(
                    user_id=user_id,
                    example_id=example.id,
                    completed_at=datetime.utcnow(),
                    points_awarded=example.base_points(),
                )
            )
        db.session.commit()

    response = client.get("/")
    assert b"text-bg-success" in response.data


def test_roadmap_track_fill_reflects_overall_percent(app, client):
    seed_database(app)
    response = client.get("/")
    assert b'class="roadmap-track-fill" style="height: 0%"' in response.data
