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


def test_anonymous_visitor_sees_no_earned_badges(app, client):
    seed_database(app)
    response = client.get("/")
    assert b"text-bg-success" not in response.data


def test_completing_a_whole_category_shows_its_badge(app, client):
    seed_database(app)
    user_id = _login_as(client, app, "alice")
    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")

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


def test_partial_category_completion_shows_no_badge_for_it(app, client):
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
    assert b"text-bg-success" not in response.data
