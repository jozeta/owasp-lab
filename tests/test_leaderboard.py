from app.core.models import ExampleProgress, Settings, User
from app.core.seed import seed_database
from app.extensions import db
from datetime import datetime


def _login_as(client, app, username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        user_id = user.id
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
    return user_id


def test_leaderboard_loads_without_login(app, client):
    seed_database(app)
    response = client.get("/leaderboard")
    assert response.status_code == 200
    assert b"Leaderboard" in response.data


def test_leaderboard_lists_every_seeded_user(app, client):
    seed_database(app)
    response = client.get("/leaderboard")
    body = response.data.decode()
    for username in ("alice", "bob", "carol", "admin"):
        assert username in body


def test_leaderboard_sort_completed_orders_by_completions_desc(app, client):
    seed_database(app)
    alice_id = _login_as(client, app, "alice")

    with app.app_context():
        db.session.add(
            ExampleProgress(
                user_id=alice_id,
                example_id="sqli-login",
                completed_at=datetime.utcnow(),
                points_awarded=10,
            )
        )
        db.session.commit()

    response = client.get("/leaderboard?sort=completed")
    body = response.data.decode()
    assert body.index("alice") < body.index("bob")


def test_leaderboard_invalid_sort_falls_back_to_completed(app, client):
    seed_database(app)
    response = client.get("/leaderboard?sort=not-a-real-sort")
    assert response.status_code == 200


def test_leaderboard_hides_score_column_when_scoring_disabled(app, client):
    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.scoring_enabled = False
        db.session.commit()

    response = client.get("/leaderboard")
    assert b"Score" not in response.data


def test_leaderboard_shows_score_column_when_scoring_enabled(app, client):
    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.scoring_enabled = True
        db.session.commit()

    response = client.get("/leaderboard")
    assert b"Score" in response.data
