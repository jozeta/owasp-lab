from datetime import datetime

from app.core.models import ActivityDay, User
from app.core.nav import CATEGORIES
from app.core.seed import seed_database


def _login_as(client, app, username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        user_id = user.id
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
    return user_id


def _safe_test_example():
    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    return next(e for e in a03.examples if e.id == "sqli-login")


def test_toggle_progress_records_activity_today(app, client):
    seed_database(app)
    example = _safe_test_example()

    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        rows = ActivityDay.query.all()
        assert len(rows) == 1
        assert rows[0].date == datetime.utcnow().date()


def test_toggle_progress_activity_is_idempotent_same_day(app, client):
    seed_database(app)
    example = _safe_test_example()

    client.post("/progress/toggle", data={"example_id": example.id})
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        assert ActivityDay.query.count() == 1


def test_reveal_hint_records_activity_today(app, client):
    seed_database(app)
    example = _safe_test_example()

    client.post("/hints/reveal", data={"example_id": example.id})

    with app.app_context():
        rows = ActivityDay.query.all()
        assert len(rows) == 1
        assert rows[0].date == datetime.utcnow().date()


def test_activity_stays_recorded_once_regardless_of_which_identity_toggles(app, client):
    # The four seeded accounts are fictional identities for exploit
    # purposes, not separate real students -- switching between them mid-day
    # must not create separate activity rows.
    seed_database(app)
    example = _safe_test_example()

    _login_as(client, app, "alice")
    client.post("/progress/toggle", data={"example_id": example.id})

    _login_as(client, app, "bob")
    client.post("/hints/reveal", data={"example_id": example.id})

    with app.app_context():
        assert ActivityDay.query.count() == 1
