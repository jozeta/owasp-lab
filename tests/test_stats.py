from datetime import datetime, timedelta

from app.core.models import ActivityDay, ExampleProgress, User
from app.core.nav import CATEGORIES
from app.core.seed import seed_database
from app.core.stats import compute_user_stats
from app.extensions import db


def _user_id(app, username):
    with app.app_context():
        return User.query.filter_by(username=username).first().id


def _a10_examples():
    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")
    return a10.examples


def test_no_progress_gives_zeroed_stats(app):
    seed_database(app)
    user_id = _user_id(app, "alice")

    with app.app_context():
        stats = compute_user_stats(user_id)

    assert stats == {
        "completed_total": 0,
        "score_total": 0,
        "streak_days": 0,
        "badges": {},
        "last_active": None,
    }


def test_completing_every_example_in_a_category_earns_its_badge(app):
    seed_database(app)
    user_id = _user_id(app, "alice")
    examples = _a10_examples()
    assert len(examples) == 5  # sanity-check the fixture assumption

    with app.app_context():
        base_time = datetime(2026, 1, 1, 12, 0, 0)
        for i, example in enumerate(examples):
            db.session.add(
                ExampleProgress(
                    user_id=user_id,
                    example_id=example.id,
                    completed_at=base_time + timedelta(minutes=i),
                    points_awarded=example.base_points(),
                )
            )
        db.session.commit()

        stats = compute_user_stats(user_id)

    assert stats["completed_total"] == 5
    assert stats["score_total"] == sum(e.base_points() for e in examples)
    assert "a10_ssrf" in stats["badges"]
    # earned_at is the LATEST completion among the category's examples --
    # that's the 5th (index 4) example, base_time + 4 minutes.
    assert stats["badges"]["a10_ssrf"] == base_time + timedelta(minutes=4)


def test_partial_category_completion_earns_no_badge(app):
    seed_database(app)
    user_id = _user_id(app, "alice")
    examples = _a10_examples()

    with app.app_context():
        db.session.add(
            ExampleProgress(
                user_id=user_id,
                example_id=examples[0].id,
                completed_at=datetime.utcnow(),
                points_awarded=examples[0].base_points(),
            )
        )
        db.session.commit()

        stats = compute_user_stats(user_id)

    assert stats["badges"] == {}


def test_streak_counts_today(app):
    seed_database(app)
    user_id = _user_id(app, "alice")

    with app.app_context():
        db.session.add(ActivityDay(user_id=user_id, date=datetime.utcnow().date()))
        db.session.commit()

        stats = compute_user_stats(user_id)

    assert stats["streak_days"] == 1
    assert stats["last_active"] == datetime.utcnow().date()


def test_streak_stays_active_with_only_yesterday(app):
    seed_database(app)
    user_id = _user_id(app, "alice")
    yesterday = datetime.utcnow().date() - timedelta(days=1)

    with app.app_context():
        db.session.add(ActivityDay(user_id=user_id, date=yesterday))
        db.session.commit()

        stats = compute_user_stats(user_id)

    assert stats["streak_days"] == 1


def test_streak_counts_consecutive_days_ending_yesterday(app):
    seed_database(app)
    user_id = _user_id(app, "alice")
    today = datetime.utcnow().date()

    with app.app_context():
        for offset in (1, 2, 3):
            db.session.add(ActivityDay(user_id=user_id, date=today - timedelta(days=offset)))
        db.session.commit()

        stats = compute_user_stats(user_id)

    assert stats["streak_days"] == 3


def test_streak_resets_after_a_gap(app):
    seed_database(app)
    user_id = _user_id(app, "alice")
    today = datetime.utcnow().date()

    with app.app_context():
        db.session.add(ActivityDay(user_id=user_id, date=today))
        db.session.add(ActivityDay(user_id=user_id, date=today - timedelta(days=1)))
        # Gap at day 2 -- day 3 is stale and must not extend the streak.
        db.session.add(ActivityDay(user_id=user_id, date=today - timedelta(days=3)))
        db.session.commit()

        stats = compute_user_stats(user_id)

    assert stats["streak_days"] == 2


def test_zero_streak_when_last_activity_is_two_or_more_days_ago(app):
    seed_database(app)
    user_id = _user_id(app, "alice")
    today = datetime.utcnow().date()

    with app.app_context():
        db.session.add(ActivityDay(user_id=user_id, date=today - timedelta(days=2)))
        db.session.commit()

        stats = compute_user_stats(user_id)

    assert stats["streak_days"] == 0


def test_compute_user_stats_runs_at_most_two_queries(app):
    """Query-efficiency requirement: one query for ExampleProgress rows, one
    for ActivityDay rows, regardless of how many categories exist -- never
    one query per category."""
    seed_database(app)
    user_id = _user_id(app, "alice")

    with app.app_context():
        queries = []
        from sqlalchemy import event

        from app.extensions import db as _db

        def _count(*args, **kwargs):
            queries.append(1)

        event.listen(_db.engine, "before_cursor_execute", _count)
        try:
            compute_user_stats(user_id)
        finally:
            event.remove(_db.engine, "before_cursor_execute", _count)

    assert len(queries) <= 2
