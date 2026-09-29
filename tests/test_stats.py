from datetime import datetime, timedelta

from app.core.models import ActivityDay, ExampleProgress
from app.core.nav import CATEGORIES
from app.core.seed import seed_database
from app.core.stats import compute_stats
from app.extensions import db


def _a10_examples():
    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")
    return a10.examples


def test_no_progress_gives_zeroed_stats(app):
    seed_database(app)

    with app.app_context():
        stats = compute_stats()

    assert stats == {
        "completed_total": 0,
        "score_total": 0,
        "streak_days": 0,
        "last_active": None,
    }


def test_streak_counts_today(app):
    seed_database(app)

    with app.app_context():
        db.session.add(ActivityDay(date=datetime.utcnow().date()))
        db.session.commit()

        stats = compute_stats()

    assert stats["streak_days"] == 1
    assert stats["last_active"] == datetime.utcnow().date()


def test_streak_stays_active_with_only_yesterday(app):
    seed_database(app)
    yesterday = datetime.utcnow().date() - timedelta(days=1)

    with app.app_context():
        db.session.add(ActivityDay(date=yesterday))
        db.session.commit()

        stats = compute_stats()

    assert stats["streak_days"] == 1


def test_streak_counts_consecutive_days_ending_yesterday(app):
    seed_database(app)
    today = datetime.utcnow().date()

    with app.app_context():
        for offset in (1, 2, 3):
            db.session.add(ActivityDay(date=today - timedelta(days=offset)))
        db.session.commit()

        stats = compute_stats()

    assert stats["streak_days"] == 3


def test_streak_resets_after_a_gap(app):
    seed_database(app)
    today = datetime.utcnow().date()

    with app.app_context():
        db.session.add(ActivityDay(date=today))
        db.session.add(ActivityDay(date=today - timedelta(days=1)))
        # Gap at day 2 -- day 3 is stale and must not extend the streak.
        db.session.add(ActivityDay(date=today - timedelta(days=3)))
        db.session.commit()

        stats = compute_stats()

    assert stats["streak_days"] == 2


def test_zero_streak_when_last_activity_is_two_or_more_days_ago(app):
    seed_database(app)
    today = datetime.utcnow().date()

    with app.app_context():
        db.session.add(ActivityDay(date=today - timedelta(days=2)))
        db.session.commit()

        stats = compute_stats()

    assert stats["streak_days"] == 0


def test_compute_stats_runs_at_most_two_queries(app):
    """Query-efficiency requirement: one query for ExampleProgress rows, one
    for ActivityDay rows, regardless of how many categories exist -- never
    one query per category."""
    seed_database(app)

    with app.app_context():
        queries = []
        from sqlalchemy import event

        from app.extensions import db as _db

        def _count(*args, **kwargs):
            queries.append(1)

        event.listen(_db.engine, "before_cursor_execute", _count)
        try:
            compute_stats()
        finally:
            event.remove(_db.engine, "before_cursor_execute", _count)

    assert len(queries) <= 2
