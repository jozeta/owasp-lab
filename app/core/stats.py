from datetime import datetime, timedelta

from app.core.models import ActivityDay, ExampleProgress
from app.core.nav import CATEGORIES


def compute_stats():
    """Completed/score/streak/badge summary for this instance.

    Runs exactly two queries (ExampleProgress, ActivityDay) regardless of
    how many categories or examples exist.
    """
    progress_rows = ExampleProgress.query.all()
    completed_by_id = {
        p.example_id: p for p in progress_rows if p.completed_at is not None
    }
    completed_total = len(completed_by_id)
    score_total = sum(p.points_awarded or 0 for p in completed_by_id.values())

    badges = {}
    for category in CATEGORIES:
        category_example_ids = {e.id for e in category.examples}
        if category_example_ids and category_example_ids.issubset(completed_by_id.keys()):
            badges[category.id] = max(
                completed_by_id[example_id].completed_at
                for example_id in category_example_ids
            )

    activity_dates = {row.date for row in ActivityDay.query.all()}
    streak_days = _compute_streak(activity_dates)
    last_active = max(activity_dates) if activity_dates else None

    return {
        "completed_total": completed_total,
        "score_total": score_total,
        "streak_days": streak_days,
        "badges": badges,
        "last_active": last_active,
    }


def _compute_streak(activity_dates):
    today = datetime.utcnow().date()
    if today in activity_dates:
        cursor = today
    elif today - timedelta(days=1) in activity_dates:
        cursor = today - timedelta(days=1)
    else:
        return 0

    streak = 0
    while cursor in activity_dates:
        streak += 1
        cursor -= timedelta(days=1)
    return streak
