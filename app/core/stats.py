from datetime import datetime, timedelta

from app.core.models import ActivityDay, ExampleProgress


def compute_stats():
    """Completed/score/streak summary for this instance.

    Runs exactly two queries (ExampleProgress, ActivityDay) regardless of
    how many categories or examples exist.
    """
    progress_rows = ExampleProgress.query.all()
    completed_by_id = {
        p.example_id: p for p in progress_rows if p.completed_at is not None
    }
    completed_total = len(completed_by_id)
    score_total = sum(p.points_awarded or 0 for p in completed_by_id.values())

    activity_dates = {row.date for row in ActivityDay.query.all()}
    streak_days = compute_streak(activity_dates)
    last_active = max(activity_dates) if activity_dates else None

    return {
        "completed_total": completed_total,
        "score_total": score_total,
        "streak_days": streak_days,
        "last_active": last_active,
    }


def compute_streak(activity_dates):
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
