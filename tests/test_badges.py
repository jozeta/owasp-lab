from datetime import datetime, timedelta

from app.core.badges import BADGE_CATALOG, compute_badges
from app.core.models import ActivityDay, ExampleProgress
from app.core.nav import CATEGORIES
from app.core.seed import seed_database
from app.extensions import db


def _a10_examples():
    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")
    return a10.examples


def _complete(example_id, hints_used=0, completed_at=None):
    db.session.add(
        ExampleProgress(
            example_id=example_id,
            completed_at=completed_at or datetime.utcnow(),
            hints_used=hints_used,
            points_awarded=10,
        )
    )


def test_no_progress_earns_only_the_participation_trophy(app):
    seed_database(app)

    with app.app_context():
        badges = compute_badges()

    assert badges["participation-trophy"] is True
    assert all(
        not earned for badge_id, earned in badges.items() if badge_id != "participation-trophy"
    )


def test_category_mastery_badge_earned_on_full_category(app):
    seed_database(app)
    examples = _a10_examples()

    with app.app_context():
        for example in examples:
            _complete(example.id)
        db.session.commit()

        badges = compute_badges()

    assert badges["request-forger"] is True


def test_difficulty_sweep_badges(app):
    seed_database(app)

    with app.app_context():
        for category in CATEGORIES:
            for example in category.examples:
                if example.difficulty == "Easy":
                    _complete(example.id)
        db.session.commit()

        badges = compute_badges()

    assert badges["script-kiddie"] is True
    assert badges["grey-hat"] is False
    assert badges["1337-haxor"] is False


def test_grand_completion_badge(app):
    seed_database(app)

    with app.app_context():
        for category in CATEGORIES:
            for example in category.examples:
                _complete(example.id)
        db.session.commit()

        badges = compute_badges()

    assert badges["red-team-legend"] is True


def test_purist_badge_requires_hint_free_category(app):
    seed_database(app)
    examples = _a10_examples()

    with app.app_context():
        for example in examples:
            _complete(example.id, hints_used=0)
        db.session.commit()

        badges = compute_badges()

    assert badges["purist"] is True


def test_purist_badge_not_earned_if_any_hint_used_in_the_category(app):
    seed_database(app)
    examples = _a10_examples()

    with app.app_context():
        for i, example in enumerate(examples):
            _complete(example.id, hints_used=1 if i == 0 else 0)
        db.session.commit()

        badges = compute_badges()

    assert badges["purist"] is False


def test_tell_me_everything_badge(app):
    seed_database(app)
    example = _a10_examples()[0]

    with app.app_context():
        _complete(example.id, hints_used=len(example.hints))
        db.session.commit()

        badges = compute_badges()

    assert badges["tell-me-everything"] is True


def test_google_is_my_copilot_badge(app):
    seed_database(app)
    examples = [e for c in CATEGORIES for e in c.examples][:5]

    with app.app_context():
        for example in examples:
            db.session.add(ExampleProgress(example_id=example.id, hints_used=5, completed_at=None))
        db.session.commit()

        badges = compute_badges()

    assert badges["google-is-my-copilot"] is True


def test_natural_talent_badge(app):
    seed_database(app)
    examples = [e for c in CATEGORIES for e in c.examples][:10]

    with app.app_context():
        for example in examples:
            _complete(example.id, hints_used=0)
        db.session.commit()

        badges = compute_badges()

    assert badges["natural-talent"] is True


def test_streak_badges(app):
    seed_database(app)
    today = datetime.utcnow().date()

    with app.app_context():
        for offset in range(7):
            db.session.add(ActivityDay(date=today - timedelta(days=offset)))
        db.session.commit()

        badges = compute_badges()

    assert badges["consistent-threat"] is True
    assert badges["advanced-persistent-threat"] is True
    assert badges["nation-state-actor"] is False


def test_leet_badge(app):
    seed_database(app)

    with app.app_context():
        db.session.add(
            ExampleProgress(example_id="score-filler", completed_at=datetime.utcnow(), points_awarded=1337)
        )
        db.session.commit()

        badges = compute_badges()

    assert badges["leet"] is True


def test_the_answer_badge(app):
    seed_database(app)
    examples = [e for c in CATEGORIES for e in c.examples][:42]

    with app.app_context():
        for example in examples:
            _complete(example.id)
        db.session.commit()

        badges = compute_badges()

    assert badges["the-answer"] is True


def test_badge_catalog_has_24_entries_with_unique_ids():
    ids = [b.id for b in BADGE_CATALOG]
    assert len(ids) == 24
    assert len(set(ids)) == 24
