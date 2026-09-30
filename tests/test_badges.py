from datetime import datetime, timedelta

from app.core.badges import (
    BADGE_CATALOG,
    CODE_EXECUTION_EXAMPLE_IDS,
    REVERSE_SHELL_EXAMPLE_IDS,
    SQLI_EXAMPLE_IDS,
    compute_badges,
)
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


def test_badge_catalog_has_32_entries_with_unique_ids():
    ids = [b.id for b in BADGE_CATALOG]
    assert len(ids) == 32
    assert len(set(ids)) == 32


def test_milestone_badges_earned_at_each_threshold(app):
    seed_database(app)
    examples = [e for c in CATEGORIES for e in c.examples]
    assert len(examples) >= 100

    with app.app_context():
        for example in examples[:75]:
            _complete(example.id)
        db.session.commit()

        badges = compute_badges()

    assert badges["foothold-established"] is True
    assert badges["privilege-escalation"] is True
    assert badges["lateral-movement"] is True
    assert badges["domain-admin"] is True
    assert badges["total-pwnage"] is False


def test_milestone_badge_not_earned_below_threshold(app):
    seed_database(app)
    examples = [e for c in CATEGORIES for e in c.examples][:9]

    with app.app_context():
        for example in examples:
            _complete(example.id)
        db.session.commit()

        badges = compute_badges()

    assert badges["foothold-established"] is False


def test_sqli_example_ids_exist_in_the_real_nav(app):
    with app.app_context():
        all_ids = {e.id for c in CATEGORIES for e in c.examples}

    assert SQLI_EXAMPLE_IDS.issubset(all_ids)
    assert CODE_EXECUTION_EXAMPLE_IDS.issubset(all_ids)
    assert REVERSE_SHELL_EXAMPLE_IDS.issubset(all_ids)
    assert REVERSE_SHELL_EXAMPLE_IDS.issubset(CODE_EXECUTION_EXAMPLE_IDS)


def test_bobby_tables_badge_requires_every_sqli_example(app):
    seed_database(app)

    with app.app_context():
        sqli_ids = sorted(SQLI_EXAMPLE_IDS)
        for example_id in sqli_ids[:-1]:
            _complete(example_id)
        db.session.commit()
        assert compute_badges()["bobby-tables"] is False

        _complete(sqli_ids[-1])
        db.session.commit()

        badges = compute_badges()

    assert badges["bobby-tables"] is True


def test_code_red_badge_earned_by_any_single_rce_example(app):
    seed_database(app)

    with app.app_context():
        assert compute_badges()["code-red"] is False

        _complete("debug-console-rce")
        db.session.commit()

        badges = compute_badges()

    assert badges["code-red"] is True


def test_popped_a_shell_badge_earned_by_command_injection_or_sqli_to_rce(app):
    seed_database(app)

    with app.app_context():
        assert compute_badges()["popped-a-shell"] is False

        # A code-execution example NOT in the reverse-shell set should not
        # trip this badge, even though it earns code-red.
        _complete("debug-console-rce")
        db.session.commit()
        assert compute_badges()["popped-a-shell"] is False

        _complete("command-injection")
        db.session.commit()

        badges = compute_badges()

    assert badges["popped-a-shell"] is True
