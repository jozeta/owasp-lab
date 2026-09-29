# Expanded Achievement System Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single "one badge per category" concept with a full 24-badge achievement system (category mastery, difficulty sweeps, grand completion, hint-based, streak-based, and funny/easter-egg badges), shown as a dedicated "badge case" on the home page — dimmed until earned, colored once earned. Also flip `scoring_enabled`'s default to `True`.

**Architecture:** A new module, `app/core/badges.py`, holds the badge catalog (24 entries: name, icon, description, condition) and `compute_badges()`. `compute_stats()` (`app/core/stats.py`) drops its old `badges` key — badges are now fully `badges.py`'s concern. A new sprite file, `static/icons/badge-icons.svg`, holds all 24 badge icons (10 copied verbatim from the existing category icons, 14 new). `home()` computes badge state alongside its existing stats and passes it to a new "Badge Case" section in `home.html`, replacing the old inline per-category 🏅 marker on the dash-cards.

**Tech Stack:** Flask, SQLAlchemy, Jinja2, pytest with the real Flask test client.

**Spec:** docs/superpowers/specs/2026-09-29-owasp-lab-achievements-design.md

## Global Constraints

- No new database tables or columns — every badge condition is derived from existing `ExampleProgress`/`ActivityDay` data plus static `CATEGORIES`/`ExampleNav` metadata (`difficulty`, `hints`).
- `compute_badges()` runs exactly 2 queries (`ExampleProgress.query.all()`, `ActivityDay.query.all()`), matching `compute_stats()`'s already-established pattern — this is a third and fourth query on top of `home()`'s own fetch and `compute_stats()`'s own two, deliberately accepted (see spec) rather than refactored away.
- Flipping `scoring_enabled`'s default has one known test ripple: `tests/test_hints.py::test_score_ui_absent_when_scoring_disabled` currently relies on the fresh-database default being `False` — it must now explicitly disable scoring itself. This plan's own survey (`grep -rln "scoring_enabled\|Score:\|b"Score" tests/*.py`) found exactly two files reference scoring state at all (`test_dashboard_rework.py`, `test_hints.py`) — both are handled explicitly below; no other file needs touching for this reason.
- Baseline at plan-writing time: 636 passed, 3 skipped, at commit `60042ab` on `main`. Expected final count: **648 passed, 3 skipped** (636 + 13 new `test_badges.py` - 2 removed `test_stats.py` badge tests + 1 net `test_home_badges.py` rewrite = 648).

---

### Task 1: Badge catalog module, icon sprite, `stats.py` cleanup, and Settings default

**Files:**
- Modify: `app/core/models.py`
- Modify: `app/core/stats.py`
- Create: `app/core/badges.py`
- Create: `static/icons/badge-icons.svg`
- Modify: `tests/test_stats.py`
- Create: `tests/test_badges.py`

**Interfaces:**
- Produces: `Badge` dataclass and `BADGE_CATALOG` (24 entries) in `app/core/badges.py`; `compute_badges()` returning `{badge.id: bool}`; `compute_streak()` (renamed from `stats.py`'s private `_compute_streak`, now shared across both modules).
- Consumed by Task 2's `views.py`/`home.html`.

- [ ] **Step 1: Flip `Settings`'s scoring default**

In `app/core/models.py`, change line 12 from:

```python
    scoring_enabled = db.Column(db.Boolean, nullable=False, default=False)
```

to:

```python
    scoring_enabled = db.Column(db.Boolean, nullable=False, default=True)
```

And change `Settings.get()`'s creation defaults (currently lines 18-22) from:

```python
            settings = cls(
                show_explanations=True,
                show_exploit_instructions=False,
                scoring_enabled=False,
            )
```

to:

```python
            settings = cls(
                show_explanations=True,
                show_exploit_instructions=False,
                scoring_enabled=True,
            )
```

- [ ] **Step 2: Rename `_compute_streak` to `compute_streak` and drop `compute_stats()`'s `badges` key**

Replace `app/core/stats.py`'s entire content with:

```python
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
```

(Dropped: the `badges` dict and its whole computation loop, and the now-unused `from app.core.nav import CATEGORIES` import. Renamed: `_compute_streak` → `compute_streak`, now a public shared helper.)

- [ ] **Step 3: Create the badge sprite, `static/icons/badge-icons.svg`**

```html
<svg xmlns="http://www.w3.org/2000/svg" style="display:none" aria-hidden="true">
  <defs>
    <symbol id="badge-a01-mastery" viewBox="0 0 24 24"><path d="M6 3h9a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H6"/><path d="M6 3 3 5v14l3 2"/><circle cx="12.6" cy="12" r="0.9" fill="currentColor" stroke="none"/></symbol>
    <symbol id="badge-a02-mastery" viewBox="0 0 24 24"><circle cx="8" cy="8" r="4"/><path d="m10.8 10.8 8.6 8.6"/><path d="M16 16.5 18.5 14"/><path d="M18 18.5 20.5 16"/><path d="M9.5 6.2 7 8.7"/></symbol>
    <symbol id="badge-a03-mastery" viewBox="0 0 24 24"><path d="M20 4 16 8"/><path d="m17.5 5.5-9 9-3.5 5 5-3.5 9-9z"/><path d="m13 9 2 2"/><path d="M4.5 19.5 6 18"/></symbol>
    <symbol id="badge-a04-mastery" viewBox="0 0 24 24"><rect x="3.5" y="3.5" width="17" height="17" rx="1.2"/><path d="M3.5 9h5.5M15 9h5.5M3.5 15h3M17.5 15h3"/><path d="m10 9 2 3-2 3 2 3"/></symbol>
    <symbol id="badge-a05-mastery" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3.4"/><path d="M12 3.5v2.3M12 18.2v2.3M20.5 12h-2.3M5.8 12H3.5M18 6l-1.6 1.6M7.6 16.4 6 18M18 18l-1.6-1.6M7.6 7.6 6 6"/><path d="M20.8 5.2 19 7" stroke-dasharray="1 2.4"/></symbol>
    <symbol id="badge-a06-mastery" viewBox="0 0 24 24"><path d="M12 3 20.5 7.5v9L12 21 3.5 16.5v-9z"/><path d="M3.5 7.5 12 12l8.5-4.5M12 12v9"/><path d="m9.5 9-1.5 3 1.5 3"/></symbol>
    <symbol id="badge-a07-mastery" viewBox="0 0 24 24"><path d="M12 4a6 6 0 0 1 6 6v2.5"/><path d="M12 4a6 6 0 0 0-6 6v3"/><path d="M9 20v-6a3 3 0 0 1 5.5-1.7"/><path d="M15 20v-6.3"/><path d="M6 20v-4a6 6 0 0 1 .3-1.9"/></symbol>
    <symbol id="badge-a08-mastery" viewBox="0 0 24 24"><rect x="3" y="8" width="7" height="10" rx="3.5" transform="rotate(-20 6.5 13)"/><rect x="14" y="6" width="7" height="10" rx="3.5" transform="rotate(-20 17.5 11)"/><path d="m10.5 12.5 1.6-1.8"/></symbol>
    <symbol id="badge-a09-mastery" viewBox="0 0 24 24"><path d="M3 12s3.5-6 9-6 9 6 9 6-3.5 6-9 6-9-6-9-6Z"/><circle cx="12" cy="12" r="2.4"/><path d="m4 19 16-14" stroke-dasharray="1.6 2"/></symbol>
    <symbol id="badge-a10-mastery" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="6" rx="1.2"/><rect x="4" y="14" width="16" height="6" rx="1.2"/><circle cx="7.3" cy="7" r=".6" fill="currentColor" stroke="none"/><circle cx="7.3" cy="17" r=".6" fill="currentColor" stroke="none"/><path d="M14 10.5v3a3.5 3.5 0 0 1-3.5 3.5H10"/><path d="m11.6 15.6-1.9 1.4 1.9 1.4"/></symbol>
    <symbol id="badge-script-kiddie" viewBox="0 0 24 24"><path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M4 19h16"/></symbol>
    <symbol id="badge-grey-hat" viewBox="0 0 24 24"><ellipse cx="12" cy="16" rx="9" ry="2"/><path d="M8 16c0-5 1-9 4-9s4 4 4 9"/><path d="M9 11h6"/></symbol>
    <symbol id="badge-1337-haxor" viewBox="0 0 24 24"><circle cx="12" cy="10" r="6"/><path d="M9 10.5v1M15 10.5v1"/><path d="M9 16v2M12 16v3M15 16v2"/><path d="M9.5 13.5c1 1 4 1 5 0"/></symbol>
    <symbol id="badge-red-team-legend" viewBox="0 0 24 24"><path d="M6 3v18"/><path d="M6 4h11l-3 4 3 4H6"/></symbol>
    <symbol id="badge-purist" viewBox="0 0 24 24"><path d="M3 12s3.5 4 9 4 9-4 9-4"/><path d="M8 14.5 6.5 17M16 14.5l1.5 2.5M12 15.5V18"/></symbol>
    <symbol id="badge-tell-me-everything" viewBox="0 0 24 24"><path d="M4 5h16v10H9l-4 3v-3H4z"/><path d="M8 9h8M8 12h5"/></symbol>
    <symbol id="badge-google-is-my-copilot" viewBox="0 0 24 24"><circle cx="10" cy="10" r="6"/><path d="m19 19-4.5-4.5"/></symbol>
    <symbol id="badge-natural-talent" viewBox="0 0 24 24"><path d="M9 18h6"/><path d="M10 21h4"/><path d="M12 3a6 6 0 0 0-3 11c1 .8 1 1.5 1 2h4c0-.5 0-1.2 1-2a6 6 0 0 0-3-11Z"/></symbol>
    <symbol id="badge-consistent-threat" viewBox="0 0 24 24"><path d="M12 3c2 3-1 4-1 6a3 3 0 0 0 6 0c0-1-.5-2-.5-2 1 1 2 3 2 5a6 6 0 0 1-12 0c0-4 3-6 3-9Z"/></symbol>
    <symbol id="badge-advanced-persistent-threat" viewBox="0 0 24 24"><path d="M4 18a8 8 0 0 1 16 0"/><path d="M8 18a4 4 0 0 1 8 0"/><circle cx="12" cy="18" r="1" fill="currentColor" stroke="none"/><path d="M12 3v4"/></symbol>
    <symbol id="badge-nation-state-actor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5v17"/><path d="M6 6.5c2 2 10 2 12 0M6 17.5c2-2 10-2 12 0"/></symbol>
    <symbol id="badge-participation-trophy" viewBox="0 0 24 24"><path d="M8 4h8v4a4 4 0 0 1-8 0z"/><path d="M8 5H5v2a3 3 0 0 0 3 3M16 5h3v2a3 3 0 0 1-3 3"/><path d="M12 12v4"/><path d="M9 20h6M9 20c0-2 1-3 1-4h4c0 1 1 2 1 4"/></symbol>
    <symbol id="badge-leet" viewBox="0 0 24 24"><path d="m9 6-5 6 5 6"/><path d="m15 6 5 6-5 6"/></symbol>
    <symbol id="badge-the-answer" viewBox="0 0 24 24"><path d="M12 3c3 2 4 6 4 10l-4 3-4-3c0-4 1-8 4-10Z"/><path d="M9 15l-2 4M15 15l2 4"/><circle cx="12" cy="9" r="1.3" fill="currentColor" stroke="none"/></symbol>
  </defs>
</svg>
```

(The first 10 symbols' path data is copied verbatim, character-for-character, from `static/icons/category-icons.svg`'s `icon-a01`..`icon-a10` — only the `id` attribute differs. Verify this by diffing the path data, not just eyeballing it.)

- [ ] **Step 4: Create `app/core/badges.py`**

```python
from dataclasses import dataclass
from typing import Callable

from app.core.models import ActivityDay, ExampleProgress
from app.core.nav import CATEGORIES
from app.core.stats import compute_streak

TOTAL_EXAMPLES = sum(len(c.examples) for c in CATEGORIES)


@dataclass
class Badge:
    id: str
    name: str
    icon: str
    description: str
    condition: Callable[[dict], bool]
    scoring_only: bool = False


def _category_mastery(category_id):
    def check(ctx):
        category = next(c for c in CATEGORIES if c.id == category_id)
        ids = {e.id for e in category.examples}
        return bool(ids) and ids.issubset(ctx["completed_ids"])

    return check


def _difficulty_sweep(difficulty):
    def check(ctx):
        ids = {e.id for c in CATEGORIES for e in c.examples if e.difficulty == difficulty}
        return bool(ids) and ids.issubset(ctx["completed_ids"])

    return check


def _grand_completion(ctx):
    return ctx["completed_total"] >= TOTAL_EXAMPLES


def _purist(ctx):
    for category in CATEGORIES:
        ids = {e.id for e in category.examples}
        if not ids or not ids.issubset(ctx["completed_ids"]):
            continue
        if all(ctx["hints_used_by_id"].get(example_id, 0) == 0 for example_id in ids):
            return True
    return False


def _tell_me_everything(ctx):
    example_by_id = {e.id: e for c in CATEGORIES for e in c.examples}
    for example_id, hints_used in ctx["hints_used_by_id"].items():
        example = example_by_id.get(example_id)
        if example is not None and len(example.hints) > 0 and hints_used >= len(example.hints):
            return True
    return False


def _google_is_my_copilot(ctx):
    return sum(ctx["hints_used_by_id"].values()) >= 25


def _natural_talent(ctx):
    hint_free_completions = sum(
        1
        for example_id in ctx["completed_ids"]
        if ctx["hints_used_by_id"].get(example_id, 0) == 0
    )
    return hint_free_completions >= 10


def _streak_at_least(days):
    def check(ctx):
        return ctx["streak_days"] >= days

    return check


def _participation_trophy(ctx):
    return True


def _leet(ctx):
    return ctx["score_total"] >= 1337


def _the_answer(ctx):
    return ctx["completed_total"] >= 42


BADGE_CATALOG = [
    Badge("backdoor-baron", "Backdoor Baron", "badge-a01-mastery", "Complete every Broken Access Control example.", _category_mastery("a01_access_control")),
    Badge("cipher-breaker", "Cipher Breaker", "badge-a02-mastery", "Complete every Cryptographic Failures example.", _category_mastery("a02_crypto_failures")),
    Badge("sql-ninja", "SQL Ninja", "badge-a03-mastery", "Complete every Injection example.", _category_mastery("a03_injection")),
    Badge("architect-of-chaos", "Architect of Chaos", "badge-a04-mastery", "Complete every Insecure Design example.", _category_mastery("a04_insecure_design")),
    Badge("config-crusher", "Config Crusher", "badge-a05-mastery", "Complete every Security Misconfiguration example.", _category_mastery("a05_security_misconfiguration")),
    Badge("dependency-hell-survivor", "Dependency Hell Survivor", "badge-a06-mastery", "Complete every Vulnerable Components example.", _category_mastery("a06_vulnerable_components")),
    Badge("session-hijacker", "Session Hijacker", "badge-a07-mastery", "Complete every Auth Failures example.", _category_mastery("a07_auth_failures")),
    Badge("supply-chain-saboteur", "Supply Chain Saboteur", "badge-a08-mastery", "Complete every Integrity Failures example.", _category_mastery("a08_integrity_failures")),
    Badge("ghost-in-the-logs", "Ghost in the Logs", "badge-a09-mastery", "Complete every Logging Failures example.", _category_mastery("a09_logging_monitoring_failures")),
    Badge("request-forger", "Request Forger", "badge-a10-mastery", "Complete every SSRF example.", _category_mastery("a10_ssrf")),
    Badge("script-kiddie", "Script Kiddie", "badge-script-kiddie", "Complete every Easy example, in any category.", _difficulty_sweep("Easy")),
    Badge("grey-hat", "Grey Hat", "badge-grey-hat", "Complete every Medium example, in any category.", _difficulty_sweep("Medium")),
    Badge("1337-haxor", "1337 Haxor", "badge-1337-haxor", "Complete every Hard example, in any category.", _difficulty_sweep("Hard")),
    Badge("red-team-legend", "Red Team Legend", "badge-red-team-legend", f"Complete all {TOTAL_EXAMPLES} examples.", _grand_completion),
    Badge("purist", "Purist", "badge-purist", "Complete a whole category without revealing a single hint.", _purist),
    Badge("tell-me-everything", "Tell Me Everything", "badge-tell-me-everything", "Reveal every hint on one example.", _tell_me_everything),
    Badge("google-is-my-copilot", "Google Is My Copilot", "badge-google-is-my-copilot", "Reveal 25 hints, lab-wide.", _google_is_my_copilot),
    Badge("natural-talent", "Natural Talent", "badge-natural-talent", "Complete 10 examples without using a hint.", _natural_talent),
    Badge("consistent-threat", "Consistent Threat", "badge-consistent-threat", "Practice 3 days in a row.", _streak_at_least(3)),
    Badge("advanced-persistent-threat", "Advanced Persistent Threat", "badge-advanced-persistent-threat", "Practice 7 days in a row.", _streak_at_least(7)),
    Badge("nation-state-actor", "Nation-State Actor", "badge-nation-state-actor", "Practice 30 days in a row.", _streak_at_least(30)),
    Badge("participation-trophy", "Participation Trophy", "badge-participation-trophy", "Show up. That's it.", _participation_trophy),
    Badge("leet", "Leet", "badge-leet", "Cross 1337 points.", _leet, scoring_only=True),
    Badge("the-answer", "The Answer", "badge-the-answer", "Complete 42 examples.", _the_answer),
]


def compute_badges():
    """Returns {badge.id: bool} for every badge in BADGE_CATALOG."""
    progress_rows = ExampleProgress.query.all()
    completed_ids = {p.example_id for p in progress_rows if p.completed_at is not None}
    completed_total = len(completed_ids)
    hints_used_by_id = {p.example_id: p.hints_used for p in progress_rows}
    score_total = sum(
        p.points_awarded or 0 for p in progress_rows if p.completed_at is not None
    )
    activity_dates = {row.date for row in ActivityDay.query.all()}
    streak_days = compute_streak(activity_dates)

    ctx = {
        "completed_ids": completed_ids,
        "completed_total": completed_total,
        "hints_used_by_id": hints_used_by_id,
        "score_total": score_total,
        "streak_days": streak_days,
    }

    return {badge.id: badge.condition(ctx) for badge in BADGE_CATALOG}
```

- [ ] **Step 5: Update `tests/test_stats.py`**

Remove `test_completing_every_example_in_a_category_earns_its_badge` and `test_partial_category_completion_earns_no_badge` entirely (badges are no longer `compute_stats()`'s concern — they're covered by Step 6's new `test_badges.py`). Change `test_no_progress_gives_zeroed_stats`'s assertion from:

```python
    assert stats == {
        "completed_total": 0,
        "score_total": 0,
        "streak_days": 0,
        "badges": {},
        "last_active": None,
    }
```

to:

```python
    assert stats == {
        "completed_total": 0,
        "score_total": 0,
        "streak_days": 0,
        "last_active": None,
    }
```

Every other test in the file (the streak tests, the query-count test) is untouched.

- [ ] **Step 6: Create `tests/test_badges.py`**

```python
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
```

- [ ] **Step 7: Run the affected tests**

Run: `pytest tests/test_stats.py tests/test_badges.py -v`
Expected: `test_stats.py` 7 passed, `test_badges.py` 13 passed.

- [ ] **Step 8: Run the full suite**

Run: `pytest -q`
Expected: FAIL for tests outside this task's scope — `test_home_badges.py` and `test_dashboard_rework.py` still reference the old badge/stat-strip system, and `test_hints.py::test_score_ui_absent_when_scoring_disabled` still relies on the old default. This is expected; Task 2 fixes the templates and views these depend on, Task 2 also fixes the one `test_hints.py` test. Confirm specifically that `pytest tests/test_stats.py tests/test_badges.py -v` (Step 7) is fully green — that's this task's actual scope.

- [ ] **Step 9: Commit**

```bash
git add app/core/models.py app/core/stats.py app/core/badges.py static/icons/badge-icons.svg tests/test_stats.py tests/test_badges.py
git commit -m "feat: add 24-badge achievement catalog and flip scoring default to on

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: Home page badge case, stat-strip, and views wiring

**Files:**
- Modify: `app/core/views.py`
- Modify: `app/core/templates/core/home.html`
- Modify: `static/css/lab.css`
- Modify: `tests/test_home_badges.py`
- Modify: `tests/test_dashboard_rework.py`
- Modify: `tests/test_hints.py`

**Interfaces:**
- Consumes: `BADGE_CATALOG`, `compute_badges()` (Task 1).

**Orchestration note:** re-read `app/core/views.py` and `app/core/templates/core/home.html` fresh before editing — this brief quotes their current exact content, but confirm before applying the diff.

- [ ] **Step 1: Update `app/core/views.py`**

Change the import block (currently lines 1-9) from:

```python
from datetime import datetime

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, session, url_for

from app.core.models import ExampleProgress, Settings, User, compute_points, record_activity
from app.core.nav import CATEGORIES
from app.core.seed import reset_database
from app.core.stats import compute_stats
from app.extensions import db
```

to:

```python
from datetime import datetime

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, session, url_for

from app.core.badges import BADGE_CATALOG, compute_badges
from app.core.models import ExampleProgress, Settings, User, compute_points, record_activity
from app.core.nav import CATEGORIES
from app.core.seed import reset_database
from app.extensions import db
```

(Dropped the now-unused `from app.core.stats import compute_stats` import — `home()` no longer calls it, see below. Verify with a grep that `compute_stats` really is unused elsewhere in this file before dropping it.)

Replace `home()` (currently lines 30-71) with:

```python
@core_bp.route("/")
def home():
    progress_rows = {p.example_id: p for p in ExampleProgress.query.all()}
    completed_ids = {
        example_id for example_id, p in progress_rows.items() if p.completed_at is not None
    }
    category_stats = []
    for category in sorted(CATEGORIES, key=lambda c: c.short_id):
        completed = sum(1 for e in category.examples if e.id in completed_ids)
        category_total = len(category.examples)
        earned_points = sum(
            progress_rows[e.id].points_awarded or 0
            for e in category.examples
            if e.id in completed_ids
        )
        max_points = sum(e.base_points() for e in category.examples)
        category_stats.append(
            {
                "category": category,
                "completed": completed,
                "total": category_total,
                "percent": round(completed / category_total * 100) if category_total else 0,
                "earned_points": earned_points,
                "max_points": max_points,
            }
        )
    completed_total = sum(cs["completed"] for cs in category_stats)
    total = sum(cs["total"] for cs in category_stats)
    overall_percent = round(completed_total / total * 100) if total else 0
    earned_points_total = sum(cs["earned_points"] for cs in category_stats)
    max_points_total = sum(cs["max_points"] for cs in category_stats)

    settings = Settings.get()
    earned_badges = compute_badges()
    visible_badges = [b for b in BADGE_CATALOG if not b.scoring_only or settings.scoring_enabled]
    badges_earned_count = sum(1 for b in visible_badges if earned_badges[b.id])

    return render_template(
        "core/home.html",
        completed_total=completed_total,
        total=total,
        overall_percent=overall_percent,
        category_stats=category_stats,
        earned_points_total=earned_points_total,
        max_points_total=max_points_total,
        visible_badges=visible_badges,
        earned_badges=earned_badges,
        badges_earned_count=badges_earned_count,
    )
```

(Dropped: the old `badges = compute_stats()["badges"]` line and the `"badge_earned": category.id in badges` key in each `category_stats` entry — the dash-cards no longer show an inline badge marker, see Step 2. Added: `settings`, `earned_badges`, `visible_badges`, `badges_earned_count`.)

- [ ] **Step 2: Update `app/core/templates/core/home.html`**

Replace the entire file with:

```html
{% extends "core/base.html" %}
{% block title %}OWASP Top 10 Training Lab{% endblock %}
{% block content %}
<h1>OWASP Top 10 (2021) Training Lab</h1>
<p class="lead">Pick a category below to see its overview and graduated, exploitable examples.</p>

<div class="stat-strip{% if settings.scoring_enabled %} stat-strip-4col{% endif %}">
  <div class="stat stat-accent">
    <div class="stat-num">{{ completed_total }}<small>/{{ total }}</small></div>
    <div class="stat-lbl">Examples completed</div>
  </div>
  <div class="stat">
    <div class="stat-num">{{ overall_percent }}<small>%</small></div>
    <div class="stat-lbl">Overall progress</div>
  </div>
  {% if settings.scoring_enabled %}
  <div class="stat">
    <div class="stat-num">{{ earned_points_total }}<small>/{{ max_points_total }}</small></div>
    <div class="stat-lbl">Score</div>
  </div>
  {% endif %}
  <div class="stat">
    <div class="stat-num">{{ badges_earned_count }}<small>/{{ visible_badges|length }}</small></div>
    <div class="stat-lbl">Badges</div>
  </div>
</div>

<div class="badge-case-grid">
  {% for badge in visible_badges %}
  <div class="badge-chip {% if earned_badges[badge.id] %}earned{% else %}locked{% endif %}" title="{{ badge.description }}">
    <span class="icon-box" style="width: 40px; height: 40px; border-radius: 10px;">
      <svg class="category-icon" style="width: 20px; height: 20px;" viewBox="0 0 24 24">
        <use href="{{ url_for('static', filename='icons/badge-icons.svg') }}#{{ badge.icon }}"></use>
      </svg>
    </span>
    <span class="badge-chip-name">{{ badge.name }}</span>
    <span class="badge-chip-desc">{{ badge.description }}</span>
  </div>
  {% endfor %}
</div>

<div class="dash-grid">
  {% for cs in category_stats %}
  <a href="{{ url_for(cs.category.overview_endpoint) }}" class="dash-card">
    <div class="dash-card-top">
      <span class="icon-box" style="width: 32px; height: 32px; border-radius: 8px;">
        <svg class="category-icon" style="width: 17px; height: 17px;" viewBox="0 0 24 24">
          <use href="{{ url_for('static', filename='icons/category-icons.svg') }}#icon-{{ cs.category.id[:3] }}"></use>
        </svg>
      </span>
      <span class="dash-card-code">{{ cs.category.short_id }}</span>
    </div>
    <div class="dash-card-name">{{ cs.category.title }}</div>
    <div class="dash-bar-track"><div class="dash-bar-fill fjord-fill" style="width: {{ cs.percent }}%"></div></div>
    <div class="dash-card-meta">
      <span>{{ cs.completed }} / {{ cs.total }}</span>
      {% if settings.scoring_enabled %}<span class="dash-card-pts">{{ cs.earned_points }} pts</span>{% endif %}
    </div>
  </a>
  {% endfor %}
</div>
{% endblock %}
```

(The dash-card's `<span class="dash-card-code">` block dropped its `{% if cs.badge_earned %}` sub-block entirely — it's now just the plain short_id text, unchanged from before badges existed at all on this element.)

- [ ] **Step 3: Update `static/css/lab.css`**

Remove the now-dead `.stat-strip-2col` rule (currently):

```css
.stat-strip.stat-strip-2col {
  grid-template-columns: repeat(2, 1fr);
}
```

(There is no longer a 2-tile case — the Badges tile means every stat-strip has at least 3 tiles now.)

Append this to the end of the file:

```css

/* ===================================================================
   Badge case
   =================================================================== */

.stat-strip.stat-strip-4col {
  grid-template-columns: repeat(4, 1fr);
}

.badge-case-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(96px, 1fr));
  gap: 4px;
  margin-bottom: 2rem;
}

.badge-chip {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  gap: 0.35rem;
  padding: 0.75rem 0.4rem;
  border-radius: 10px;
  transition: opacity 0.15s ease;
}

.badge-chip-name {
  font-size: 11.5px;
  font-weight: 600;
  line-height: 1.25;
}

.badge-chip-desc {
  font-size: 10px;
  color: var(--bs-secondary-color);
  line-height: 1.3;
}

.badge-chip.locked {
  opacity: 0.5;
}

.badge-chip.locked .icon-box {
  background: var(--bs-border-color);
  color: var(--bs-secondary-color);
}

.badge-chip.locked .badge-chip-name {
  color: var(--bs-secondary-color);
}
```

Also add `.stat-strip-4col` and `.badge-case-grid` to the existing mobile media query block (`@media (max-width: 700px) { ... }`) so both collapse to a single column on narrow screens, matching `.stat-strip`'s existing mobile behavior:

```css
@media (max-width: 700px) {
  .stat-strip {
    grid-template-columns: 1fr;
  }

  .badge-case-grid {
    grid-template-columns: repeat(3, 1fr);
  }
}
```

(Read the file fresh to find the exact current media-query block and add the `.badge-case-grid` rule inside it alongside the existing `.stat-strip` rule — do not create a second, separate media query.)

- [ ] **Step 4: Rewrite `tests/test_home_badges.py`**

Replace the entire file with:

```python
from datetime import datetime

from app.core.models import ExampleProgress, Settings
from app.core.nav import CATEGORIES
from app.core.seed import seed_database
from app.extensions import db


def test_badge_case_shows_all_visible_badges_locked_by_default(app, client):
    seed_database(app)
    response = client.get("/")
    body = response.data.decode()
    assert body.count('class="badge-chip earned"') == 1  # only participation-trophy
    assert body.count('class="badge-chip locked"') >= 20


def test_earning_a_category_badge_marks_its_chip_earned(app, client):
    seed_database(app)
    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")

    with app.app_context():
        for example in a10.examples:
            db.session.add(
                ExampleProgress(
                    example_id=example.id,
                    completed_at=datetime.utcnow(),
                    points_awarded=example.base_points(),
                )
            )
        db.session.commit()

    response = client.get("/")
    body = response.data.decode()
    assert "Request Forger" in body
    request_forger_index = body.index("Request Forger")
    chip_start = body.rindex('class="badge-chip', 0, request_forger_index)
    assert "earned" in body[chip_start:request_forger_index]


def test_leet_badge_hidden_when_scoring_disabled(app, client):
    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.scoring_enabled = False
        db.session.commit()

    response = client.get("/")
    assert b"Cross 1337 points" not in response.data


def test_leet_badge_shown_when_scoring_enabled(app, client):
    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.scoring_enabled = True
        db.session.commit()

    response = client.get("/")
    assert b"Cross 1337 points" in response.data
```

Run: `pytest tests/test_home_badges.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Rewrite `tests/test_dashboard_rework.py`**

Replace the entire file with:

```python
from app.core.models import Settings
from app.core.seed import seed_database
from app.extensions import db


def test_stat_strip_has_four_tiles_when_scoring_enabled(app, client):
    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.scoring_enabled = True
        db.session.commit()

    response = client.get("/")
    body = response.data.decode()
    assert 'class="stat-strip stat-strip-4col"' in body
    assert "Score" in body
    assert "Badges" in body


def test_stat_strip_has_three_tiles_when_scoring_disabled(app, client):
    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.scoring_enabled = False
        db.session.commit()

    response = client.get("/")
    body = response.data.decode()
    assert 'class="stat-strip"' in body
    assert "stat-strip-4col" not in body
    assert "Score" not in body
    assert "Badges" in body


def test_nav_category_links_use_the_quiet_navcat_style(app, client):
    seed_database(app)
    response = client.get("/")
    assert b'class="nav-link navcat-link' in response.data
```

Run: `pytest tests/test_dashboard_rework.py -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Fix the one scoring-default-dependent test in `tests/test_hints.py`**

Change `test_score_ui_absent_when_scoring_disabled` (currently):

```python
def test_score_ui_absent_when_scoring_disabled(client):
    response = client.get("/")
    assert b"Score:" not in response.data
```

to:

```python
def test_score_ui_absent_when_scoring_disabled(app, client):
    with app.app_context():
        settings = Settings.get()
        settings.scoring_enabled = False
        db.session.commit()

    response = client.get("/")
    assert b"Score:" not in response.data
```

Every other test in this file already explicitly manages `scoring_enabled` via `_enable_scoring(app)` or its own direct `Settings.get()` call, so none of them are affected by the default flip.

- [ ] **Step 7: Run the affected tests**

Run: `pytest tests/test_home_badges.py tests/test_dashboard_rework.py tests/test_hints.py -v`
Expected: all pass (4 + 3 + 12 = 19 tests).

- [ ] **Step 8: Run the full suite**

Run: `pytest -q`
Expected: 648 passed, 3 skipped.

- [ ] **Step 9: Commit**

```bash
git add app/core/views.py app/core/templates/core/home.html static/css/lab.css tests/test_home_badges.py tests/test_dashboard_rework.py tests/test_hints.py
git commit -m "feat: show the badge case on the home page, wire up scoring-aware stat strip

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: Final integration — README and full-suite verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the Home bullet and mention the achievement system**

Read `README.md`'s "More pages" section fresh. The **Home** bullet currently describes global progress tracking (from the prior sub-project) — add one or two sentences describing the new badge case: 24 achievements spanning category mastery, difficulty sweeps, hint-based challenges, streaks, and a few just-for-fun ones, shown dimmed until earned. Keep the rest of the bullet's existing wording about global tracking untouched — this is an addition, not a rewrite of that part.

- [ ] **Step 2: Note the scoring-default change**

Find wherever the README currently describes the Settings page / scoring toggle (search for "scoring" in the file) and add a short note that scoring is enabled by default now (rather than off by default as before) — a single sentence is enough, this is a behavior change worth documenting but not a major new concept.

- [ ] **Step 3: Run the full suite fresh**

Run: `pytest -q`
Expected: 648 passed, 3 skipped.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document the achievement system and default-on scoring

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage:**
- All 24 badges (catalog, names, conditions) → Task 1's `BADGE_CATALOG`. ✅
- Icon sprite (10 reused verbatim + 14 new) → Task 1. ✅
- `compute_badges()`, 2-query shape matching `compute_stats()`'s precedent → Task 1. ✅
- `compute_stats()` drops its `badges` key → Task 1. ✅
- Scoring default flip → Task 1. ✅
- Home page badge case (dimmed/earned), 4th stat-strip tile, dash-card marker removed → Task 2. ✅
- The one known scoring-default test ripple (`test_score_ui_absent_when_scoring_disabled`) → Task 2, Step 6, with the plan's own grep confirming no other file needed this fix.

**2. Placeholder scan:** every step has complete, literal Python/HTML/CSS/test code — no "similarly update X," no vague styling instructions. The 14 new icon path strings are given in full, not described.

**3. Type/naming consistency:** `compute_badges()`'s return shape (`{badge.id: bool}`) is defined once in Task 1 and consumed identically in Task 2's `home()` and template. `compute_streak` (renamed from `_compute_streak`) is used consistently by both `compute_stats()` and `compute_badges()`. Badge icon ids (`badge-a01-mastery`, etc.) are used identically in the sprite file, the catalog, and nowhere else.

**4. Running total sanity check:** 636 (baseline) + 13 (`test_badges.py`) - 2 (`test_stats.py` badge tests removed) + 1 net (`test_home_badges.py`: 3→4) = 648 passed, 3 skipped. Matches Task 2's and Task 3's stated expected counts. (`test_dashboard_rework.py` stays at 3 tests, net 0; `test_hints.py` stays at 12 tests, net 0 — only one test's body changed.)

**5. Risk note carried to execution:** the 14 new badge icons are hand-designed SVG path data with no prior visual rendering — the user explicitly declined a pre-implementation mockup for this round, accepting that risk. The final whole-branch review should still render the badge case live (via any available browser tooling) and look at the icons for anything obviously broken (missing curves, degenerate paths), even though a full visual-design pass wasn't requested.
