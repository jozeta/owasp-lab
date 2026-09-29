# Revert to Global (Single-Student) Progress Tracking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Undo the per-user scoping added in sub-projects 1 and 2 (progress/hints/score/badges/streaks all keyed by `user_id`), restoring a single global progress state per instance, since this app is meant to run one-instance-per-student rather than one shared instance across real people. Remove the leaderboard and instructor view (both exist only to compare users on one shared instance). Keep the `alice`/`bob`/`carol`/`admin` "act as" identity switcher exactly as-is — it exists purely for exploit content (IDOR, session, authorization examples), which never touches progress data.

**Architecture:** `ExampleProgress`/`ActivityDay` lose their `user_id` columns and per-user unique constraints, returning to their pre-sub-project-1 shape. `compute_user_stats(user_id)` becomes `compute_stats()`. `toggle_progress()`/`reveal_hint()` drop their anonymous-redirect gate (restoring their pre-sub-project-1 behavior, verified directly against that commit during spec-writing). `leaderboard()`/`instructor_view()` and their templates/nav links are deleted outright.

**Tech Stack:** Flask, SQLAlchemy, Jinja2, pytest with the real Flask test client.

**Spec:** docs/superpowers/specs/2026-09-29-owasp-lab-global-progress-design.md

## Global Constraints

- Nothing about the `User` model, the `/switch-user` picker, or any individual exploit example's own use of session identity changes — this plan touches only progress/score/badge/streak tracking and the two pages that compared it across users.
- Every exact new file below was written against the actual current content of each file, read fresh during plan-writing (not reconstructed from memory) — this includes every test file being modified.
- Baseline at plan-writing time: 650 passed, 3 skipped, at commit `ddccb24` on `main`. Final expected count after this plan: **636 passed, 3 skipped** (arithmetic: -6 `test_leaderboard.py` deleted, -4 `test_instructor_view.py` deleted, -4 `test_per_user_progress.py` deleted, +4 new `test_global_progress.py`, -1 `test_progress.py` net, -1 `test_hints.py` net, -2 `test_fjord_remaining_pages.py` net = -14 from 650).
- This is real, correct application code — not a training vulnerability. No shortcuts needed to "preserve" anything.

---

### Task 1: Data model and route changes

**Files:**
- Modify: `app/core/models.py`
- Modify: `app/core/stats.py`
- Modify: `app/core/views.py`
- Modify: `app/core/__init__.py`

**Interfaces:**
- Produces: `ExampleProgress` (columns: `id`, `example_id` unique, `completed_at`, `hints_used`, `points_awarded` — no `user_id`), `ActivityDay` (`id`, `date` unique — no `user_id`), `record_activity()` (no args), `compute_stats()` (no args, same return-dict shape as before: `completed_total`, `score_total`, `streak_days`, `badges`, `last_active`).
- These four files must change together in one task — `views.py` calling `ExampleProgress.query.filter_by(user_id=...)` while `models.py` no longer has that column would break immediately, so there is no way to sequence this across multiple tasks without leaving the app broken mid-way.

**Orchestration note:** these are the four most fundamental files in the app; every later task (templates, tests) depends on their exact new shape. Re-read all four fresh before starting, even though this brief already quotes their current exact content, in case anything changed between plan-writing and execution.

- [ ] **Step 1: Update `app/core/models.py`**

Change `ExampleProgress` (currently lines 41-53) from:

```python
class ExampleProgress(db.Model):
    __tablename__ = "example_progress"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    example_id = db.Column(db.String(80), nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    hints_used = db.Column(db.Integer, nullable=False, default=0)
    points_awarded = db.Column(db.Integer, nullable=True)

    __table_args__ = (
        db.UniqueConstraint("user_id", "example_id", name="uq_progress_user_example"),
    )
```

to:

```python
class ExampleProgress(db.Model):
    __tablename__ = "example_progress"

    id = db.Column(db.Integer, primary_key=True)
    example_id = db.Column(db.String(80), nullable=False, unique=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    hints_used = db.Column(db.Integer, nullable=False, default=0)
    points_awarded = db.Column(db.Integer, nullable=True)
```

Change `ActivityDay` (currently lines 56-65) from:

```python
class ActivityDay(db.Model):
    __tablename__ = "activity_days"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    date = db.Column(db.Date, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("user_id", "date", name="uq_activity_user_date"),
    )
```

to:

```python
class ActivityDay(db.Model):
    __tablename__ = "activity_days"

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, unique=True)
```

Change `record_activity(user_id)` (currently lines 68-77) from:

```python
def record_activity(user_id):
    """Idempotently mark that `user_id` practiced today (UTC).

    Adds to the session but does not commit -- callers already commit once
    at the end of their own request handler.
    """
    today = datetime.utcnow().date()
    already_recorded = ActivityDay.query.filter_by(user_id=user_id, date=today).first()
    if already_recorded is None:
        db.session.add(ActivityDay(user_id=user_id, date=today))
```

to:

```python
def record_activity():
    """Idempotently mark that today (UTC) had activity on this instance.

    Adds to the session but does not commit -- callers already commit once
    at the end of their own request handler.
    """
    today = datetime.utcnow().date()
    already_recorded = ActivityDay.query.filter_by(date=today).first()
    if already_recorded is None:
        db.session.add(ActivityDay(date=today))
```

Leave `Settings`, `User`, and `compute_points()` completely untouched.

- [ ] **Step 2: Rewrite `app/core/stats.py`**

Replace the entire file with:

```python
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
```

(Only the function name and the two query filters changed from the current file — `_compute_streak` is byte-for-byte identical.)

- [ ] **Step 3: Update `app/core/views.py`**

Change the import block (currently lines 1-10) from:

```python
from datetime import datetime

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, session, url_for

from app.core.auth import get_current_user
from app.core.models import ExampleProgress, Settings, User, compute_points, record_activity
from app.core.nav import CATEGORIES
from app.core.seed import reset_database
from app.core.stats import compute_user_stats
from app.extensions import db
```

to:

```python
from datetime import datetime

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, session, url_for

from app.core.models import ExampleProgress, Settings, User, compute_points, record_activity
from app.core.nav import CATEGORIES
from app.core.seed import reset_database
from app.core.stats import compute_stats
from app.extensions import db
```

(Dropped `from app.core.auth import get_current_user` — after this task, no route in this file calls it any more; `User` stays, still used by `switch_user()`.)

Replace `home()` (currently lines 31-79) with:

```python
@core_bp.route("/")
def home():
    progress_rows = {p.example_id: p for p in ExampleProgress.query.all()}
    completed_ids = {
        example_id for example_id, p in progress_rows.items() if p.completed_at is not None
    }
    badges = compute_stats()["badges"]
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
                "badge_earned": category.id in badges,
            }
        )
    completed_total = sum(cs["completed"] for cs in category_stats)
    total = sum(cs["total"] for cs in category_stats)
    overall_percent = round(completed_total / total * 100) if total else 0
    earned_points_total = sum(cs["earned_points"] for cs in category_stats)
    max_points_total = sum(cs["max_points"] for cs in category_stats)
    return render_template(
        "core/home.html",
        completed_total=completed_total,
        total=total,
        overall_percent=overall_percent,
        category_stats=category_stats,
        earned_points_total=earned_points_total,
        max_points_total=max_points_total,
    )
```

Delete the `leaderboard()` function (currently lines 82-115) and the `instructor_view()` function (currently lines 118-147) entirely — both routes, both docstrings/bodies, gone.

Replace `toggle_progress()` (currently lines 220-242) with:

```python
@core_bp.route("/progress/toggle", methods=["POST"])
def toggle_progress():
    example_id = request.form.get("example_id", "")
    example = _find_example(example_id)
    if example is None:
        abort(404)
    progress = ExampleProgress.query.filter_by(example_id=example_id).first()
    if progress is None:
        progress = ExampleProgress(example_id=example_id, hints_used=0)
        db.session.add(progress)
    if progress.completed_at is None:
        progress.completed_at = datetime.utcnow()
        progress.points_awarded = compute_points(example, progress.hints_used)
    else:
        progress.completed_at = None
        progress.points_awarded = None
    record_activity()
    db.session.commit()
    return redirect(url_for(example.endpoint))
```

Replace `reveal_hint()` (currently lines 245-263) with:

```python
@core_bp.route("/hints/reveal", methods=["POST"])
def reveal_hint():
    example_id = request.form.get("example_id", "")
    example = _find_example(example_id)
    if example is None:
        abort(404)
    progress = ExampleProgress.query.filter_by(example_id=example_id).first()
    if progress is None:
        progress = ExampleProgress(example_id=example_id, hints_used=0)
        db.session.add(progress)
    if progress.hints_used < len(example.hints):
        progress.hints_used += 1
    record_activity()
    db.session.commit()
    return redirect(url_for(example.endpoint))
```

Leave `_is_safe_redirect_target()`, `_find_example()`, `switch_user()`, `logout()`, `settings_page()`, `reset_lab()`, `force_reset()`, `tools_page()`, `about_page()` (and their comments) completely untouched.

- [ ] **Step 4: Restore `app/core/__init__.py` to its pre-per-user shape**

Replace the entire file with:

```python
from flask import current_app, request


def register_core(app):
    from app.core.auth import get_current_user
    from app.core.models import ExampleProgress, Settings, compute_points
    from app.core.nav import CATEGORIES
    from app.core.views import core_bp

    app.register_blueprint(core_bp)

    @app.context_processor
    def inject_globals():
        active_category = next(
            (
                c
                for c in CATEGORIES
                if request.endpoint and request.endpoint.startswith(c.blueprint_name + ".")
            ),
            None,
        )
        current_example = next(
            (e for c in CATEGORIES for e in c.examples if e.endpoint == request.endpoint),
            None,
        )
        progress_rows = {p.example_id: p for p in ExampleProgress.query.all()}
        completed_example_ids = {
            example_id
            for example_id, p in progress_rows.items()
            if p.completed_at is not None
        }
        if current_example is not None and current_example.id in progress_rows:
            current_progress = progress_rows[current_example.id]
        else:
            current_progress = ExampleProgress(hints_used=0, completed_at=None, points_awarded=None)
        current_example_pending_points = (
            compute_points(current_example, current_progress.hints_used)
            if current_example is not None
            else None
        )
        nav_score_earned = sum(
            p.points_awarded or 0 for p in progress_rows.values() if p.completed_at is not None
        )
        nav_score_max = sum(e.base_points() for c in CATEGORIES for e in c.examples)
        return dict(
            settings=Settings.get(),
            categories=sorted(CATEGORIES, key=lambda c: c.short_id),
            current_user=get_current_user(),
            active_category=active_category,
            registered_endpoints=set(current_app.view_functions.keys()),
            current_example=current_example,
            completed_example_ids=completed_example_ids,
            current_progress=current_progress,
            current_example_pending_points=current_example_pending_points,
            nav_score_earned=nav_score_earned,
            nav_score_max=nav_score_max,
        )
```

(This is exactly the file's shape from before sub-project 1 — confirmed against `git show e817ab2^:app/core/__init__.py` during spec-writing. `get_current_user()` is now imported and called here instead of in `views.py`, since `views.py` no longer needs it but `current_user` is still exposed to every template for nav display and exploit-identity purposes.)

- [ ] **Step 5: Run a quick sanity check (full suite will fail until Tasks 2-3 land — that's expected)**

Run: `python -c "from app import create_app; from app.config import TestConfig; create_app(TestConfig)"` to confirm the app still imports cleanly with no syntax/import errors. Do NOT run the full test suite yet — many tests will fail until Task 3 updates them, and `home.html`/`base.html` still reference the now-deleted `leaderboard`/`instructor_view` endpoints via `url_for()`, which will raise `BuildError` until Task 2 lands. This is expected and not a sign anything is wrong.

- [ ] **Step 6: Commit**

```bash
git add app/core/models.py app/core/stats.py app/core/views.py app/core/__init__.py
git commit -m "feat: revert progress/score/badges/streaks to global (single-instance) tracking

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: Templates — remove anonymous alert, nav links, and the two deleted pages

**Files:**
- Modify: `app/core/templates/core/home.html`
- Modify: `app/core/templates/core/base.html`
- Delete: `app/core/templates/core/leaderboard.html`
- Delete: `app/core/templates/core/instructor.html`

**Interfaces:**
- Consumes: `category_stats`, `overall_percent`, etc. from Task 1's `home()` (unchanged shape, just no longer viewer-scoped).

**Orchestration note:** re-read both templates fresh before editing — this brief quotes their current exact content, but confirm before applying the diff.

- [ ] **Step 1: Remove the anonymous-visitor alert from `home.html`**

Find and delete this block (currently lines 7-13, right after the `<p class="lead">` line and before the `<div class="stat-strip...">` line):

```html
{% if not viewer %}
<div class="alert alert-info">
  Your progress isn't being tracked yet.
  <a href="{{ url_for('core.switch_user', next=request.path) }}">Pick a user</a>
  to track completions, hints, and score under your own name.
</div>
{% endif %}
```

Leave every other line in the file (the stat-strip, the dash-grid, everything from the dashboard rework) completely untouched.

- [ ] **Step 2: Remove the Leaderboard and Instructor-view nav links from `base.html`**

Find and delete these lines from the hamburger dropdown (currently lines 96-99):

```html
              <li><a class="dropdown-item" href="{{ url_for('core.leaderboard') }}">Leaderboard</a></li>
              {% if current_user and current_user.role == "admin" %}
              <li><a class="dropdown-item" href="{{ url_for('core.instructor_view') }}">Instructor view</a></li>
              {% endif %}
```

The dropdown's `<li>` for Settings (just above) and the `{% if current_user %}`-gated divider/Log-out block (just below) stay exactly where they are — only these two Leaderboard/Instructor-view lines are removed.

- [ ] **Step 3: Delete the two now-orphaned templates**

```bash
git rm app/core/templates/core/leaderboard.html app/core/templates/core/instructor.html
```

- [ ] **Step 4: Verify the app now imports and builds its URL map cleanly**

Run: `python -c "from app import create_app; from app.config import TestConfig; app = create_app(TestConfig); app.app_context().push(); print('OK')"`
Expected: prints `OK` with no `BuildError`/`ImportError` (confirms no remaining template or Python reference to `core.leaderboard`/`core.instructor_view`).

Also run this grep to confirm nothing else references the removed endpoints:

```bash
grep -rn "core.leaderboard\|core.instructor_view\|compute_user_stats" app/ --include="*.html" --include="*.py"
```

Expected: no output. If anything is found, it's a leftover reference this task must also fix.

- [ ] **Step 5: Commit**

```bash
git add app/core/templates/core/home.html app/core/templates/core/base.html
git rm app/core/templates/core/leaderboard.html app/core/templates/core/instructor.html 2>/dev/null || true
git commit -m "feat: remove anonymous-progress alert and leaderboard/instructor-view pages

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: Test suite overhaul

**Files:**
- Delete: `tests/test_leaderboard.py`, `tests/test_instructor_view.py`, `tests/test_per_user_progress.py`
- Create: `tests/test_global_progress.py`
- Rewrite: `tests/test_stats.py`, `tests/test_activity_tracking.py`, `tests/test_home_badges.py`, `tests/test_progress.py`, `tests/test_hints.py`, `tests/test_fjord_remaining_pages.py`

**Interfaces:**
- Consumes: `compute_stats()`, `record_activity()`, `ExampleProgress`/`ActivityDay` (no `user_id`) from Task 1; the templates from Task 2.

**Orchestration note:** this is a large task (7 files touched, ~40 tests total) but every change in it is contingent on Task 1's exact new shapes landing first — there's no natural way to split it further without leaving some files calling APIs that no longer exist. Work through it file by file, in the order listed below, running each file's own tests before moving to the next so failures stay isolated to whichever file you're currently on.

- [ ] **Step 1: Delete three files whose entire premise is now gone**

```bash
git rm tests/test_leaderboard.py tests/test_instructor_view.py tests/test_per_user_progress.py
```

(`test_leaderboard.py` and `test_instructor_view.py` tested features that no longer exist. `test_per_user_progress.py` tested isolation *between* users, which this plan removes — it's replaced by Step 2's new file testing the opposite: that progress is shared regardless of identity.)

- [ ] **Step 2: Create `tests/test_global_progress.py`**

```python
from flask import url_for

from app.core.models import ExampleProgress, User
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


def test_anonymous_progress_toggle_works_directly(app, client):
    seed_database(app)
    example = _safe_test_example()

    with app.test_request_context():
        expected = url_for(example.endpoint)

    response = client.post("/progress/toggle", data={"example_id": example.id})
    assert response.status_code == 302
    assert response.headers["Location"] == expected

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress is not None
        assert progress.completed_at is not None


def test_anonymous_hint_reveal_works_directly(app, client):
    seed_database(app)
    example = _safe_test_example()

    with app.test_request_context():
        expected = url_for(example.endpoint)

    response = client.post("/hints/reveal", data={"example_id": example.id})
    assert response.status_code == 302
    assert response.headers["Location"] == expected

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress is not None
        assert progress.hints_used == 1


def test_progress_completed_as_one_identity_is_visible_as_another(app, client):
    seed_database(app)
    example = _safe_test_example()
    examples = [e for category in CATEGORIES for e in category.examples]

    _login_as(client, app, "alice")
    client.post("/progress/toggle", data={"example_id": example.id})

    _login_as(client, app, "bob")
    response = client.get("/")
    body = response.data.decode()
    assert f"1<small>/{len(examples)}</small>" in body


def test_completing_the_example_as_different_identities_toggles_the_same_row(app, client):
    seed_database(app)
    example = _safe_test_example()

    _login_as(client, app, "alice")
    client.post("/progress/toggle", data={"example_id": example.id})

    _login_as(client, app, "bob")
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        assert ExampleProgress.query.count() == 1
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.completed_at is None
```

Run: `pytest tests/test_global_progress.py -v`
Expected (once Task 1 has landed): PASS (4 tests).

- [ ] **Step 3: Rewrite `tests/test_stats.py`**

Replace the entire file with:

```python
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
        "badges": {},
        "last_active": None,
    }


def test_completing_every_example_in_a_category_earns_its_badge(app):
    seed_database(app)
    examples = _a10_examples()
    assert len(examples) == 5  # sanity-check the fixture assumption

    with app.app_context():
        base_time = datetime(2026, 1, 1, 12, 0, 0)
        for i, example in enumerate(examples):
            db.session.add(
                ExampleProgress(
                    example_id=example.id,
                    completed_at=base_time + timedelta(minutes=i),
                    points_awarded=example.base_points(),
                )
            )
        db.session.commit()

        stats = compute_stats()

    assert stats["completed_total"] == 5
    assert stats["score_total"] == sum(e.base_points() for e in examples)
    assert "a10_ssrf" in stats["badges"]
    # earned_at is the LATEST completion among the category's examples --
    # that's the 5th (index 4) example, base_time + 4 minutes.
    assert stats["badges"]["a10_ssrf"] == base_time + timedelta(minutes=4)


def test_partial_category_completion_earns_no_badge(app):
    seed_database(app)
    examples = _a10_examples()

    with app.app_context():
        db.session.add(
            ExampleProgress(
                example_id=examples[0].id,
                completed_at=datetime.utcnow(),
                points_awarded=examples[0].base_points(),
            )
        )
        db.session.commit()

        stats = compute_stats()

    assert stats["badges"] == {}


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
```

Run: `pytest tests/test_stats.py -v`
Expected: PASS (9 tests).

- [ ] **Step 4: Rewrite `tests/test_activity_tracking.py`**

Replace the entire file with:

```python
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
```

Run: `pytest tests/test_activity_tracking.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Rewrite `tests/test_home_badges.py`**

Replace the entire file with:

```python
from datetime import datetime

from app.core.models import ExampleProgress
from app.core.nav import CATEGORIES
from app.core.seed import seed_database
from app.extensions import db


def test_no_badges_shown_when_nothing_completed(app, client):
    seed_database(app)
    response = client.get("/")
    assert b"text-bg-success" not in response.data


def test_completing_a_whole_category_shows_its_badge(app, client):
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
    assert b"text-bg-success" in response.data


def test_partial_category_completion_shows_no_badge_for_it(app, client):
    seed_database(app)
    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")

    with app.app_context():
        db.session.add(
            ExampleProgress(
                example_id=a10.examples[0].id,
                completed_at=datetime.utcnow(),
                points_awarded=a10.examples[0].base_points(),
            )
        )
        db.session.commit()

    response = client.get("/")
    assert b"text-bg-success" not in response.data
```

Run: `pytest tests/test_home_badges.py -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Rewrite `tests/test_progress.py`**

Replace the entire file with:

```python
from app.core.models import ExampleProgress
from app.core.nav import CATEGORIES
from app.core.seed import seed_database


def _safe_test_example():
    # Deliberately NOT "the first registered example" -- CATEGORIES[0] is
    # A01, whose first example (idor) has its own exploit logic tied to
    # session identity, which would make it a confusing choice for a test
    # file about progress tracking specifically. sqli-login is a standalone
    # A03 route with no login/session requirement at all -- confirmed live
    # before writing this test file.
    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    return next(e for e in a03.examples if e.id == "sqli-login")


def test_toggle_progress_marks_example_complete(app, client):
    seed_database(app)
    example = _safe_test_example()

    response = client.post(
        "/progress/toggle", data={"example_id": example.id}, follow_redirects=True
    )
    assert response.status_code == 200

    with app.app_context():
        assert ExampleProgress.query.filter_by(example_id=example.id).first() is not None


def test_toggle_progress_unmarks_on_second_toggle(app, client):
    seed_database(app)
    example = _safe_test_example()

    client.post("/progress/toggle", data={"example_id": example.id})
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress is not None
        assert progress.completed_at is None


def test_toggle_progress_rejects_unknown_example_id(app, client):
    seed_database(app)
    response = client.post("/progress/toggle", data={"example_id": "not-a-real-example"})
    assert response.status_code == 404

    with app.app_context():
        assert ExampleProgress.query.count() == 0


def test_toggle_progress_redirects_to_the_example_page(app, client):
    from flask import url_for

    seed_database(app)
    example = _safe_test_example()

    with app.test_request_context():
        expected = url_for(example.endpoint)

    response = client.post("/progress/toggle", data={"example_id": example.id})
    assert response.status_code == 302
    assert response.headers["Location"] == expected


def test_mark_as_done_button_appears_on_example_page(app, client):
    from flask import url_for

    seed_database(app)
    example = _safe_test_example()

    with app.test_request_context():
        path = url_for(example.endpoint)

    response = client.get(path)
    assert response.status_code == 200
    assert b"Mark as done" in response.data


def test_completed_example_shows_checkmark_button(app, client):
    from flask import url_for

    seed_database(app)
    example = _safe_test_example()
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.test_request_context():
        path = url_for(example.endpoint)

    response = client.get(path)
    assert "✓ Completed".encode() in response.data


def test_mark_as_done_button_absent_on_category_overview_page(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Mark as done" not in response.data
    assert "✓ Completed".encode() not in response.data


def test_mark_as_done_button_absent_on_settings_page(client):
    response = client.get("/settings")
    assert response.status_code == 200
    assert b"Mark as done" not in response.data


def test_reset_lab_clears_progress(app, client):
    seed_database(app)
    example = _safe_test_example()
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        assert ExampleProgress.query.count() == 1

    client.post("/settings/reset")

    with app.app_context():
        assert ExampleProgress.query.count() == 0


def test_home_page_shows_progress(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Overall" in response.data


def test_home_page_shows_zero_percent_when_nothing_completed(app, client):
    seed_database(app)
    examples = [e for category in CATEGORIES for e in category.examples]
    response = client.get("/")
    body = response.data.decode()
    assert f"0<small>/{len(examples)}</small>" in body
    assert "0<small>%</small>" in body


def test_home_page_shows_correct_overall_count(app, client):
    seed_database(app)
    examples = [e for category in CATEGORIES for e in category.examples]
    assert len(examples) >= 2

    client.post("/progress/toggle", data={"example_id": examples[0].id})
    client.post("/progress/toggle", data={"example_id": examples[1].id})

    response = client.get("/")
    body = response.data.decode()
    expected_percent = round(2 / len(examples) * 100)
    assert f"2<small>/{len(examples)}</small>" in body
    assert f"{expected_percent}<small>%</small>" in body


def test_home_page_shows_correct_per_category_count(app, client):
    seed_database(app)
    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    example = a03.examples[0]

    client.post("/progress/toggle", data={"example_id": example.id})

    response = client.get("/")
    body = response.data.decode()
    assert f"1 / {len(a03.examples)}" in body
    assert "Injection" in body


def test_stats_page_and_dropdown_link_are_removed(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "/stats" not in response.data.decode()

    response = client.get("/stats")
    assert response.status_code == 404
```

(The old `test_anonymous_toggle_redirects_to_switch_user_with_example_page_as_next` test is gone — its premise is now wrong; `test_global_progress.py`'s `test_anonymous_progress_toggle_works_directly` supersedes it.)

Run: `pytest tests/test_progress.py -v`
Expected: PASS (14 tests).

- [ ] **Step 7: Rewrite `tests/test_hints.py`**

Replace the entire file with:

```python
from flask import url_for

from app.core.models import ExampleProgress, Settings
from app.core.nav import CATEGORIES
from app.core.seed import seed_database
from app.extensions import db


def _a10_example(example_id):
    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")
    return next(e for e in a10.examples if e.id == example_id)


def _enable_scoring(app):
    with app.app_context():
        settings = Settings.get()
        settings.scoring_enabled = True
        db.session.commit()


def test_reveal_hint_increments_hints_used(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("webhook-internal-metadata")

    client.post("/hints/reveal", data={"example_id": example.id})

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.hints_used == 1


def test_reveal_hint_is_capped_at_the_examples_hint_count(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("webhook-internal-metadata")
    assert len(example.hints) == 3

    for _ in range(5):
        client.post("/hints/reveal", data={"example_id": example.id})

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.hints_used == 3


def test_revealed_hint_text_appears_on_the_example_page(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("webhook-internal-metadata")

    client.post("/hints/reveal", data={"example_id": example.id})

    with app.test_request_context():
        path = url_for(example.endpoint)
    response = client.get(path)
    assert example.hints[0].encode() in response.data
    assert example.hints[1].encode() not in response.data


def test_mark_as_done_button_previews_exact_point_value(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("webhook-internal-metadata")

    client.post("/hints/reveal", data={"example_id": example.id})

    with app.test_request_context():
        path = url_for(example.endpoint)
    response = client.get(path)
    assert b"Mark as done (earn 7 pts)" in response.data


def test_points_freeze_at_completion_and_survive_later_hint_reveals(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("fetch-based-port-scan")

    client.post("/hints/reveal", data={"example_id": example.id})
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.points_awarded == 15

    client.post("/hints/reveal", data={"example_id": example.id})

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.points_awarded == 15


def test_unmarking_and_recompleting_recomputes_points_fresh(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("blocklist-redirect-bypass")

    client.post("/progress/toggle", data={"example_id": example.id})
    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.points_awarded == 30

    client.post("/progress/toggle", data={"example_id": example.id})
    client.post("/hints/reveal", data={"example_id": example.id})
    client.post("/hints/reveal", data={"example_id": example.id})
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        progress = ExampleProgress.query.filter_by(example_id=example.id).first()
        assert progress.points_awarded == 18


def test_scoring_enabled_hides_exploit_instructions_regardless_of_stored_value(app, client):
    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.show_exploit_instructions = True
        settings.scoring_enabled = True
        db.session.commit()
    example = _a10_example("webhook-internal-metadata")

    with app.test_request_context():
        path = url_for(example.endpoint)
    response = client.get(path)
    assert b'card-header bg-danger text-white">Exploitation' not in response.data


def test_settings_post_does_not_clear_show_exploit_instructions_while_enabling_scoring(app, client):
    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.show_exploit_instructions = True
        db.session.commit()

    # Simulates the browser: the exploit-instructions checkbox is disabled
    # while scoring is being turned on, so it is omitted from the submitted
    # form data entirely.
    client.post(
        "/settings",
        data={"show_explanations": "on", "scoring_enabled": "on"},
    )

    with app.app_context():
        settings = Settings.get()
        assert settings.show_exploit_instructions is True
        assert settings.scoring_enabled is True


def test_home_page_shows_score_totals_when_scoring_enabled(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("webhook-internal-metadata")
    client.post("/progress/toggle", data={"example_id": example.id})

    response = client.get("/")
    body = response.data.decode()
    assert "10<small>/2270</small>" in body


def test_nav_bar_shows_running_score_on_any_page_when_scoring_enabled(app, client):
    seed_database(app)
    _enable_scoring(app)
    example = _a10_example("webhook-internal-metadata")
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.test_request_context():
        path = url_for("a10_ssrf.overview")
    response = client.get(path)
    assert b"Score: 10 / 2270" in response.data


def test_score_ui_absent_when_scoring_disabled(client):
    response = client.get("/")
    assert b"Score:" not in response.data
```

(The old `test_anonymous_reveal_hint_redirects_to_switch_user_with_example_page_as_next` test is gone — superseded by `test_global_progress.py`'s `test_anonymous_hint_reveal_works_directly`.)

Run: `pytest tests/test_hints.py -v`
Expected: PASS (11 tests).

- [ ] **Step 8: Rewrite `tests/test_fjord_remaining_pages.py`**

Replace the entire file with:

```python
from app.core.seed import seed_database


def test_switch_user_page_still_renders(app, client):
    seed_database(app)
    response = client.get("/switch-user")
    assert response.status_code == 200
    assert b"Choose Who You're Logged In As" in response.data


def test_settings_page_still_renders(app, client):
    seed_database(app)
    response = client.get("/settings")
    assert response.status_code == 200


def test_tools_page_still_renders(app, client):
    seed_database(app)
    response = client.get("/tools")
    assert response.status_code == 200


def test_about_page_still_renders(app, client):
    seed_database(app)
    response = client.get("/about")
    assert response.status_code == 200
```

Run: `pytest tests/test_fjord_remaining_pages.py -v`
Expected: PASS (4 tests).

- [ ] **Step 9: Run the full suite**

Run: `pytest -q`
Expected: 636 passed, 3 skipped.

- [ ] **Step 10: Commit**

```bash
git add -A
git commit -m "test: rewrite the test suite for global (single-instance) progress tracking

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 4: Final integration — README and full-suite verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the "More pages" section**

Read `README.md`'s "More pages" section fresh. Find and remove the Leaderboard and Instructor-view bullets (added in sub-project 2) — they describe pages this plan deletes. Leave the Home/Tools/About bullets and the theme-toggle line exactly as they are.

Also re-read the **Home** bullet itself fresh — it currently describes per-user progress tracking ("Progress is tracked per user: pick a user via the top nav's 'Switch user' link... to have your completions and hints counted under your own name. An anonymous visitor sees an empty dashboard with a prompt to pick a user."). This is no longer accurate. Replace that bullet's body with wording describing the actual current behavior: progress/score/badges are shared across the whole instance regardless of which seeded identity (if any) is active; the "act as" picker exists only so specific exploit examples work correctly, not to track progress. Keep the bullet's existing opening clause about what the page shows (overall + per-category progress, running score when enabled) — only the per-user-tracking sentences need rewriting.

- [ ] **Step 2: Update the schema-caveat paragraph**

Read the existing paragraph about `docker compose down -v` (covers the A07 `pending_mfa_code` column addition and the sub-project-1 `user_id` column addition) fresh, and add one more sentence after it, specifically flagging that this change is **not** the same kind of caveat as the previous ones:

> This release goes further than a normal additive schema change: it *removes* the `user_id` column from `example_progress` and `activity_days`. `db.create_all()` never drops or alters an existing column, so on an old volume the stale `user_id` column's `NOT NULL` constraint will make every new completion or hint action fail outright (not just silently miss a feature) until you run the `docker compose down -v` reset described above.

Insert this as a new paragraph immediately after the existing schema-caveat paragraph, before the "## More pages" heading.

- [ ] **Step 3: Run the full suite fresh**

Run: `pytest -q`
Expected: 636 passed, 3 skipped.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: update README for global (single-instance) progress tracking

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage:**
- `ExampleProgress`/`ActivityDay` lose `user_id`, restore single-column uniques → Task 1. ✅
- `record_activity()`/`compute_user_stats()` → `compute_stats()`, unscoped → Task 1. ✅
- `home()`/`toggle_progress()`/`reveal_hint()` drop viewer-branching and the anonymous-redirect gate, restoring pre-sub-project-1 behavior (verified against that exact commit during spec-writing) → Task 1. ✅
- `leaderboard()`/`instructor_view()` routes, templates, and nav links removed → Tasks 1-2. ✅
- `inject_globals()` restored to its pre-sub-project-1 shape exactly → Task 1. ✅
- Home page's anonymous alert removed → Task 2. ✅
- `switch_user.html`/`User` model/`Settings` untouched → confirmed in every task's file list; none touch these.
- Every test file the spec's own self-review flagged as needing a per-file decision (delete/rewrite/leave) → Task 3, with an explicit decision and exact new content for every one of the 10 files identified.

**2. Placeholder scan:** every step gives complete, literal replacement file content or exact before/after diffs — no "similarly update X" without showing X's actual new content.

**3. Type/naming consistency:** `compute_stats()` (no args) is defined once in Task 1 and called identically (`compute_stats()["badges"]` in `home()`, direct calls in `test_stats.py`) everywhere it's used. `record_activity()` (no args) likewise.

**4. Running total sanity check:** 650 (baseline) - 6 (`test_leaderboard.py` deleted) - 4 (`test_instructor_view.py` deleted) - 4 (`test_per_user_progress.py` deleted) + 4 (`test_global_progress.py` new) - 1 (`test_progress.py` net) - 1 (`test_hints.py` net) - 2 (`test_fjord_remaining_pages.py` net) = 636 passed, 3 skipped. Matches Task 3's and Task 4's stated expected counts.

**5. Risk note carried to execution:** this plan restores several files to an exact prior git state (verified directly against commit `e817ab2^`, the commit immediately before per-user progress was introduced) rather than deriving that shape from scratch — the final whole-branch review should independently confirm `app/core/__init__.py`'s new content is genuinely byte-for-byte what that historical commit had, not just plausible-looking.
