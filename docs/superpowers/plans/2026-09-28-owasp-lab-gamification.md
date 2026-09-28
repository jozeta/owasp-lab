# Gamification: Leaderboard, Badges, Streaks & Instructor View Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a leaderboard, per-category completion badges, daily practice streaks, and an admin-gated instructor aggregate view to the OWASP Top 10 Training Lab, building on sub-project 1's per-user progress tracking.

**Architecture:** One new append-only table (`ActivityDay`) records the calendar dates a user touched their progress. One new shared module (`app/core/stats.py`) computes completed/score/streak/badge totals for a single user from `ExampleProgress` + `ActivityDay`, reused identically by the home page, the leaderboard, and the instructor view. Two new routes (`GET /leaderboard`, `GET /instructor`) and small template/nav additions surface it. No new example content — this is application plumbing, not a vulnerability round.

**Tech Stack:** Flask, Flask-SQLAlchemy, Jinja2, Bootstrap 5 (already vendored), pytest with a real Flask test client (no mocking).

**Spec:** docs/superpowers/specs/2026-09-28-owasp-lab-gamification-design.md

## Global Constraints

- No new SQLAlchemy migration tooling exists (no Alembic). Schema changes rely on `db.create_all()` at app startup (creates missing tables, never alters existing ones) and `db.drop_all()` + `db.create_all()` inside `reset_database()` (`app/core/seed.py:70-74`, the "Reset lab" button — this fully recreates the schema either way). `ActivityDay` is a brand-new table, so it needs **no** README volume-reset caveat update — `db.create_all()` already creates missing tables on a pre-existing volume without a wipe. (This corrects an initial assumption in the design spec's Current State section, which conflated "new table" with "new column on an existing table" — only the latter needs the existing `docker compose down -v` caveat, and that caveat's existing text, which cites `pending_mfa_code` and `example_progress.user_id`, both new *columns*, stays accurate and unchanged.)
- This is real, correct application code — not a vulnerability example. The `/instructor` admin check must be a genuinely correct, unconditional `role == "admin"` check (use `abort(403)`, the codebase's existing convention for a real forbidden-access response — see e.g. `app/categories/a01_access_control/routes.py:240`).
- `compute_user_stats(user_id)` must run at most 2 database queries (one for `ExampleProgress`, one for `ActivityDay`) regardless of category/example count — never one query per category.
- All new routes/templates use plain Bootstrap 5 classes already used elsewhere in `app/core/templates/core/` (`text-bg-success`, `text-bg-secondary`, `table`, `nav-pills`, `badge`) — no new CSS, no custom icons (that's sub-project 3).
- New test files copy the existing `_login_as(client, app, username)` helper verbatim into their own file (the established convention in this codebase — see `tests/test_progress.py:6-12`; it is duplicated per-file, not shared via `conftest.py`, and this plan does not change that).
- Current example count (105) and max score (2270) are unchanged by this plan — no new examples are added. `tests/test_all_examples_have_hints.py` and `tests/test_hints.py`'s totals need no edits.
- Baseline at plan-writing time: commit `90a74ec` on `main`, 600 passed / 3 skipped (verified fresh).

---

### Task 1: `ActivityDay` model, `record_activity()`, and wiring into progress/hint routes

**Files:**
- Modify: `app/core/models.py` (currently 69 lines — add after `ExampleProgress`, which ends at line 53)
- Modify: `app/core/views.py` (wire into `toggle_progress()` at lines 149-170 and `reveal_hint()` at lines 173-190)
- Test: `tests/test_activity_tracking.py` (new)

**Interfaces:**
- Produces: `ActivityDay` model (`app/core/models.py`) with columns `id`, `user_id` (FK to `users.id`), `date` (`db.Date`), unique constraint `("user_id", "date")` named `uq_activity_user_date`.
- Produces: `record_activity(user_id)` (`app/core/models.py`) — adds today's UTC date for `user_id` to the session if not already present; does **not** call `db.session.commit()` itself (the caller already commits once at the end of its own transaction).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_activity_tracking.py`:

```python
from datetime import date

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
    # sqli-login is a standalone A03 route with no login/session requirement
    # of its own, matching the precedent in tests/test_progress.py.
    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    return next(e for e in a03.examples if e.id == "sqli-login")


def test_toggle_progress_records_activity_today(app, client):
    seed_database(app)
    user_id = _login_as(client, app, "alice")
    example = _safe_test_example()

    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        rows = ActivityDay.query.filter_by(user_id=user_id).all()
        assert len(rows) == 1
        assert rows[0].date == date.today()


def test_toggle_progress_activity_is_idempotent_same_day(app, client):
    seed_database(app)
    user_id = _login_as(client, app, "alice")
    example = _safe_test_example()

    client.post("/progress/toggle", data={"example_id": example.id})
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        assert ActivityDay.query.filter_by(user_id=user_id).count() == 1


def test_reveal_hint_records_activity_today(app, client):
    seed_database(app)
    user_id = _login_as(client, app, "alice")
    example = _safe_test_example()

    client.post("/hints/reveal", data={"example_id": example.id})

    with app.app_context():
        rows = ActivityDay.query.filter_by(user_id=user_id).all()
        assert len(rows) == 1
        assert rows[0].date == date.today()


def test_activity_recorded_separately_per_user(app, client):
    seed_database(app)
    alice_id = _login_as(client, app, "alice")
    example = _safe_test_example()
    client.post("/progress/toggle", data={"example_id": example.id})

    bob_id = _login_as(client, app, "bob")
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        assert ActivityDay.query.filter_by(user_id=alice_id).count() == 1
        assert ActivityDay.query.filter_by(user_id=bob_id).count() == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_activity_tracking.py -v`
Expected: FAIL — `ImportError: cannot import name 'ActivityDay'`.

- [ ] **Step 3: Add `ActivityDay` and `record_activity()` to `app/core/models.py`**

Insert immediately after `ExampleProgress`'s closing `__table_args__` (after line 53, before `def compute_points`):

```python
class ActivityDay(db.Model):
    __tablename__ = "activity_days"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    date = db.Column(db.Date, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("user_id", "date", name="uq_activity_user_date"),
    )


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

(`datetime` is already imported at the top of `app/core/models.py`; no new import needed there.)

- [ ] **Step 4: Wire `record_activity()` into `toggle_progress()` and `reveal_hint()`**

In `app/core/views.py`, change the import line (currently line 6):

```python
from app.core.models import ExampleProgress, Settings, User, compute_points
```

to:

```python
from app.core.models import ExampleProgress, Settings, User, compute_points, record_activity
```

In `toggle_progress()` (currently lines 149-170), insert the call right before the existing `db.session.commit()`:

```python
    if progress.completed_at is None:
        progress.completed_at = datetime.utcnow()
        progress.points_awarded = compute_points(example, progress.hints_used)
    else:
        progress.completed_at = None
        progress.points_awarded = None
    record_activity(viewer.id)
    db.session.commit()
    return redirect(url_for(example.endpoint))
```

In `reveal_hint()` (currently lines 173-190), insert the same call right before its `db.session.commit()`:

```python
    if progress.hints_used < len(example.hints):
        progress.hints_used += 1
    record_activity(viewer.id)
    db.session.commit()
    return redirect(url_for(example.endpoint))
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_activity_tracking.py -v`
Expected: PASS (4 tests).

- [ ] **Step 6: Run the full suite to confirm no regressions**

Run: `pytest -q`
Expected: 604 passed, 3 skipped (600 + 4 new).

- [ ] **Step 7: Commit**

```bash
git add app/core/models.py app/core/views.py tests/test_activity_tracking.py
git commit -m "feat: track daily activity for streaks

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: `app/core/stats.py` — `compute_user_stats()`

**Files:**
- Create: `app/core/stats.py`
- Test: `tests/test_stats.py` (new)

**Interfaces:**
- Consumes: `ActivityDay`, `ExampleProgress` (`app/core/models.py`, from Task 1); `CATEGORIES` (`app/core/nav.py`).
- Produces: `compute_user_stats(user_id)` returning a dict with exactly these keys:
  - `completed_total` (int) — count of this user's completed examples across all categories.
  - `score_total` (int) — sum of `points_awarded` across completed examples.
  - `streak_days` (int) — see algorithm below.
  - `badges` (dict of `category.id (str) -> earned_at (datetime)`) — present only for categories where every example is completed; value is the latest `completed_at` among that category's examples.
  - `last_active` (`date` or `None`) — the most recent `ActivityDay.date` for this user, or `None` if they have none.

  This exact shape is consumed unchanged by Task 3 (`leaderboard()`), Task 4 (`instructor_view()`), and Task 5 (`home()`).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_stats.py`. This uses A10 SSRF as the "small category" fixture (5 examples, ids `webhook-internal-metadata` (Easy/10), `fetch-based-port-scan` (Medium/20), `file-scheme-local-read` (Easy/10), `blocklist-alternate-ip-bypass` (Medium/20), `blocklist-redirect-bypass` (Hard/30) — verified fresh against `app/categories/a10_ssrf/__init__.py`):

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_stats.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.core.stats'`.

- [ ] **Step 3: Write `app/core/stats.py`**

```python
from datetime import datetime, timedelta

from app.core.models import ActivityDay, ExampleProgress
from app.core.nav import CATEGORIES


def compute_user_stats(user_id):
    """Completed/score/streak/badge summary for one user.

    Runs exactly two queries (ExampleProgress, ActivityDay) regardless of
    how many categories or examples exist -- callers such as the
    leaderboard and instructor view call this once per user, so this must
    stay flat rather than growing with category count.
    """
    progress_rows = ExampleProgress.query.filter_by(user_id=user_id).all()
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

    activity_dates = {
        row.date for row in ActivityDay.query.filter_by(user_id=user_id).all()
    }
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

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_stats.py -v`
Expected: PASS (9 tests).

- [ ] **Step 5: Run the full suite to confirm no regressions**

Run: `pytest -q`
Expected: 613 passed, 3 skipped (604 + 9 new).

- [ ] **Step 6: Commit**

```bash
git add app/core/stats.py tests/test_stats.py
git commit -m "feat: add compute_user_stats() for badges, streaks, and totals

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: Leaderboard page

**Files:**
- Modify: `app/core/views.py` (add route + import)
- Create: `app/core/templates/core/leaderboard.html`
- Modify: `app/core/templates/core/base.html` (nav link)
- Test: `tests/test_leaderboard.py` (new)

**Interfaces:**
- Consumes: `compute_user_stats(user_id)` (Task 2, exact return shape above).
- Produces: route `core.leaderboard` at `GET /leaderboard`.

**Orchestration note:** Task 1 already changed the import line at `app/core/views.py:6` and inserted `record_activity()` calls into `toggle_progress()`/`reveal_hint()`. Before editing, re-read the current `app/core/views.py` fresh — do not assume the line numbers in this brief still match exactly; find `toggle_progress()`, `reveal_hint()`, and the end of the import block by content, not by line number.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_leaderboard.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_leaderboard.py -v`
Expected: FAIL — 404s (`/leaderboard` doesn't exist yet).

- [ ] **Step 3: Add the route to `app/core/views.py`**

Update the import line to include `compute_user_stats` (find and extend the current import block — Task 1 already added `record_activity` there):

```python
from app.core.stats import compute_user_stats
```

Add the route (a sensible place is right after `home()` and before `switch_user()`, but exact placement doesn't matter — Flask routes don't need to be declared in any particular order):

```python
@core_bp.route("/leaderboard")
def leaderboard():
    valid_sorts = {"completed", "score", "streak"}
    sort = request.args.get("sort", "completed")
    if sort not in valid_sorts:
        sort = "completed"

    total_examples = sum(len(c.examples) for c in CATEGORIES)
    rows = []
    for user in User.query.order_by(User.username).all():
        stats = compute_user_stats(user.id)
        rows.append(
            {
                "user": user,
                "completed_total": stats["completed_total"],
                "score_total": stats["score_total"],
                "streak_days": stats["streak_days"],
                "badge_count": len(stats["badges"]),
            }
        )
    sort_key = {
        "completed": lambda r: r["completed_total"],
        "score": lambda r: r["score_total"],
        "streak": lambda r: r["streak_days"],
    }[sort]
    rows.sort(key=sort_key, reverse=True)

    return render_template(
        "core/leaderboard.html",
        rows=rows,
        sort=sort,
        total_examples=total_examples,
        total_badges=len(CATEGORIES),
    )
```

(`settings` for the template is already available everywhere via `inject_globals()`'s context processor — no need to pass it explicitly, matching `home()`'s existing convention.)

- [ ] **Step 4: Create `app/core/templates/core/leaderboard.html`**

```html
{% extends "core/base.html" %}
{% block title %}Leaderboard — OWASP Top 10 Training Lab{% endblock %}
{% block content %}
<h1>Leaderboard</h1>
<p class="lead">See how every seeded account is progressing through the lab.</p>

<ul class="nav nav-pills mb-3">
  <li class="nav-item">
    <a class="nav-link {% if sort == 'completed' %}active{% endif %}" href="{{ url_for('core.leaderboard', sort='completed') }}">Most completed</a>
  </li>
  {% if settings.scoring_enabled %}
  <li class="nav-item">
    <a class="nav-link {% if sort == 'score' %}active{% endif %}" href="{{ url_for('core.leaderboard', sort='score') }}">Highest score</a>
  </li>
  {% endif %}
  <li class="nav-item">
    <a class="nav-link {% if sort == 'streak' %}active{% endif %}" href="{{ url_for('core.leaderboard', sort='streak') }}">Longest streak</a>
  </li>
</ul>

<table class="table">
  <thead>
    <tr>
      <th>User</th>
      <th>Completed</th>
      {% if settings.scoring_enabled %}<th>Score</th>{% endif %}
      <th>Streak</th>
      <th>Badges</th>
    </tr>
  </thead>
  <tbody>
    {% for row in rows %}
    <tr>
      <td>{{ row.user.username }}</td>
      <td>{{ row.completed_total }} / {{ total_examples }}</td>
      {% if settings.scoring_enabled %}<td>{{ row.score_total }}</td>{% endif %}
      <td>{{ row.streak_days }} day{{ "s" if row.streak_days != 1 else "" }}</td>
      <td>{{ row.badge_count }} / {{ total_badges }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
```

- [ ] **Step 5: Add the nav link in `app/core/templates/core/base.html`**

Re-read the file fresh first (earlier tasks in this plan don't touch it, but confirm). In the hamburger dropdown, add a "Leaderboard" item right after the existing Settings item:

```html
              <li><a class="dropdown-item" href="{{ url_for('core.settings_page') }}">Settings</a></li>
              <li><a class="dropdown-item" href="{{ url_for('core.leaderboard') }}">Leaderboard</a></li>
```

(Task 4 will add the Instructor view link immediately below this one — re-read the file fresh in Task 4 before editing, since this step changes what's there.)

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_leaderboard.py -v`
Expected: PASS (6 tests).

- [ ] **Step 7: Run the full suite to confirm no regressions**

Run: `pytest -q`
Expected: 619 passed, 3 skipped (613 + 6 new).

- [ ] **Step 8: Commit**

```bash
git add app/core/views.py app/core/templates/core/leaderboard.html app/core/templates/core/base.html tests/test_leaderboard.py
git commit -m "feat: add leaderboard page

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 4: Instructor aggregate view

**Files:**
- Modify: `app/core/views.py` (add route)
- Create: `app/core/templates/core/instructor.html`
- Modify: `app/core/templates/core/base.html` (nav link, admin-gated)
- Test: `tests/test_instructor_view.py` (new)

**Interfaces:**
- Consumes: `compute_user_stats(user_id)` (Task 2); `abort` (already imported in `app/core/views.py`, confirm still present).
- Produces: route `core.instructor_view` at `GET /instructor`.

**Orchestration note:** Re-read `app/core/views.py` and `app/core/templates/core/base.html` fresh before editing — Task 3 already added a route and a nav-dropdown line to each.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_instructor_view.py`:

```python
from app.core.models import User
from app.core.seed import seed_database


def _login_as(client, app, username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        user_id = user.id
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
    return user_id


def test_anonymous_visitor_is_redirected_to_switch_user(app, client):
    seed_database(app)
    response = client.get("/instructor")
    assert response.status_code == 302
    assert "/switch-user" in response.headers["Location"]


def test_non_admin_user_gets_403(app, client):
    seed_database(app)
    _login_as(client, app, "alice")
    response = client.get("/instructor")
    assert response.status_code == 403


def test_admin_sees_every_seeded_user_including_zero_progress(app, client):
    seed_database(app)
    _login_as(client, app, "admin")
    response = client.get("/instructor")
    assert response.status_code == 200
    body = response.data.decode()
    for username in ("alice", "bob", "carol", "admin"):
        assert username in body


def test_admin_view_shows_never_for_users_with_no_activity(app, client):
    seed_database(app)
    _login_as(client, app, "admin")
    response = client.get("/instructor")
    assert b"Never" in response.data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_instructor_view.py -v`
Expected: FAIL — 404s (`/instructor` doesn't exist yet).

- [ ] **Step 3: Add the route to `app/core/views.py`**

```python
@core_bp.route("/instructor")
def instructor_view():
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=url_for("core.instructor_view")))
    if viewer.role != "admin":
        abort(403)

    total_examples = sum(len(c.examples) for c in CATEGORIES)
    rows = []
    for user in User.query.order_by(User.username).all():
        stats = compute_user_stats(user.id)
        rows.append(
            {
                "user": user,
                "completed_total": stats["completed_total"],
                "score_total": stats["score_total"],
                "streak_days": stats["streak_days"],
                "badge_count": len(stats["badges"]),
                "last_active": stats["last_active"],
            }
        )
    rows.sort(key=lambda r: r["completed_total"], reverse=True)

    return render_template(
        "core/instructor.html",
        rows=rows,
        total_examples=total_examples,
        total_badges=len(CATEGORIES),
    )
```

- [ ] **Step 4: Create `app/core/templates/core/instructor.html`**

```html
{% extends "core/base.html" %}
{% block title %}Instructor view — OWASP Top 10 Training Lab{% endblock %}
{% block content %}
<h1>Instructor view</h1>
<p class="lead">Aggregate progress across every seeded account.</p>

<table class="table">
  <thead>
    <tr>
      <th>User</th>
      <th>Completed</th>
      {% if settings.scoring_enabled %}<th>Score</th>{% endif %}
      <th>Streak</th>
      <th>Badges</th>
      <th>Last active</th>
    </tr>
  </thead>
  <tbody>
    {% for row in rows %}
    <tr>
      <td>{{ row.user.username }}</td>
      <td>{{ row.completed_total }} / {{ total_examples }}</td>
      {% if settings.scoring_enabled %}<td>{{ row.score_total }}</td>{% endif %}
      <td>{{ row.streak_days }} day{{ "s" if row.streak_days != 1 else "" }}</td>
      <td>{{ row.badge_count }} / {{ total_badges }}</td>
      <td>{% if row.last_active %}{{ row.last_active.isoformat() }}{% else %}Never{% endif %}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
```

- [ ] **Step 5: Add the admin-gated nav link in `app/core/templates/core/base.html`**

Re-read the file fresh (Task 3 added the Leaderboard line just above where this goes). Add immediately after the Leaderboard `<li>`:

```html
              <li><a class="dropdown-item" href="{{ url_for('core.leaderboard') }}">Leaderboard</a></li>
              {% if current_user and current_user.role == "admin" %}
              <li><a class="dropdown-item" href="{{ url_for('core.instructor_view') }}">Instructor view</a></li>
              {% endif %}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_instructor_view.py -v`
Expected: PASS (4 tests).

- [ ] **Step 7: Run the full suite to confirm no regressions**

Run: `pytest -q`
Expected: 623 passed, 3 skipped (619 + 4 new).

- [ ] **Step 8: Commit**

```bash
git add app/core/views.py app/core/templates/core/instructor.html app/core/templates/core/base.html tests/test_instructor_view.py
git commit -m "feat: add admin-gated instructor aggregate view

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 5: Per-category badges on the home page

**Files:**
- Modify: `app/core/views.py` (`home()`)
- Modify: `app/core/templates/core/home.html`
- Test: `tests/test_home_badges.py` (new)

**Interfaces:**
- Consumes: `compute_user_stats(user_id)["badges"]` (Task 2).

**Orchestration note:** Re-read `app/core/views.py` fresh before editing `home()` — Tasks 1, 3, and 4 have all touched this file already.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_home_badges.py`:

```python
from datetime import datetime

from app.core.models import ExampleProgress, User
from app.core.nav import CATEGORIES
from app.core.seed import seed_database
from app.extensions import db


def _login_as(client, app, username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        user_id = user.id
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
    return user_id


def test_anonymous_visitor_sees_no_earned_badges(app, client):
    seed_database(app)
    response = client.get("/")
    assert b"text-bg-success" not in response.data


def test_completing_a_whole_category_shows_its_badge(app, client):
    seed_database(app)
    user_id = _login_as(client, app, "alice")
    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")

    with app.app_context():
        for example in a10.examples:
            db.session.add(
                ExampleProgress(
                    user_id=user_id,
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
    user_id = _login_as(client, app, "alice")
    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")

    with app.app_context():
        db.session.add(
            ExampleProgress(
                user_id=user_id,
                example_id=a10.examples[0].id,
                completed_at=datetime.utcnow(),
                points_awarded=a10.examples[0].base_points(),
            )
        )
        db.session.commit()

    response = client.get("/")
    assert b"text-bg-success" not in response.data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_home_badges.py -v`
Expected: FAIL — `test_completing_a_whole_category_shows_its_badge` fails (no `text-bg-success` in the response yet).

- [ ] **Step 3: Update `home()` in `app/core/views.py`**

Find the current `home()` function. After the existing `progress_rows`/`completed_ids` setup and before the `category_stats = []` loop, add:

```python
    badges = compute_user_stats(viewer.id)["badges"] if viewer is not None else {}
```

Inside the `category_stats.append({...})` call, add one new key, `"badge_earned"`:

```python
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
```

- [ ] **Step 4: Update `app/core/templates/core/home.html`**

Change the card title line (currently `<h5 class="card-title">{{ cs.category.short_id }}: {{ cs.category.title }}</h5>`) to:

```html
        <h5 class="card-title d-flex justify-content-between align-items-center">
          <span>{{ cs.category.short_id }}: {{ cs.category.title }}</span>
          {% if cs.badge_earned %}
          <span class="badge text-bg-success" title="All {{ cs.category.short_id }} examples completed">🏅 {{ cs.category.short_id }}</span>
          {% else %}
          <span class="badge text-bg-secondary" title="Complete every {{ cs.category.short_id }} example to earn this badge">{{ cs.category.short_id }}</span>
          {% endif %}
        </h5>
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_home_badges.py -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Run the full suite to confirm no regressions**

Run: `pytest -q`
Expected: 626 passed, 3 skipped (623 + 3 new).

- [ ] **Step 7: Commit**

```bash
git add app/core/views.py app/core/templates/core/home.html tests/test_home_badges.py
git commit -m "feat: show per-category completion badges on the home page

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 6: Final integration — README and full-suite verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Re-read `README.md`'s "More pages" section fresh**

Confirm its current exact text (it should still match the bullets for Home/Tools/About plus the theme-toggle line — Tasks 1-5 do not touch `README.md`).

- [ ] **Step 2: Add Leaderboard and Instructor view bullets**

Insert two new bullets after the existing **Home** bullet and before **Tools**:

```markdown
- **Leaderboard** (`/leaderboard`) — every seeded account's completed-example
  count, streak, and badge count, sortable by most completed, highest score
  (when scoring is enabled), or longest streak. No login required to view.
- **Instructor view** (`/instructor`) — the same per-user stats as the
  leaderboard, in one table, for every seeded account including ones with no
  progress yet. Only visible to a user whose account has the `admin` role
  (the seeded `admin` account).
```

- [ ] **Step 3: Run the full suite fresh**

Run: `pytest -q`
Expected: 626 passed, 3 skipped.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document the leaderboard and instructor view pages

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage:**
- Streaks / `ActivityDay` table → Task 1. ✅
- `compute_user_stats()` shared helper (badges, streak, totals) → Task 2. ✅
- Leaderboard, 3 sort modes, dropping "fastest completion" → Task 3. ✅
- Per-category badges on home page → Task 5. ✅
- Admin-gated instructor view → Task 4. ✅
- Nav bar additions (Leaderboard unconditional, Instructor conditional on admin) → Tasks 3 and 4. ✅
- "Plain Bootstrap, no new CSS" scope boundary → respected in every template (Tasks 3, 4, 5). ✅
- README schema-caveat update → **deliberately not done** (see Global Constraints — a new table doesn't need it; doing so would add an inaccurate claim). This is a correction to the spec's Current State section, not a gap.

**2. Placeholder scan:** No TBD/TODO. Every step has complete, runnable code and exact test code. No task says "similar to Task N" without repeating the code.

**3. Type/naming consistency:** `compute_user_stats()`'s return dict (`completed_total`, `score_total`, `streak_days`, `badges`, `last_active`) is defined once in Task 2 and consumed with those exact keys, unchanged, in Task 3 (`leaderboard()`), Task 4 (`instructor_view()`), and Task 5 (`home()`, badges-only). `record_activity(user_id)` (Task 1) is imported and called identically in both call sites. Route names (`core.leaderboard`, `core.instructor_view`) are referenced consistently between the routes themselves (Tasks 3/4) and the nav template `url_for()` calls (Tasks 3/4) and the redirect in `instructor_view()` (Task 4).

**4. Running total sanity check:** 600 (baseline) + 4 (Task 1) + 9 (Task 2) + 6 (Task 3) + 4 (Task 4) + 3 (Task 5) = 626 passed, 3 skipped at Task 6. Each task's "expected" step count matches this running total.
