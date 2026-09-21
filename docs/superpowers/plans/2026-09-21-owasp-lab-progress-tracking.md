# Progress Tracking & Stats Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a learner manually mark any of the app's ~26 example pages
as done, and see their progress (overall + per-category) on a new Stats
page — using one shared-template change instead of touching any of the
~26 individual example routes/templates.

**Architecture:** One new global model (`ExampleProgress`, a row per
completed example — existence means done, no boolean columns). The
existing `inject_globals()` context processor in `app/core/__init__.py`
gains two more values (`current_example`, `completed_example_ids`),
computed the same way `active_category` already is, from
`request.endpoint`. One generic toggle route and one Stats route on the
existing `core_bp` blueprint. The "Mark as done" control is added once to
the shared `example_page_base.html`.

**Tech Stack:** Flask, Jinja2, SQLAlchemy, Bootstrap 5 (`progress`
component), pytest + Flask test client.

**Spec:** `docs/superpowers/specs/2026-09-21-owasp-lab-progress-tracking-design.md`

## Global Constraints

- Progress is a single global state (matching `Settings`), never tied to
  `current_user`/`session["user_id"]` — that mechanism belongs to the A01
  broken-access-control exercises, not learner identity.
- Completion is per-example only — no per-Task granularity.
- No automatic success detection — completion is only ever set by the
  learner submitting the toggle form.
- No changes to any existing example's route, template, or tests.
- No changes to the `switch_user`/`current_user`/`User` mechanism.
- No Alembic migration — this app has none; every model addition so far
  relies on plain `db.create_all()` (called by `seed_database()`, which
  already runs at both app-startup (`wsgi.py`) and in every test's `app`
  fixture (`tests/conftest.py`)).
- `reset_database()` already does `db.drop_all()` + reseed, so
  `ExampleProgress` is wiped automatically on "Reset lab" — no
  special-case reset code needed.

---

### Task 1: Progress model, context processor, toggle route, "Mark as done" UI

**Files:**
- Modify: `app/core/models.py`
- Modify: `app/core/__init__.py`
- Modify: `app/core/views.py`
- Modify: `app/core/templates/core/example_page_base.html`
- Create: `tests/test_progress.py`

**Interfaces:**
- Produces: model `ExampleProgress` (`example_id: str`, `completed_at: datetime`);
  route `core.toggle_progress` at `POST /progress/toggle` (form field
  `example_id`); context values `current_example: ExampleNav | None` and
  `completed_example_ids: set[str]`, available in every template render.
- Consumes: `ExampleNav`/`CategoryNav`/`CATEGORIES` from `app/core/nav.py`
  (unchanged, read-only).

---

- [ ] **Step 1: Write the failing tests**

Create `tests/test_progress.py`:

```python
from app.core.models import ExampleProgress
from app.core.nav import CATEGORIES
from app.core.seed import seed_database
from app.extensions import db


def _safe_test_example():
    # Deliberately NOT "the first registered example" -- CATEGORIES[0] is
    # A01, whose first example (idor) requires being "logged in" as a
    # seeded user (redirects to /switch-user otherwise), which would make
    # every plain client.get() in this file 302 instead of 200. sqli-login
    # is a standalone A03 route with no login/session requirement at all
    # -- confirmed live before writing this test file.
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
        assert ExampleProgress.query.filter_by(example_id=example.id).first() is None


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

    # url_for() needs a request context to build a relative URL (this app
    # has no SERVER_NAME configured, so app_context() alone raises
    # RuntimeError) -- test_request_context() provides one without making
    # a real HTTP request.
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
```

The `app` and `client` fixtures come from the project's existing
`tests/conftest.py` (the `app` fixture already runs `db.create_all()`
before every test, so `ExampleProgress`'s table exists without needing
`seed_database` in every test — it's called explicitly only where a test
needs real seeded category data or a clean baseline).

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `pytest tests/test_progress.py -v`
Expected: collection fails with
`ImportError: cannot import name 'ExampleProgress'` — `app/core/models.py`
doesn't define it yet, and the test file imports it at module level.

- [ ] **Step 3: Add the `ExampleProgress` model**

In `app/core/models.py`, add the `datetime` import at the top and the new
model class at the end of the file:

```python
from datetime import datetime

from app.extensions import db


class Settings(db.Model):
    ...  # unchanged


class User(db.Model):
    ...  # unchanged


class ExampleProgress(db.Model):
    __tablename__ = "example_progress"

    id = db.Column(db.Integer, primary_key=True)
    example_id = db.Column(db.String(80), unique=True, nullable=False)
    completed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
```

(Only the `datetime` import and the new `ExampleProgress` class are new —
`Settings` and `User` are unchanged, shown here only for placement
context.)

- [ ] **Step 4: Add the context processor values**

In `app/core/__init__.py`, change the imports and the `inject_globals()`
function to the following (the whole file, since it's short):

```python
from flask import current_app, request


def register_core(app):
    from app.core.auth import get_current_user
    from app.core.models import ExampleProgress, Settings
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
        completed_example_ids = {p.example_id for p in ExampleProgress.query.all()}
        return dict(
            settings=Settings.get(),
            categories=sorted(CATEGORIES, key=lambda c: c.short_id),
            current_user=get_current_user(),
            active_category=active_category,
            registered_endpoints=set(current_app.view_functions.keys()),
            current_example=current_example,
            completed_example_ids=completed_example_ids,
        )
```

- [ ] **Step 5: Add the toggle route**

In `app/core/views.py`, change the top-of-file imports to:

```python
from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, session, url_for

from app.core.models import ExampleProgress, Settings, User
from app.core.nav import CATEGORIES
from app.core.seed import reset_database
from app.extensions import db
```

Then add the following route, after the existing `force_reset()` route
and before `tools_page()`:

```python
@core_bp.route("/progress/toggle", methods=["POST"])
def toggle_progress():
    example_id = request.form.get("example_id", "")
    example = next(
        (
            e
            for c in CATEGORIES
            for e in c.examples
            if e.id == example_id and e.endpoint in current_app.view_functions
        ),
        None,
    )
    if example is None:
        abort(404)
    existing = ExampleProgress.query.filter_by(example_id=example_id).first()
    if existing:
        db.session.delete(existing)
    else:
        db.session.add(ExampleProgress(example_id=example_id))
    db.session.commit()
    return redirect(url_for(example.endpoint))
```

- [ ] **Step 6: Add the "Mark as done" control**

In `app/core/templates/core/example_page_base.html`, replace the header
`<div>` block:

```html
<div class="d-flex justify-content-between align-items-center mb-3">
  <h1>{{ example_title }}</h1>
  <span class="badge {{ badge_classes[example_difficulty] }}">{{ example_difficulty }}</span>
</div>
```

with:

```html
<div class="d-flex justify-content-between align-items-center mb-3">
  <h1>{{ example_title }}</h1>
  <div class="d-flex align-items-center gap-2">
    {% if current_example %}
    <form method="post" action="{{ url_for('core.toggle_progress') }}" class="d-inline">
      <input type="hidden" name="example_id" value="{{ current_example.id }}">
      {% if current_example.id in completed_example_ids %}
      <button type="submit" class="btn btn-success btn-sm">✓ Completed</button>
      {% else %}
      <button type="submit" class="btn btn-outline-secondary btn-sm">Mark as done</button>
      {% endif %}
    </form>
    {% endif %}
    <span class="badge {{ badge_classes[example_difficulty] }}">{{ example_difficulty }}</span>
  </div>
</div>
```

(The rest of the file, everything after this header block, is unchanged.)

- [ ] **Step 7: Run the new tests to verify they pass**

Run: `pytest tests/test_progress.py -v`
Expected: all tests PASS.

- [ ] **Step 8: Run the full test suite**

Run: `pytest -v`
Expected: all tests PASS.

- [ ] **Step 9: Commit**

```bash
git add app/core/models.py \
        app/core/__init__.py \
        app/core/views.py \
        app/core/templates/core/example_page_base.html \
        tests/test_progress.py
git commit -m "feat: add example progress tracking with manual mark-as-done control"
```

---

### Task 2: Stats page

**Files:**
- Modify: `app/core/views.py`
- Create: `app/core/templates/core/stats.html`
- Modify: `app/core/templates/core/base.html`
- Modify: `tests/test_progress.py`

**Interfaces:**
- Consumes: `ExampleProgress`, `CATEGORIES`, and the `/progress/toggle`
  route from Task 1.
- Produces: route `core.stats_page` at `GET /stats`.

---

- [ ] **Step 1: Write the failing tests**

Append the following to `tests/test_progress.py`:

```python
def test_stats_page_loads(client):
    response = client.get("/stats")
    assert response.status_code == 200
    assert b"Your Progress" in response.data


def test_stats_page_shows_zero_percent_when_nothing_completed(app, client):
    seed_database(app)
    response = client.get("/stats")
    assert b"0%" in response.data


def test_stats_page_shows_correct_overall_count(app, client):
    seed_database(app)
    examples = [e for category in CATEGORIES for e in category.examples]
    assert len(examples) >= 2

    client.post("/progress/toggle", data={"example_id": examples[0].id})
    client.post("/progress/toggle", data={"example_id": examples[1].id})

    response = client.get("/stats")
    body = response.data.decode()
    assert f"2 of {len(examples)} completed" in body


def test_stats_page_shows_correct_per_category_count(app, client):
    seed_database(app)
    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    example = a03.examples[0]

    client.post("/progress/toggle", data={"example_id": example.id})

    response = client.get("/stats")
    body = response.data.decode()
    assert f"1 of {len(a03.examples)} completed" in body
    assert "A03: Injection" in body


def test_stats_link_appears_in_dropdown_menu(client):
    response = client.get("/")
    assert response.status_code == 200
    assert 'class="dropdown-item" href="/stats"' in response.data.decode()
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `pytest tests/test_progress.py -v -k stats`
Expected: every new test fails — `test_stats_page_loads` and the others
with a 404 (the `/stats` route doesn't exist yet),
`test_stats_link_appears_in_dropdown_menu` with the dropdown link missing
from the response body.

- [ ] **Step 3: Add the Stats route**

In `app/core/views.py`, add the following route, after `toggle_progress()`:

```python
@core_bp.route("/stats")
def stats_page():
    completed_ids = {p.example_id for p in ExampleProgress.query.all()}
    category_stats = []
    for category in sorted(CATEGORIES, key=lambda c: c.short_id):
        completed = sum(1 for e in category.examples if e.id in completed_ids)
        total = len(category.examples)
        category_stats.append(
            {
                "category": category,
                "completed": completed,
                "total": total,
                "percent": round(completed / total * 100) if total else 0,
            }
        )
    completed_total = sum(cs["completed"] for cs in category_stats)
    total = sum(cs["total"] for cs in category_stats)
    overall_percent = round(completed_total / total * 100) if total else 0
    return render_template(
        "core/stats.html",
        completed_total=completed_total,
        total=total,
        overall_percent=overall_percent,
        category_stats=category_stats,
    )
```

- [ ] **Step 4: Create the template**

Create `app/core/templates/core/stats.html`:

```html
{% extends "core/base.html" %}
{% block title %}Stats — OWASP Top 10 Lab{% endblock %}
{% block content %}
<h1>Your Progress</h1>

<div class="card mb-4">
  <div class="card-body">
    <div class="d-flex justify-content-between mb-1">
      <span class="fw-bold">Overall</span>
      <span>{{ completed_total }} of {{ total }} completed — {{ overall_percent }}%</span>
    </div>
    <div class="progress" role="progressbar" aria-valuenow="{{ completed_total }}" aria-valuemin="0" aria-valuemax="{{ total }}">
      <div class="progress-bar" style="width: {{ overall_percent }}%"></div>
    </div>
  </div>
</div>

{% for cs in category_stats %}
<div class="card mb-3">
  <div class="card-body">
    <div class="d-flex justify-content-between mb-1">
      <span class="fw-bold">{{ cs.category.short_id }}: {{ cs.category.title }}</span>
      <span>{{ cs.completed }} of {{ cs.total }} completed</span>
    </div>
    <div class="progress" role="progressbar" aria-valuenow="{{ cs.completed }}" aria-valuemin="0" aria-valuemax="{{ cs.total }}">
      <div class="progress-bar" style="width: {{ cs.percent }}%"></div>
    </div>
  </div>
</div>
{% endfor %}
{% endblock %}
```

- [ ] **Step 5: Add the dropdown-menu link**

In `app/core/templates/core/base.html`, add a new dropdown item
immediately before the existing "Tools" item:

```html
<li><a class="dropdown-item" href="{{ url_for('core.stats_page') }}">Stats</a></li>
<li><a class="dropdown-item" href="{{ url_for('core.tools_page') }}">Tools</a></li>
```

(Only the new "Stats" line is added — the "Tools" line already exists.)

- [ ] **Step 6: Run the new tests to verify they pass**

Run: `pytest tests/test_progress.py -v`
Expected: all tests PASS (both Task 1's and Task 2's).

- [ ] **Step 7: Run the full test suite**

Run: `pytest -v`
Expected: all tests PASS.

- [ ] **Step 8: Commit**

```bash
git add app/core/views.py \
        app/core/templates/core/stats.html \
        app/core/templates/core/base.html \
        tests/test_progress.py
git commit -m "feat: add Stats page with overall and per-category progress breakdowns"
```
