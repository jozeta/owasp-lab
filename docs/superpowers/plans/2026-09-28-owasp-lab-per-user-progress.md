# Per-User Progress Tracking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make example completion, hint usage, and score tracking per-user instead of a single global pool shared by every visitor — sub-project 1 of 4 toward per-user accounts, gamification, a Fjord visual redesign, and a roadmap homepage.

**Architecture:** `ExampleProgress` gains a required `user_id` foreign key; its uniqueness moves from "one row per example, globally" to "one row per (user, example)". The two routes that mutate progress (`toggle_progress`, `reveal_hint`) gain the exact login gate already used by several A01 example routes. The two read sites (`home()`, the `inject_globals()` context processor) scope every query by the current user, falling back to an empty/zero state for anonymous visitors rather than erroring or showing someone else's data.

**Tech Stack:** Flask, Flask-SQLAlchemy, Jinja2, pytest with Flask's test client.

**Spec:** `docs/superpowers/specs/2026-09-28-owasp-lab-per-user-progress-design.md`

## Global Constraints

- No new authentication system — reuse the existing no-password `session["user_id"]` / `POST /switch-user` mechanism exactly as-is. Do not add passwords, registration, or any new login route.
- `Settings` (show_explanations, show_exploit_instructions, scoring_enabled) stays a global singleton — do not make any part of it per-user.
- `toggle_progress()` and `reveal_hint()` must require a logged-in user (redirect to `/switch-user` with `next` set to the current path when anonymous) — matching the exact pattern already used in `app/categories/a01_access_control/routes.py` (`if viewer is None: return redirect(url_for("core.switch_user", next=request.path))`).
- Anonymous visitors must still be able to view the home page, every category overview, and every example page — only the two progress-mutating routes gain a login requirement. Never gate content-viewing routes as part of this plan.
- `reset_database()` must continue to wipe every user's progress in one shot (unchanged behavior) — do not scope resets to a single user.
- Every place that reads `ExampleProgress` must scope by `user_id=current_user.id` when a user is logged in, and treat progress as empty/zero (never error, never show another user's data) when anonymous.

---

### Task 1: Per-user data model, routes, and context processor

**Files:**
- Modify: `app/core/models.py`
- Modify: `app/core/views.py`
- Modify: `app/core/__init__.py`
- Modify: `app/core/templates/core/home.html`
- Modify: `README.md` (schema-change caveat)
- Create: `tests/test_per_user_progress.py`

**Interfaces:**
- Consumes: `get_current_user()` (`app/core/auth.py`, unchanged), the existing `session["user_id"]` / `POST /switch-user` mechanism (unchanged).
- Produces: `ExampleProgress.user_id` (required FK to `users.id`); every existing caller of `ExampleProgress` updated to filter/create by `(user_id, example_id)` instead of `example_id` alone.

This task lands the full behavior change in one commit — the model change and the routes that depend on it can't be usefully separated (the moment the unique constraint changes, every old `example_id`-only query is already semantically wrong), and Task 2 (fixing the existing tests this breaks) depends on this task's exact final shape.

- [ ] **Step 1: Read the current files fresh**

Read `app/core/models.py`, `app/core/views.py`, `app/core/__init__.py`, and `app/core/templates/core/home.html` in full. If anything has changed from what's shown below, adapt accordingly — this plan is accurate as of repo tip `90e5715`.

- [ ] **Step 2: Change the `ExampleProgress` model**

In `app/core/models.py`, change:

```python
class ExampleProgress(db.Model):
    __tablename__ = "example_progress"

    id = db.Column(db.Integer, primary_key=True)
    example_id = db.Column(db.String(80), unique=True, nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    hints_used = db.Column(db.Integer, nullable=False, default=0)
    points_awarded = db.Column(db.Integer, nullable=True)
```

to:

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

- [ ] **Step 3: Update `toggle_progress()` and `reveal_hint()` in `app/core/views.py`**

Change:

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
    db.session.commit()
    return redirect(url_for(example.endpoint))


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
    db.session.commit()
    return redirect(url_for(example.endpoint))
```

to:

```python
@core_bp.route("/progress/toggle", methods=["POST"])
def toggle_progress():
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=request.path))
    example_id = request.form.get("example_id", "")
    example = _find_example(example_id)
    if example is None:
        abort(404)
    progress = ExampleProgress.query.filter_by(user_id=viewer.id, example_id=example_id).first()
    if progress is None:
        progress = ExampleProgress(user_id=viewer.id, example_id=example_id, hints_used=0)
        db.session.add(progress)
    if progress.completed_at is None:
        progress.completed_at = datetime.utcnow()
        progress.points_awarded = compute_points(example, progress.hints_used)
    else:
        progress.completed_at = None
        progress.points_awarded = None
    db.session.commit()
    return redirect(url_for(example.endpoint))


@core_bp.route("/hints/reveal", methods=["POST"])
def reveal_hint():
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=request.path))
    example_id = request.form.get("example_id", "")
    example = _find_example(example_id)
    if example is None:
        abort(404)
    progress = ExampleProgress.query.filter_by(user_id=viewer.id, example_id=example_id).first()
    if progress is None:
        progress = ExampleProgress(user_id=viewer.id, example_id=example_id, hints_used=0)
        db.session.add(progress)
    if progress.hints_used < len(example.hints):
        progress.hints_used += 1
    db.session.commit()
    return redirect(url_for(example.endpoint))
```

Add `get_current_user` to this file's imports — change:
```python
from app.core.models import ExampleProgress, Settings, User, compute_points
```
to:
```python
from app.core.auth import get_current_user
from app.core.models import ExampleProgress, Settings, User, compute_points
```

- [ ] **Step 4: Update `home()` in `app/core/views.py`**

Change:

```python
@core_bp.route("/")
def home():
    progress_rows = {p.example_id: p for p in ExampleProgress.query.all()}
    completed_ids = {
        example_id for example_id, p in progress_rows.items() if p.completed_at is not None
    }
```

to:

```python
@core_bp.route("/")
def home():
    viewer = get_current_user()
    if viewer is None:
        progress_rows = {}
    else:
        progress_rows = {
            p.example_id: p for p in ExampleProgress.query.filter_by(user_id=viewer.id).all()
        }
    completed_ids = {
        example_id for example_id, p in progress_rows.items() if p.completed_at is not None
    }
```

Leave the rest of `home()` (the `category_stats` loop, `completed_total`, `overall_percent`, etc.) unchanged — it already derives everything from `progress_rows`/`completed_ids`, which now naturally come back empty for an anonymous visitor. Pass `viewer` through to the template so it can show the anonymous prompt:

```python
    return render_template(
        "core/home.html",
        completed_total=completed_total,
        total=total,
        overall_percent=overall_percent,
        category_stats=category_stats,
        earned_points_total=earned_points_total,
        max_points_total=max_points_total,
        viewer=viewer,
    )
```

- [ ] **Step 5: Update `inject_globals()` in `app/core/__init__.py`**

The current full function (verified fresh — `app/core/__init__.py`, inside `register_core()`), reproduced here in full since every line matters for this change:

```python
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

Replace it with:

```python
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
        viewer = get_current_user()
        if viewer is None:
            progress_rows = {}
        else:
            progress_rows = {
                p.example_id: p for p in ExampleProgress.query.filter_by(user_id=viewer.id).all()
            }
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
            current_user=viewer,
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

The only changes: `viewer = get_current_user()` is captured once (right after `current_example` is computed) instead of being called inline a second time inside the returned `dict`; `progress_rows` is now scoped by `viewer.id` (or empty when anonymous) instead of querying every row; and `current_user=get_current_user()` in the returned dict becomes `current_user=viewer`, reusing the single call. Every other line — `completed_example_ids`, `current_progress`, `current_example_pending_points`, `nav_score_earned`, `nav_score_max`, and the rest of the returned `dict` — is byte-for-byte identical to before; they already derive correctly from `progress_rows`, which now naturally comes back empty for an anonymous visitor.

`get_current_user` is already imported at the top of `register_core()` (`from app.core.auth import get_current_user`) — no new import needed.

- [ ] **Step 6: Add the anonymous-visitor prompt to `home.html`**

In `app/core/templates/core/home.html`, change:

```html
{% extends "core/base.html" %}
{% block title %}OWASP Top 10 Training Lab{% endblock %}
{% block content %}
<h1>OWASP Top 10 (2021) Training Lab</h1>
<p class="lead">Pick a category below to see its overview and graduated, exploitable examples.</p>
```

to:

```html
{% extends "core/base.html" %}
{% block title %}OWASP Top 10 Training Lab{% endblock %}
{% block content %}
<h1>OWASP Top 10 (2021) Training Lab</h1>
<p class="lead">Pick a category below to see its overview and graduated, exploitable examples.</p>

{% if not viewer %}
<div class="alert alert-info">
  Your progress isn't being tracked yet.
  <a href="{{ url_for('core.switch_user', next=request.path) }}">Pick a user</a>
  to track completions, hints, and score under your own name.
</div>
{% endif %}
```

- [ ] **Step 7: Update the README's existing schema-change caveat**

Find the paragraph in `README.md`'s Settings section, currently:
```
If you're running under Docker and your Postgres data volume was created before a
schema change landed (for example, an older checkout without the A07 MFA examples'
`pending_mfa_code` column), clicking "Reset lab" in the UI reseeds rows but won't add
new columns to already-existing tables. In that case, run
`docker compose down -v && docker compose up -d` once to drop the old volume and let
the app recreate the schema from scratch, then use "Reset lab" as normal afterward.
```
change it to:
```
If you're running under Docker and your Postgres data volume was created before a
schema change landed (for example, an older checkout without the A07 MFA examples'
`pending_mfa_code` column, or without per-user progress tracking's `user_id` column
on `example_progress`), clicking "Reset lab" in the UI reseeds rows but won't add
new columns to already-existing tables. In that case, run
`docker compose down -v && docker compose up -d` once to drop the old volume and let
the app recreate the schema from scratch, then use "Reset lab" as normal afterward.
```

**Note:** read this paragraph fresh from the live file before editing (do not assume the wrap points above match character-for-character) — this plan's own established practice is to treat the real file's current text as source of truth.

- [ ] **Step 8: Write the per-user isolation test**

Create `tests/test_per_user_progress.py`:

```python
from app.core.models import ExampleProgress, User
from app.core.nav import CATEGORIES
from app.core.seed import seed_database


def _safe_test_example():
    # Same rationale as tests/test_progress.py's helper: sqli-login has no
    # login/session requirement of its own to VIEW, unlike CATEGORIES[0]'s
    # first example.
    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    return next(e for e in a03.examples if e.id == "sqli-login")


def _login_as(client, app, username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        user_id = user.id
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
    return user_id


def test_anonymous_progress_toggle_redirects_to_switch_user(app, client):
    seed_database(app)
    example = _safe_test_example()
    response = client.post("/progress/toggle", data={"example_id": example.id})
    assert response.status_code == 302
    assert "/switch-user" in response.headers["Location"]


def test_anonymous_hint_reveal_redirects_to_switch_user(app, client):
    seed_database(app)
    example = _safe_test_example()
    response = client.post("/hints/reveal", data={"example_id": example.id})
    assert response.status_code == 302
    assert "/switch-user" in response.headers["Location"]


def test_two_users_progress_on_the_same_example_is_isolated(app, client):
    seed_database(app)
    example = _safe_test_example()
    examples = [e for category in CATEGORIES for e in category.examples]

    _login_as(client, app, "alice")
    client.post("/progress/toggle", data={"example_id": example.id})

    _login_as(client, app, "bob")
    response = client.get("/")
    body = response.data.decode()
    # Same text format as test_progress.py's
    # test_home_page_shows_zero_percent_when_nothing_completed: bob's own
    # progress is untouched by alice's completion above.
    assert f"0 of {len(examples)} completed — 0%" in body

    with app.app_context():
        alice_id = User.query.filter_by(username="alice").first().id
        bob_id = User.query.filter_by(username="bob").first().id
        alice_progress = ExampleProgress.query.filter_by(
            user_id=alice_id, example_id=example.id
        ).first()
        bob_progress = ExampleProgress.query.filter_by(
            user_id=bob_id, example_id=example.id
        ).first()
        assert alice_progress is not None
        assert alice_progress.completed_at is not None
        assert bob_progress is None


def test_bob_completing_the_example_does_not_affect_alice(app, client):
    seed_database(app)
    example = _safe_test_example()

    _login_as(client, app, "alice")
    client.post("/progress/toggle", data={"example_id": example.id})

    _login_as(client, app, "bob")
    client.post("/progress/toggle", data={"example_id": example.id})

    with app.app_context():
        alice_id = User.query.filter_by(username="alice").first().id
        bob_id = User.query.filter_by(username="bob").first().id
        alice_progress = ExampleProgress.query.filter_by(
            user_id=alice_id, example_id=example.id
        ).first()
        bob_progress = ExampleProgress.query.filter_by(
            user_id=bob_id, example_id=example.id
        ).first()
        assert alice_progress.completed_at is not None
        assert bob_progress.completed_at is not None
```

- [ ] **Step 9: Run the new test file to verify it passes**

Run: `pytest tests/test_per_user_progress.py -v`
Expected: PASS (all 4 tests).

- [ ] **Step 10: Commit**

```bash
git add app/core/models.py app/core/views.py app/core/__init__.py \
        app/core/templates/core/home.html README.md \
        tests/test_per_user_progress.py
git commit -m "feat(core): make example progress, hints, and score per-user"
```

**Do not run the full test suite yet** — `tests/test_progress.py` and `tests/test_hints.py` are expected to fail extensively after this commit (they assume anonymous progress-tracking works). That's Task 2.

---

### Task 2: Fix existing tests broken by the login requirement

**Files:**
- Modify: `tests/test_progress.py`
- Modify: `tests/test_hints.py`

**Interfaces:**
- Consumes: Task 1's `toggle_progress()`/`reveal_hint()` login requirement and `ExampleProgress.user_id` column (already landed).
- Produces: nothing new downstream — this task only makes the existing test suite pass again against Task 1's real behavior change.

Verified before this plan was written: `grep -rln "ExampleProgress\|progress/toggle\|hints/reveal" tests/` returns ONLY `tests/test_progress.py` and `tests/test_hints.py` — no other test file in the whole suite touches this behavior, so this task's scope is exhaustive.

- [ ] **Step 1: Read both files fresh**

Read `tests/test_progress.py` and `tests/test_hints.py` in full. If anything has changed from what's shown below, adapt accordingly.

- [ ] **Step 2: Add a `_login_as` helper to `tests/test_progress.py`**

At the top of `tests/test_progress.py`, after the existing imports, add:

```python
from app.core.models import User


def _login_as(client, app, username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        user_id = user.id
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
    return user_id
```

- [ ] **Step 3: Add a login call to every test that POSTs to `/progress/toggle`**

Every test function in `tests/test_progress.py` that calls `client.post("/progress/toggle", ...)` needs `_login_as(client, app, "alice")` (any seeded username is fine — use `"alice"` consistently for this file) called once, right after `seed_database(app)`, before the first `client.post(...)` call. This applies to:
- `test_toggle_progress_marks_example_complete`
- `test_toggle_progress_unmarks_on_second_toggle`
- `test_toggle_progress_rejects_unknown_example_id`
- `test_toggle_progress_redirects_to_the_example_page`
- `test_completed_example_shows_checkmark_button`
- `test_reset_lab_clears_progress`
- `test_home_page_shows_correct_overall_count`
- `test_home_page_shows_correct_per_category_count`

Every `ExampleProgress.query.filter_by(example_id=example.id)` in these same tests must ALSO gain `user_id=user_id` (the value returned by `_login_as`), since the column is now required and the old query (no `user_id` filter at all) would still technically run under SQLAlchemy but is no longer the correct way to look up "the progress row this test just created" — use the exact `user_id` value `_login_as` returned.

`test_toggle_progress_rejects_unknown_example_id` and `test_mark_as_done_button_appears_on_example_page` and `test_mark_as_done_button_absent_on_category_overview_page` and `test_mark_as_done_button_absent_on_settings_page` and `test_home_page_shows_progress` and `test_home_page_shows_zero_percent_when_nothing_completed` and `test_stats_page_and_dropdown_link_are_removed` do NOT need a login call — read each one fresh to confirm whether it actually posts to a progress-mutating route or only does a `GET`; several of these only render pages and were never actually exercising anonymous progress-mutation in the first place, so don't add an unnecessary login call to a test that doesn't need one.

- [ ] **Step 4: Run `tests/test_progress.py` to verify it passes**

Run: `pytest tests/test_progress.py -v`
Expected: PASS (every test in the file).

- [ ] **Step 5: Add the same login pattern to `tests/test_hints.py`**

Add the identical `_login_as` helper (import `User` from `app.core.models` alongside the file's existing imports) and add a login call after `seed_database(app)` in every test that calls `client.post("/hints/reveal", ...)` or `client.post("/progress/toggle", ...)`:
- `test_reveal_hint_increments_hints_used`
- `test_reveal_hint_is_capped_at_the_examples_hint_count`
- `test_revealed_hint_text_appears_on_the_example_page`
- `test_mark_as_done_button_previews_exact_point_value`
- `test_points_freeze_at_completion_and_survive_later_hint_reveals`
- `test_unmarking_and_recompleting_recomputes_points_fresh`
- `test_home_page_shows_score_totals_when_scoring_enabled`
- `test_nav_bar_shows_running_score_on_any_page_when_scoring_enabled`

`test_scoring_enabled_hides_exploit_instructions_regardless_of_stored_value`, `test_settings_post_does_not_clear_show_exploit_instructions_while_enabling_scoring`, and `test_score_ui_absent_when_scoring_disabled` do NOT touch progress/hints routes — do not add a login call to these.

Every `ExampleProgress.query.filter_by(example_id=example.id)` in the tests listed above must gain `user_id=user_id` matching Step 3's pattern.

- [ ] **Step 6: Run `tests/test_hints.py` to verify it passes**

Run: `pytest tests/test_hints.py -v`
Expected: PASS (every test in the file).

- [ ] **Step 7: Run the full test suite**

Run: `pytest -q`
Expected: green, zero failures. This plan doesn't change the total example/hints count, so `test_all_examples_have_hints.py`/`test_hints.py`'s count/score assertions are unaffected — expect the exact same `594 passed, 3 skipped` baseline as before this plan, confirm the ACTUAL observed count rather than assuming it.

- [ ] **Step 8: Commit**

```bash
git add tests/test_progress.py tests/test_hints.py
git commit -m "test(core): log in before progress/hint actions now that they require a user"
```

---

## Self-Review Notes (for the plan author, not an execution step)

**Spec coverage:** all four call sites the spec identified (`home()`, `toggle_progress()`, `reveal_hint()`, `inject_globals()`) are covered in Task 1, with exact before/after code for each, verified against the actual current file contents read fresh during plan-writing.

**Placeholder scan:** an initial draft of Task 1 Step 8's isolation test had a throwaway placeholder assertion — caught during this self-review and replaced with the exact real assertion (matching `test_home_page_shows_zero_percent_when_nothing_completed`'s established text format) rather than left as implementer work. No other TBD/TODO/placeholder anywhere in the plan; every step has complete, literal code.

**Type/naming consistency:** `viewer` is used consistently as the local variable name for `get_current_user()`'s result across `toggle_progress()`, `reveal_hint()`, `home()`, and `inject_globals()`, matching the existing convention already used in every A01 route that has this same login gate.

**Task ordering and the intentional broken-tests window:** Task 1 is explicitly instructed NOT to run the full suite before committing, because `tests/test_progress.py`/`tests/test_hints.py` are known to fail until Task 2 lands — this is called out explicitly rather than left as a surprise, and Task 2's own pre-flight note (in the SDD ledger, not this plan) should record this as an expected, already-understood state rather than a regression to investigate.

**Test scope verified exhaustive:** `grep -rln "ExampleProgress" tests/` was re-run during this self-review and returns only the two files this plan already covers — no other test file anywhere in the suite touches this model or these two routes.
