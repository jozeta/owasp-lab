# OWASP Top 10 Training Lab — Progress Tracking & Stats Page Design Spec

Date: 2026-09-21
Status: Approved
Sub-project 7 of the roadmap — the final remaining piece after sub-project 6
(A03 expansion: XXE, SSTI, LDAP, plus SQLi/XSS/CMD-injection deepening),
which shipped and merged in full.

## Purpose

Let a learner mark which of the app's ~26 example pages (spanning A01–A04)
they've completed, and see their progress at a glance on a new Stats page —
without adding per-example detection logic, and without touching any of the
existing ~26 individual example routes or templates.

## Decisions from brainstorming

- **Progress is a global singleton, like `Settings` — not tied to the
  existing `current_user`/`session["user_id"]` mechanism.** That mechanism
  (`switch_user`, `get_current_user()`) is itself part of the A01
  broken-access-control exercises — logging in as one of four fixed seeded
  users (alice/bob/carol/admin) to demonstrate IDOR and role-escalation
  flaws — not a real trainee identity. Tying progress to it would scramble
  a learner's progress every time they switch users mid-exercise, and
  wouldn't distinguish separate trainees on a shared instance anyway, since
  those four users are fixed training fixtures, not learner accounts.
- **Completion is per-example only, not per-Task.** A handful of examples
  (from the A03-deepening sub-projects) have an internal multi-task
  "Show solution" structure, but most examples don't — a uniform
  per-example mark keeps the feature simple and consistent across all ~26
  examples regardless of internal structure.
- **Completion is marked manually by the learner (a button), not detected
  automatically.** Automatic success-detection would require new, bespoke
  logic added to roughly 26 existing routes across 4 categories, built by
  many different sub-projects with different vulnerability mechanics — a
  large, fragile undertaking (a false negative would block progress a
  learner actually earned). Manual marking matches how the existing
  "Show solution" UI already works: self-paced, learner-driven.
- **The key architectural finding that shrinks this feature's scope:**
  every example page already extends the shared
  `core/example_page_base.html` template, and Flask's `request.endpoint`
  is already available in every template render via the existing
  `inject_globals()` context processor in `app/core/__init__.py` (the same
  mechanism that already powers the sidebar's active-link highlighting and
  `active_category` detection). This means the "Mark as done" control can
  be added **once**, to the shared base template, with **zero** changes
  needed to any of the ~26 individual example route functions or
  templates — the context processor just needs to additionally resolve
  which `ExampleNav` matches the current request and inject it.
- **"Reset lab" (`reset_database()`) already wipes progress with no special
  case needed.** It does `db.drop_all()` + reseed, which drops every table
  including any new one — confirmed by reading `app/core/seed.py`.
- **Stats page shows overall + per-category breakdowns only** — no
  difficulty breakdown, no list of specific incomplete examples. Kept
  lean per the scope discussion; either could be added later without
  touching the data model.
- **Scope: one spec, one plan** — not split into sub-projects. The
  shared-base-template insight above makes this comparable in size to a
  single A03 sub-project (one new model, one shared-template change
  instead of 26, two new routes, one new page), not the sprawling
  cross-cutting change it might otherwise have been.

## Components

### 1. New model

`app/core/models.py` gains:

```python
class ExampleProgress(db.Model):
    __tablename__ = "example_progress"

    id = db.Column(db.Integer, primary_key=True)
    example_id = db.Column(db.String(80), unique=True, nullable=False)
    completed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
```

A row's mere existence means that `example_id` (matching `ExampleNav.id`
from `app/core/nav.py`) is complete — "not completed" is simply "no row,"
so no boolean columns need updating as new examples get added over time.
No migration script needed — this app has no Alembic setup; every model
addition so far has relied on plain `db.create_all()`, and this follows
the same pattern.

### 2. Context processor additions

`app/core/__init__.py`'s existing `inject_globals()` gains two more
injected values, computed the same way `active_category` already is
(matching against `request.endpoint`):

```python
current_example = next(
    (e for c in CATEGORIES for e in c.examples if e.endpoint == request.endpoint),
    None,
)
completed_example_ids = {p.example_id for p in ExampleProgress.query.all()}
```

`current_example` is `None` on non-example pages (overview pages, Stats,
Settings, etc.) and the `ExampleNav` for the matching entry on a real
example page. `completed_example_ids` is a set available everywhere,
letting any template (the base template, the Stats page, the sidebar)
know at a glance which examples are done.

### 3. Toggle route

`app/core/views.py` gains a new route on the existing `core_bp` blueprint:

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

Validates `example_id` against the live `CATEGORIES` registry (and that
its endpoint is actually registered in this app instance — matching the
existing sidebar's defensive `registered_endpoints` check, relevant for
test apps built with a subset of blueprints) before touching the
database. Redirects straight back to the example's own page — no `next`/
referrer handling needed, since the example is already known from
`example_id`, avoiding any open-redirect surface entirely.

### 4. "Mark as done" control

`app/core/templates/core/example_page_base.html` gains a small addition
next to the existing difficulty badge:

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

Only rendered when `current_example` is set (i.e. never on overview,
Stats, Settings, or any other non-example page).

### 5. Stats page

`GET /stats` (new `core.stats_page` route), linked from the existing
hamburger dropdown menu in `base.html`, next to Tools/About/Settings:

```python
@core_bp.route("/stats")
def stats_page():
    completed_ids = {p.example_id for p in ExampleProgress.query.all()}
    category_stats = [
        {
            "category": c,
            "completed": sum(1 for e in c.examples if e.id in completed_ids),
            "total": len(c.examples),
        }
        for c in sorted(CATEGORIES, key=lambda c: c.short_id)
    ]
    completed_total = sum(cs["completed"] for cs in category_stats)
    total = sum(cs["total"] for cs in category_stats)
    return render_template(
        "core/stats.html",
        completed_total=completed_total,
        total=total,
        category_stats=category_stats,
    )
```

The template shows one large overall progress bar at the top ("14 of 26
examples completed — 54%") followed by one card per category, each with
its own "N of M completed" line and progress bar, using each category's
existing `short_id`/`title` — matching this app's existing Bootstrap
card/progress-bar visual language rather than inventing new UI patterns.

## Testing

- Toggle-route tests: marks an example complete; a second toggle
  un-marks it; an unknown `example_id` returns 404 without touching the
  database; redirects back to the toggled example's own page.
- A test confirming the "Mark as done" control renders only on real
  example pages (present on at least one example page, absent from a
  category overview page and from the Settings page).
- Stats-page tests: renders with correct overall count/percentage and
  correct per-category counts against real seeded + toggled progress
  data (not zero examples, not all examples — a genuine partial state).
- A test confirming "Reset lab" clears all `ExampleProgress` rows.
- A `test_stats.py`/`test_progress.py` file at the core level, matching
  the existing `test_core_views.py`/`test_settings.py`/`test_nav.py`
  naming convention for core (non-category-scoped) features.

## Out of scope for this spec

- Automatic success detection for any example.
- Per-Task completion tracking (only the whole-example granularity above).
- Difficulty-level breakdown or an incomplete-examples list on the Stats
  page (either could be added later without a data model change).
- Any per-learner/multi-user distinction — progress remains a single
  global state, matching `Settings`.
- Any change to the four existing seeded `User` accounts or the
  `switch_user`/`current_user` mechanism.
- Any change to any existing example's route, template, or tests.
