# Per-User Progress Tracking — Design

## Goal

Make example completion, hint usage, and score tracking **per-user** instead of a single global pool shared by every visitor. This is sub-project 1 of a 4-part initiative (per-user foundation → gamification/instructor view → Fjord visual redesign → roadmap homepage); everything after this one depends on it.

No new authentication system: this extends the app's existing no-password "switch user" picker (`alice`/`bob`/`carol`/`admin`) rather than adding registration or passwords — this is a local training lab that already warns against public exposure, so real auth would add security surface for no real benefit.

## Current State (verified fresh against the actual code)

- `ExampleProgress` (`app/core/models.py`) has `example_id` as its unique key — **one row per example, globally**. `completed_at`, `hints_used`, and `points_awarded` are shared by every visitor to the instance.
- `Settings` (show_explanations, show_exploit_instructions, scoring_enabled) is a separate, genuinely global, singleton row — an instructor-level configuration toggle, not per-visitor state.
- `get_current_user()` (`app/core/auth.py`) reads `session["user_id"]`, set by the existing `POST /switch-user` route (`app/core/views.py`) — a plain picker with no password, already used by several A01 example routes to gate per-user actions (`if viewer is None: return redirect(url_for("core.switch_user", ...))`).
- Four call sites read/write `ExampleProgress` globally, unaware of `current_user` at all:
  - `home()` — builds per-category and overall stats from `ExampleProgress.query.all()`.
  - `toggle_progress()` (`POST /progress/toggle`) — looked up/created by `example_id` alone; currently works with **no login required at all**.
  - `reveal_hint()` (`POST /hints/reveal`) — same pattern, same lack of a login requirement.
  - `inject_globals()` (`app/core/__init__.py`, a Flask context processor run on every request) — computes `completed_example_ids`, `current_progress`, `nav_score_earned`/`nav_score_max` for the nav bar and every example page's "✓ Completed" / hint-reveal UI (`example_page_base.html`) and the per-category nav sidebar's completed-link styling (`base.html`).
- `reset_database()` (`app/core/seed.py`) does `db.drop_all()` + `db.create_all()` + reseed — fully generic, needs no change for a new column.
- **Existing tests assume anonymous progress-tracking works.** `tests/test_progress.py` and `tests/test_hints.py` contain roughly 18 call sites that `POST /progress/toggle` or `POST /hints/reveal` with no session set up at all, expecting them to succeed. Making these routes require login is a deliberate, correct behavior change (see below) — but every one of those call sites needs a login step added, or it will start hitting the new redirect-to-switch-user behavior instead of the route it's meant to be testing.

## Design

### Data model

Add a `user_id` column to `ExampleProgress`:

```python
class ExampleProgress(db.Model):
    __tablename__ = "example_progress"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    example_id = db.Column(db.String(80), nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    hints_used = db.Column(db.Integer, nullable=False, default=0)
    points_awarded = db.Column(db.Integer, nullable=True)

    __table_args__ = (db.UniqueConstraint("user_id", "example_id", name="uq_progress_user_example"),)
```

`user_id` is **not nullable** — every progress row belongs to a real user. There is no "anonymous" or "shared" bucket; anonymous visitors simply have no progress rows at all (see below).

`Settings` is unchanged — it stays a global singleton. Scoring on/off and hint-visibility are instructor-level site configuration, not personal state.

### Behavior change: progress-affecting actions require a logged-in user

`toggle_progress()` and `reveal_hint()` both gain the exact login gate already used by A01's example routes:

```python
viewer = get_current_user()
if viewer is None:
    return redirect(url_for("core.switch_user", next=request.path))
```

Every `ExampleProgress` lookup/creation in both routes is scoped to `(user_id=viewer.id, example_id=...)` instead of `example_id` alone.

**This is a deliberate behavior change**, not an oversight: progress genuinely can't be "per-user" if it can also be written with no user at all. It matches this app's own existing convention (many example routes already require being "logged in" via the same picker before a personal action is allowed) — it's simply extending that convention to the two generic progress routes that never had it.

### Read-side: anonymous visitors see zero, not an error, not everyone else's data

`home()` and `inject_globals()` both call `get_current_user()`. When it returns `None`:
- `home()`'s `category_stats` are computed with an empty progress set — every category shows `0 of N completed — 0%`, matching the shape already exercised by `test_home_page_shows_zero_percent_when_nothing_completed`.
- `inject_globals()`'s `completed_example_ids` becomes an empty set, `current_progress` falls back to the existing empty-placeholder `ExampleProgress(hints_used=0, completed_at=None, points_awarded=None)` (this fallback object already exists in the code for the "no progress row yet" case — reused as-is for "no user" too), and `nav_score_earned` becomes `0`.
- The home page gets one small addition: a dismissible prompt shown only when `current_user` is `None`, pointing at `/switch-user`, so an anonymous visitor understands why their nav shows `Score: 0 / 2270` — not a hard gate, since browsing category/example *content* anonymously already works today and should keep working.

When a user **is** logged in, every one of these four call sites filters/scopes by `user_id=viewer.id` instead of querying all rows.

### Test updates

Every anonymous `POST /progress/toggle` / `POST /hints/reveal` call in `tests/test_progress.py` and `tests/test_hints.py` needs a login step first, using the exact `session_transaction()` pattern already established in this session's own test files (e.g. `tests/test_a01_http_parameter_pollution.py`'s `_login_as` helper):

```python
def _login_as(client, app, username):
    from app.core.models import User
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        user_id = user.id
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
    return user_id
```

Beyond adding the login step, the *assertions* in most of these tests are unaffected — they were already checking a single user's-worth of behavior (toggle, then check it toggled), they just happened to run anonymously before. A few tests that build multi-example scenarios (e.g. `test_home_page_shows_correct_overall_count`) need to confirm the SAME logged-in user performs every action in the scenario, so their stats land in one place.

**New tests** to add: a per-user isolation test proving two different logged-in users' progress on the *same* example doesn't collide (alice completes `sqli-login`; bob's progress for `sqli-login` is unaffected and vice versa) — this is the actual point of the whole sub-project and deserves its own explicit proof, not just implied by the existing single-user tests still passing.

## Data Model Approach

One column addition + one unique-constraint change to an existing table (`ExampleProgress`). No new tables. No changes to `User`, `Settings`, or any category's own models.

## Self-Review

**Placeholder scan:** no TBD/TODO; the exact column, constraint, route-gate, and read-scoping changes are all fully specified.

**Internal consistency:** all four call sites that touch `ExampleProgress` today (`home()`, `toggle_progress()`, `reveal_hint()`, `inject_globals()`) are accounted for individually above — verified by grepping for every reference to `ExampleProgress` in `app/`, not assumed from memory.

**Scope check:** this spec covers only the per-user data model and the two routes/one context-processor/one view that touch it directly. The leaderboard, badges, streaks, instructor view, and any visual changes are explicitly OUT of scope for this sub-project — they're sub-projects 2-4, which build on top of this one's data model but aren't designed here.

**Ambiguity resolved:** the anonymous-visitor behavior (show zero + a soft prompt, vs. hard-gating the whole home page) was the one real design choice in this sub-project — resolved in favor of the softer option since it preserves the app's existing "content is always browsable anonymously" property and matches the shape of an already-passing test (`test_home_page_shows_zero_percent_when_nothing_completed`) almost exactly.
