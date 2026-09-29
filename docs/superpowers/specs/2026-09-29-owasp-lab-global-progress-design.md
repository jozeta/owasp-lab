# Revert to Global (Single-Student) Progress Tracking — Design

## Goal

Correct a wrong deployment assumption baked into sub-projects 1 and 2: this app is meant to run as **one instance per student**, not one shared instance across multiple real people. The `alice`/`bob`/`carol`/`admin` "act as" identities exist only so individual exploit examples can demonstrate access-control failures (IDOR, session handling, authorization) between *distinct fictional accounts* — they were never meant to represent distinct real students. Progress, hints, score, badges, and streaks should therefore be tracked **once, globally, per instance**, regardless of which identity happens to be active when the action was taken. The leaderboard and instructor view — both built to compare progress *across* users on one shared instance — no longer serve a purpose under this model and are removed.

## Current State (verified fresh against `main` at `ddccb24`)

- `ExampleProgress` (`app/core/models.py:41-53`) and `ActivityDay` (`:56-65`) are both scoped by `user_id` (FK to `users.id`), added in sub-project 1 and sub-project 2 respectively.
- `record_activity(user_id)` (`:68-77`) and `compute_user_stats(user_id)` (`app/core/stats.py:7-43`) both require a `user_id` and filter every query by it.
- `home()` (`app/core/views.py:31-79`), `toggle_progress()` (`:220-242`), and `reveal_hint()` (`:245-263`) all branch on `viewer = get_current_user()`, redirect an anonymous visitor to `/switch-user` before allowing a progress-affecting action, and filter every `ExampleProgress` query by `user_id=viewer.id`.
- `leaderboard()` (`:82-115`) and `instructor_view()` (`:118-147`) both iterate every `User` and call `compute_user_stats(user.id)` to compare them — this is the entire reason `compute_user_stats` takes a `user_id` at all.
- `app/core/__init__.py`'s `inject_globals()` mirrors `home()`'s per-viewer filtering for the nav's score display and the sidebar's completed-example highlighting.
- `home.html` shows an anonymous-visitor alert ("Your progress isn't being tracked yet... Pick a user") that only makes sense when progress is tied to a chosen identity.
- `base.html`'s hamburger dropdown links to `/leaderboard` (unconditional) and `/instructor` (gated on `current_user.role == "admin"`).
- **Confirmed by reading the pre-sub-project-1 code directly** (`git show e817ab2^:app/core/views.py`): before any of this existed, `toggle_progress()`/`reveal_hint()` had **no login requirement at all** — anonymous visitors could mark progress directly, because progress was already a single global concept. This design restores exactly that shape, not a new one.
- The `User` model, the `/switch-user` "act as" picker, and every individual exploit example's own use of `current_user`/session identity are **completely unrelated** to progress tracking — IDOR/session/authorization examples operate on separate domain objects (`User.bio`, `User.private_notes`, orders, comments, etc.), never on `ExampleProgress`. Removing `user_id` from progress tracking cannot break any exploit's correctness, because no exploit reads or writes `ExampleProgress` as part of its vulnerable behavior.

## Design

### Data model

- `ExampleProgress`: drop the `user_id` column and the `uq_progress_user_example` constraint entirely; restore a plain `unique=True` on `example_id` (its pre-sub-project-1 shape). One row per example, globally.
- `ActivityDay`: drop the `user_id` column and the `uq_activity_user_date` constraint; restore a plain `unique=True` on `date`. One row per calendar day *any* activity happened on this instance — the streak becomes "how many consecutive days has this instance been used," which is the correct question once there's only one real student behind however many fictional identities they've logged in as.
- `record_activity()`: drop its `user_id` parameter — idempotently records today's date, full stop.
- `compute_user_stats(user_id)` → `compute_stats()` (`app/core/stats.py`): drop the parameter and every `user_id` filter; the two-query shape (one for `ExampleProgress`, one for `ActivityDay`) is unchanged, just unscoped. Returns the same dict shape (`completed_total`, `score_total`, `streak_days`, `badges`, `last_active`) — `last_active` keeps its meaning ("last day this instance was used") even without a leaderboard/instructor view left to consume it directly; `home()` doesn't need it, but the field costs nothing to keep for symmetry and any future page that might want it.

### Routes

- `home()`: drop the `viewer`-branch entirely — `progress_rows` and `badges` are always computed globally (`ExampleProgress.query.all()`, `compute_stats()`). No `viewer=` passed to the template. This exactly restores the pre-sub-project-1 shape of this function, with sub-project 2's badge computation layered on top unscoped.
- `toggle_progress()` / `reveal_hint()`: drop the `viewer is None` redirect-to-switch-user branch entirely (restoring the pre-sub-project-1 behavior verified above) and drop every `user_id=` filter/argument. `record_activity()` is called with no argument.
- `leaderboard()` and `instructor_view()`: **removed** — the routes, their two templates (`leaderboard.html`, `instructor.html`), and their two nav-dropdown links in `base.html`.
- `inject_globals()` (`app/core/__init__.py`): drop the `viewer`-branch on `progress_rows`, matching `home()` — restores this function's pre-sub-project-1 shape exactly, with `current_user` still resolved from `get_current_user()` and passed through unchanged (nav display and exploit-identity purposes still need it).

### Templates

- `home.html`: remove the anonymous-visitor alert block entirely — there is no more "your progress isn't tracked" state, since progress was never gated on picking an identity in the first place.
- `base.html`: remove the Leaderboard and Instructor-view `<li>` items from the hamburger dropdown. Every other nav element (category links, "Logged in as X" / "Log in", the score display, the theme toggle, Tools/About/Settings, Log out) is untouched — all of it is either identity-switching UI (still needed for exploits) or settings/navigation unrelated to progress scoping.
- `switch_user.html`: **untouched** — it remains exactly what it always was, a way to "act as" a specific fictional identity for exploit purposes, now correctly decoupled from any notion of tracking "your" progress.

### What does NOT change

- The `User` model and its four seeded rows (`alice`/`bob`/`carol`/`admin`) — still needed by name/role for specific exploit examples (A01's broken admin-panel check, A02's leaked-credential dump, every IDOR example, etc.).
- `Settings`/`scoring_enabled` — already a global, instance-wide toggle; untouched.
- Every visual/Fjord-system change from sub-projects 3 and the dashboard rework — this is a pure data-model and route simplification layered under the existing presentation.
- Any individual category's exploit routes/templates — none of them reference `ExampleProgress`, `ActivityDay`, or `compute_user_stats`/`compute_stats`.

## Data Model Approach

Two column drops (`ExampleProgress.user_id`, `ActivityDay.user_id`) and their associated unique constraints, replaced with single-column uniques matching the pre-sub-project-1 shape exactly. No new tables. As with every prior schema change in this app, `db.create_all()` won't remove an existing column from an old Docker volume — the existing README caveat paragraph (already present, covering the `user_id` column's *addition*) needs a follow-up sentence noting this specific case now also requires the `docker compose down -v` reset, since this is the first time this project has ever needed to *remove* a column rather than add one.

## Self-Review

**Placeholder scan:** every removal/change above names the exact file, function, and current line numbers it targets, cross-checked against a fresh read of the actual current codebase during spec-writing (not assumed from memory of what earlier sub-projects built).

**Internal consistency:** the "what does NOT change" section is exhaustive against everything the Current State section inventoried — nothing is left ambiguous about the `User` model, `switch_user.html`, or `Settings`.

**Scope check:** this is a genuinely large sub-project — it touches 4 Python modules, 4 templates (2 of which are deleted outright), and (per a pre-spec repo survey) at least 10 test files totaling over 1000 lines, several of which test premises this design directly invalidates (e.g. `test_per_user_progress.py`'s entire point was proving isolation *between* users, which this design removes; `test_leaderboard.py` and `test_instructor_view.py` test features being deleted outright). The implementation plan must inventory every one of these test files individually and decide, per file, whether to delete it outright, rewrite its assertions to match the new global behavior, or leave it untouched — this spec deliberately does not attempt to enumerate every test-level change itself, since that requires the plan-writing step's own fresh read of each file's current exact content.
