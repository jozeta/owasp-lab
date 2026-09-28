# Gamification: Leaderboard, Badges, Streaks & Instructor View — Design

## Goal

Sub-project 2 of 4 (per-user foundation ✅ → **gamification + instructor view** → Fjord visual redesign → roadmap homepage). Adds:
1. A leaderboard (most completed / highest score / longest streak).
2. Per-category completion badges (10 possible, one per OWASP category).
3. Daily practice streaks.
4. An instructor/aggregate view showing every user's progress at a glance.

All of this builds directly on sub-project 1's per-user `ExampleProgress` data — nothing here would be possible against the old global-progress model.

## Current State (verified fresh)

- `ExampleProgress` (per-user as of sub-project 1): `user_id`, `example_id`, `completed_at`, `hints_used`, `points_awarded`.
- `User.role` already exists and is already `"admin"` for the seeded `admin` account, `"user"` for `alice`/`bob`/`carol` — used today only by A01's *intentionally broken* "Hidden Admin Panel" example (which deliberately never checks it). This sub-project's instructor view will be the first place in the app that correctly checks `role == "admin"` — a real, working access-control check living beside its own deliberately-vulnerable twin next door.
- `toggle_progress()` and `reveal_hint()` (`app/core/views.py`) are the only two places progress-affecting activity happens; both already resolve `viewer` before touching the database.
- Nav bar (`app/core/templates/core/base.html`) has an existing "☰" dropdown menu (Tools / About / Settings / Log out) — the natural home for new "Leaderboard" and "Instructor view" links.
- `home.html` renders one card per category today (title, completed count, progress bar, score) — the natural place to show that category's badge state for the current user.

## Design

### Streaks need one new table

`completed_at` gets cleared back to `None` when a user *un-marks* an example (toggling the "Mark as done" button off) — this means streak history cannot be derived from `ExampleProgress` alone, or a user's streak would silently shrink every time they experimented with unmarking something. A tiny, append-only table fixes this:

```python
class ActivityDay(db.Model):
    __tablename__ = "activity_days"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    date = db.Column(db.Date, nullable=False)

    __table_args__ = (db.UniqueConstraint("user_id", "date", name="uq_activity_user_date"),)
```

One row per `(user, calendar date)` the user did *anything* progress-related — toggling on, toggling off, or revealing a hint all count as "practiced today." Both `toggle_progress()` and `reveal_hint()` gain one line recording today's date for the current user (idempotent — if today's row already exists, do nothing).

**Streak** for a user = the length of the run of consecutive calendar dates in `ActivityDay`, counting backward from today, that contains no gap — ending at either today or yesterday (a user who practiced yesterday but hasn't yet today still has an active streak; one who last practiced two days ago does not).

### Per-category badges need no new table at all

A badge is simply "this user has completed every example in category X" — fully derivable from data that already exists:

```python
def earned_badge(user_id, category):
    completed = {
        p.example_id
        for p in ExampleProgress.query.filter_by(user_id=user_id).filter(
            ExampleProgress.completed_at.isnot(None)
        ).all()
        if p.example_id in {e.id for e in category.examples}
    }
    if len(completed) < len(category.examples):
        return None
    # Earned-at timestamp: the LATEST completion among this category's examples
    # -- i.e. the moment the last missing example was finished.
    return max(
        p.completed_at
        for p in ExampleProgress.query.filter_by(user_id=user_id).all()
        if p.example_id in {e.id for e in category.examples} and p.completed_at
    )
```

(Exact implementation detail — the plan will specify a single, non-N+1-query version of this, e.g. computing all ten categories' badge state from one query per user rather than one query per category.)

### A shared stats helper, used by all three new views

Home page, leaderboard, and instructor view all need the same shape of per-user data (completed count, score, streak, badges earned). Rather than duplicate this three times, add `app/core/stats.py`:

```python
def compute_user_stats(user_id):
    """Returns completed_total, score_total, streak_days, and badges (a
    dict of category id -> earned_at datetime, absent if not earned) for
    one user. Used by home(), leaderboard(), and instructor_view()."""
```

This is a new, single-responsibility module, matching this app's existing convention of small focused files under `app/core/` (`auth.py`, `nav.py`, `seed.py`).

### Leaderboard (`GET /leaderboard`)

Three sort modes via `?sort=completed|score|streak` (default `completed`), computed via `compute_user_stats()` for every `User`. Each row shows: username, completed count (`N / 105`), score (if scoring enabled), current streak, and a small "X/10 badges" count. Anonymous visitors can view the leaderboard (it's not sensitive — just names and progress of the lab's own seeded training accounts) but obviously can't appear on it themselves without picking a user first.

**"Fastest completion" is deliberately NOT a leaderboard metric** — every definition considered (fastest per-example, fastest to 100%, fastest average pace) was either ambiguous or would reward flukes (one lucky fast example) over genuine engagement. Dropped per user's approval of this design.

### Per-category badges shown on the home page

Each category card on `home.html` gains a small badge indicator (earned = filled, not yet = outline) next to its title, using `compute_user_stats()`'s badge dict. Anonymous visitors see all categories as unearned (consistent with their already-empty progress).

### Instructor view (`GET /instructor`)

Gated: `role != "admin"` → redirect to `/switch-user` (anonymous) or a plain "not authorized" message (logged in as a non-admin user) — this is the app's first GENUINELY correct role check, matching but not undermining A01's deliberately-broken twin. One table: every seeded `User`, their completed count, score, streak, badge count, and last-active date (derived from `MAX(ActivityDay.date)`). Sorted by completed count descending by default.

## Data Model Approach

One new table (`ActivityDay`) — append-only, two columns of real data plus the PK, one unique constraint. No changes to `ExampleProgress`, `User`, or `Settings`. Badges are fully computed, never stored.

## Self-Review

**Placeholder scan:** the `earned_badge()` sketch above is explicitly flagged as needing a non-N+1 rewrite at plan time — this is a deliberate implementation-detail deferral, not a design gap (the DESIGN — "badge = all examples in category complete, derived, not stored" — is fully specified; only the exact query shape is left to the plan, matching this project's convention of nailing exact code in the plan, not the spec).

**Internal consistency:** the three new views (`home()` update, `leaderboard()`, `instructor_view()`) all route through one shared `compute_user_stats()` helper, avoiding three divergent implementations of "how do we count a user's progress."

**Scope check:** no visual/CSS work is in scope here — plain Bootstrap, matching sub-project 1's home-page alert. The Fjord redesign (sub-project 3) will restyle everything gamification adds here, including giving the badges real iconography instead of a placeholder filled/outline indicator.
