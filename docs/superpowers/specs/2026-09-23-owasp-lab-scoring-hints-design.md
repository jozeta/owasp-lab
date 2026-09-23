# Scoring + Hints System — Design Spec

## Overview

Add an optional scoring system to the OWASP Top 10 Training Lab: completing
an exercise awards points based on its difficulty (30 Hard / 20 Medium / 10
Easy), reduced by however many progressive hints were requested first.
Scoring is off by default and toggleable in Settings; while it's on, the
existing "Show exploit instructions" toggle has no effect (hints become the
sole guidance mechanism) — matching the user's original request verbatim:
*"If the scoring system is enabled, the step-by-step instructions should
remain hidden."*

This is the last item of the user's original 8-item bundled enhancement
request, executed after the quick settings/home-page wins and the A03 SQLi
content expansion (both already merged to `main`).

## Existing Infrastructure This Builds On

Explored fresh before this design (not assumed):

- **Completion tracking already exists and is real, not a stub.**
  `ExampleProgress` (`app/core/models.py`: `id`, `example_id` unique,
  `completed_at`) plus a "Mark as done" / "✓ Completed" toggle button on
  every example page (`example_page_base.html:9-16`, wired to
  `POST /progress/toggle` in `app/core/views.py`). Currently toggling off
  **deletes** the row entirely.
- **State is global, not per-session or per-user.** `Settings` is a
  singleton (`Settings.get()`), and `ExampleProgress` rows are keyed only
  by `example_id` with no session/user scoping. `User`/`switch_user` is an
  unrelated feature (IDOR demo dummy accounts) and does not gate anything
  real. The scoring system follows this same global-shared-state
  convention — one running score for the whole lab, not per-visitor.
- **`app/core/__init__.py`'s `context_processor`** already injects
  `settings`, `current_example` (an `ExampleNav`, matched by
  `request.endpoint`), and `completed_example_ids` into every template
  globally — this is the existing cross-cutting insertion point the
  scoring UI reuses.
- **`example_page_base.html`** is the single shared template every example
  across all 10 categories extends (`explanation` / `detect` /
  `exploitation` / `tasks` / `vulnerable_code` / `secure_code` /
  `live_example` blocks). Changes here reach all examples with no
  per-template edits (except adding each example's authored `hints` list —
  see below).
- **No formal migrations.** Schema is created via `db.create_all()`
  (`app/core/seed.py`), and reset via `drop_all()` + `create_all()`. This
  is the first schema change in this app's history that **adds columns to
  already-existing tables** (`settings`, `example_progress`) rather than
  creating new ones — `create_all()` does not retrofit columns onto a
  table that already exists. Operationally: any already-provisioned
  deployment must run "Reset Lab" (or `docker compose down -v && up`)
  after upgrading, exactly as already documented for every other schema
  change in this app, just newly relevant here. No code needs to handle
  this — it's a deployment note, not a migration system.
- **63 examples total, verified by count**: A01:3, A02:3, A03:19, A04:3,
  A05:6, A06:6, A07:6, A08:6, A09:6, A10:5. By difficulty: 19 Easy / 20
  Medium / 25 Hard. Max possible score if every example is completed with
  zero hints: `19×10 + 20×20 + 25×30 = 1340`.

## Decisions (confirmed with the user during brainstorming)

1. **Hint-authoring scope: all 63 examples, now.** Not a framework-only
   pilot — every existing example gets 3-5 real, example-specific
   authored hints as part of this project.
2. **Points formula: even split across hint slots.**
   `points = floor(base_points × (hint_count − hints_used + 1) / (hint_count + 1))`,
   using integer floor division. `hint_count` is that example's own
   authored hint count (3, 4, or 5 — varies per example). This guarantees
   finishing always earns at least 1 point (as long as `base_points ≥
   hint_count + 1`, which always holds: `base_points ∈ {10,20,30}`,
   `hint_count ∈ {3,4,5}` → `hint_count+1 ≤ 6 ≤ base_points`).
   Confirmed examples: Hard (30 pts, 4 hints) → 30/24/18/12/6 for
   0/1/2/3/4 hints used. Easy (10 pts, 3 hints) → 10/7/5/2 for 0/1/2/3
   hints used.
3. **Settings interaction: disable the checkbox, don't destroy its stored
   value.** While `scoring_enabled` is True, "Show exploit instructions"
   renders `disabled` in the Settings form with an explanatory note.
   Rather than relying on the browser's "disabled checkboxes aren't
   submitted" behavior (which would silently flip the stored value to
   False on the next save), the **effective** value used everywhere is
   derived: `settings.show_exploit_instructions and not
   settings.scoring_enabled`. The stored `show_exploit_instructions`
   value itself is left untouched by the settings-page POST handler
   whenever the incoming `scoring_enabled` value is True — so a user's
   original preference survives toggling scoring off again later.
4. **Score freezing: locked in at completion, not live.** Points are
   computed once from `hints_used` at the moment "Mark as done" is
   clicked, and stored as `points_awarded`. Revealing more hints
   afterward out of curiosity never reduces an already-earned score.
   Un-marking and re-completing recomputes fresh from whatever
   `hints_used` is at that later moment (hint usage itself is never reset
   by unmarking — see Data Model).
5. **Reset Lab wipes scores too.** `reset_lab()` already does
   `drop_all()`+`create_all()`, which already wipes all `ExampleProgress`
   rows (hence all hint-usage and score state along with them) — no new
   code needed, just confirmed as intended behavior.

## Data Model

Modify `app/core/models.py`:

```python
class Settings(db.Model):
    __tablename__ = "settings"

    id = db.Column(db.Integer, primary_key=True)
    show_explanations = db.Column(db.Boolean, nullable=False, default=True)
    show_exploit_instructions = db.Column(db.Boolean, nullable=False, default=False)
    scoring_enabled = db.Column(db.Boolean, nullable=False, default=False)

    @classmethod
    def get(cls):
        settings = cls.query.first()
        if settings is None:
            settings = cls(
                show_explanations=True,
                show_exploit_instructions=False,
                scoring_enabled=False,
            )
            db.session.add(settings)
            db.session.commit()
        return settings
```

```python
class ExampleProgress(db.Model):
    __tablename__ = "example_progress"

    id = db.Column(db.Integer, primary_key=True)
    example_id = db.Column(db.String(80), unique=True, nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    hints_used = db.Column(db.Integer, nullable=False, default=0)
    points_awarded = db.Column(db.Integer, nullable=True)
```

`completed_at` changes from always-set (row only exists when done) to
nullable (row exists once EITHER a hint has been revealed OR the example
has ever been marked done; `completed_at is not None` means "currently
counted as done"). This is a real behavior change vs. today's
delete-the-row-on-untoggle, needed so `hints_used` survives an
unmark/re-mark cycle rather than resetting to 0 (which would let a user
"launder" hint usage into a full-price score by toggling off and back on
— explicitly the loophole freezing-at-completion is meant to close).

## Extend `ExampleNav` for Hint Content

Modify `app/core/nav.py`:

```python
@dataclass
class ExampleNav:
    id: str
    title: str
    group: str
    difficulty: str
    endpoint: str
    hints: list = field(default_factory=list)

    def base_points(self) -> int:
        return {"Easy": 10, "Medium": 20, "Hard": 30}[self.difficulty]
```

Hint text lives as static Python content authored inline in each
category's `__init__.py`, alongside the `title`/`difficulty`/`endpoint`
fields every example already declares — one single source of truth for
both the hint *count* (needed server-side for the points formula) and the
hint *display text* (needed for rendering). This matches the app's
existing convention that only mutable state lives in the database; all
other teaching content (explanation/detect/exploitation prose) already
lives in Python/Jinja, never the DB, and hints follow the same rule.

**Hint-authoring rubric** (applied per example during implementation): 3-5
hints, ordered from vague to explicit.
- Hint 1: names the general technique category or points at *where* to
  look, without naming the specific payload or parameter.
- Middle hint(s): narrow toward the specific vulnerable
  parameter/mechanism, may show a partial or generic-shaped payload.
- Final hint: gives a working payload or the exact steps needed to
  reproduce the example's own "Exploitation" section — functionally
  equivalent information to what `show_exploit_instructions` would have
  shown, since a learner who spent every hint has effectively bought the
  full walkthrough.
Each example's exact hint count (3 vs. 4 vs. 5) and exact wording is an
authoring judgment call made per example during implementation, informed
by how many natural "steps" that specific vulnerability's exploitation
already has (mirroring each example's own existing exploitation
walkthrough) — this is not fixed globally.

## Points Calculation

New helper, e.g. in `app/core/models.py` or a small new
`app/core/scoring.py`:

```python
def compute_points(example, hints_used):
    hint_count = len(example.hints)
    if hint_count == 0:
        return example.base_points()
    shares = hint_count + 1
    used = min(hints_used, hint_count)
    return (example.base_points() * (shares - used)) // shares
```

(The `hint_count == 0` branch is defensive only — every example gets real
hints per Decision 1, so this path is never hit in practice, but it keeps
the formula safe against a future example that's added without hints yet.)

## Routes (`app/core/views.py`)

**`POST /hints/reveal`** (new) — form field `example_id`, same
registered-endpoint lookup pattern as `toggle_progress`. Get-or-create the
`ExampleProgress` row for that `example_id`. If `hints_used < len(example.hints)`,
increment `hints_used` by 1 (server-side clamp — a request past the max
is a no-op, not an error). Does not touch `completed_at` or
`points_awarded`. Redirect back to the example's own endpoint.

**`POST /progress/toggle`** (modified) — get-or-create the row instead of
delete-or-create:
- If not currently completed (`completed_at is None`): set
  `completed_at = utcnow()`, compute `points_awarded =
  compute_points(example, row.hints_used)`.
- If currently completed: set `completed_at = None`,
  `points_awarded = None`. `hints_used` is left untouched either way.

**`settings_page()` POST handler** (modified) — only update
`show_exploit_instructions` from form data when the *incoming*
`scoring_enabled` value is False; when the incoming `scoring_enabled` is
True, leave the stored `show_exploit_instructions` value exactly as it
was (per Decision 3 — avoids the disabled-checkbox-omission footgun
without needing to special-case template rendering beyond the one
derived-effective-value check below).

## Template / UI Changes

**`app/core/__init__.py`'s `context_processor`**: `completed_example_ids`
becomes `{p.example_id for p in ExampleProgress.query.filter(ExampleProgress.completed_at.isnot(None))}`
(was `.query.all()`, which is now wrong since rows can exist for
hint-only, not-yet-completed examples). Also inject `current_progress`:
the `ExampleProgress` row for `current_example.id` if one exists, else a
lightweight zero-value stand-in (`hints_used=0`, `points_awarded=None`,
`completed_at=None`) — so templates can always read
`current_progress.hints_used` without a null check.

**`example_page_base.html`**:
- The "Detect"/"Exploitation"/"Tasks" sections' existing guard
  `{% if settings.show_exploit_instructions %}` becomes
  `{% if settings.show_exploit_instructions and not settings.scoring_enabled %}`
  (Decision 3's derived-effective-value rule, applied at the one place it
  matters for display).
- New "Hints" card, shown `{% if settings.scoring_enabled and current_example %}`,
  positioned where Detect/Exploitation would otherwise appear: lists
  `current_example.hints[:current_progress.hints_used]` (already-revealed
  hints, in order), and — if `current_progress.hints_used <
  current_example.hints|length` — a "Reveal next hint (N of M used)"
  button posting to `/hints/reveal`.
- "Mark as done" button label changes, when `scoring_enabled`, to preview
  the exact point value it will award right now (using
  `compute_points`-equivalent logic computed in the route/context, not
  recomputed ad hoc in Jinja) — e.g. "Mark as done (earn 24 pts)". Once
  completed, the "✓ Completed" state shows the frozen `points_awarded`
  instead (e.g. "✓ Completed — 24 pts").

**Nav bar (`base.html`)**: when `scoring_enabled`, a small persistent
badge showing the running total score (sum of `points_awarded` across all
completed examples) out of the current max possible (sum of `base_points`
across all 63 examples) — e.g. "Score: 187 / 1340".

**Home page (`home.html` / `views.py home()`)**: when `scoring_enabled`,
each category card and the overall summary additionally show that
category's/the lab's earned-points subtotal and max-possible subtotal,
alongside the existing completed/total counts and progress bar.

**Settings page (`settings.html`)**: new "Enable scoring system" toggle
with a one-line description of the points formula. The existing "Show
exploit instructions" checkbox gains `{% if settings.scoring_enabled %}disabled{% endif %}`
plus an explanatory note ("Hidden while the scoring system is enabled —
use hints instead. Disable scoring to restore manual control over this
toggle.").

## Testing Approach

- `compute_points` is a pure function — unit-testable directly with the
  confirmed formula examples from Decision 2 (Hard/4-hints and
  Easy/3-hints cases) plus edge cases (`hints_used` clamped above
  `hint_count`, `hint_count == 0` defensive branch).
- `/hints/reveal` and `/progress/toggle`: exercised via the real Flask
  test client against a handful of real examples (not mocked), asserting
  on `ExampleProgress` row state directly and on rendered page content
  (revealed hint text appears/doesn't appear; point-preview text matches
  the formula; frozen `points_awarded` survives further hint reveals
  post-completion per Decision 4).
- Settings-page interaction: a test toggling `scoring_enabled` on, then
  posting a settings-form update that also includes
  `show_exploit_instructions` unchecked, and confirming the stored value
  is unchanged (Decision 3's anti-footgun rule) — plus a test confirming
  the *effective* value used in `example_page_base.html` is False
  regardless of the stored value while `scoring_enabled` is True.
- One test per hint-authoring task (per category, during implementation)
  confirming that example's `hints` list has the right length and that
  each hint's text is non-empty and distinct from every other hint in
  that same example (guards against copy-paste placeholder content across
  63 examples of authored text).
- Existing tests referencing `ExampleProgress` row deletion-on-untoggle
  semantics need updating to the new set-`completed_at`-to-None behavior.

## Scope Note for the Implementation Plan

Authoring real, example-specific hints for all 63 examples across 10
categories is a large content-authoring effort layered on top of a
comparatively small mechanism (data model + 2 routes + 1 shared
template + settings page). The implementation plan should build the
mechanism first (against a small number of real examples, fully tested),
then apply it to the remaining examples category-by-category — likely as
either one large multi-task plan (one task per category, ~10-12 tasks
total) or a framework plan followed by several smaller per-category
content plans, executed in sequence. This structuring decision belongs to
the writing-plans phase, not this spec.
