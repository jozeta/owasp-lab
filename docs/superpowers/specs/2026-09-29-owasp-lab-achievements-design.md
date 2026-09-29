# Expanded Achievement System — Design

## Goal

Replace the current, minimal "one badge per category" system with a real achievement system: 24 badges spanning category mastery, difficulty sweeps, a grand-completion badge, hint-based challenges, streak milestones, and a few funny/easter-egg ones — all shown on the home page as a "badge case" grid, dimmed until earned and colored once earned. Also enable the scoring system by default (currently off by default). The full badge catalog and every unlock condition were proposed to and approved by the user before this spec was written.

## Current State (verified fresh)

- `Settings.scoring_enabled` defaults to `False` (`app/core/models.py:12`, and again in `Settings.get()`'s creation defaults at `:21`) — becomes `True`.
- `app/core/stats.py`'s `compute_stats()` currently returns a `badges` key: a dict of `category.id -> completed_at`, one entry per category where every example in it is complete. This dict, and the `home()` route's `badge_earned` flag it feeds into each `category_stats` entry, are both replaced by the new system below — the concept of "one badge per category" survives as 10 of the new catalog's 24 entries, but the mechanism (boolean-only, defined in a dedicated catalog module, not timestamped) is new.
- `home.html`'s dash-cards currently show an inline 🏅/`text-bg-success` marker per category card when that category's old-style badge is earned. This is removed — the new dedicated Badge Case section is the only place badges are shown, so a category card doesn't need its own inline marker any more.
- `static/icons/category-icons.svg` holds the 10 existing category `<symbol>`s (`icon-a01`..`icon-a10`) plus `icon-shield` (nav brand). The 10 category-mastery badges in the new catalog reuse this same artwork, but as their own self-contained symbols in a *new*, separate sprite file (see Design) — badges and categories are related but independent concerns, and the badge system should not need to reach into the category sprite to render itself.
- `home.html`'s stat-strip currently shows 2 tiles (scoring disabled) or 3 (scoring enabled) via a `stat-strip`/`stat-strip-2col` CSS-class toggle. A 4th tile (badge count) is added, requiring a new `stat-strip-4col` variant for the scoring-enabled case (3 tiles becomes 4).

## Design

### Badge catalog (24 entries)

A new module, `app/core/badges.py`, defines a `Badge` (id, name, icon symbol id, description, and a condition callable) and a `BADGE_CATALOG` list. Every condition is derived purely from data already in `ExampleProgress`/`ActivityDay` plus static `CATEGORIES`/`ExampleNav` metadata (`difficulty`, `hints`) — no new columns or tables.

| id | Name | Unlock condition | Icon |
| --- | --- | --- | --- |
| `backdoor-baron` | Backdoor Baron | Every A01 example complete | reuses `icon-a01` artwork |
| `cipher-breaker` | Cipher Breaker | Every A02 example complete | reuses `icon-a02` |
| `sql-ninja` | SQL Ninja | Every A03 example complete | reuses `icon-a03` |
| `architect-of-chaos` | Architect of Chaos | Every A04 example complete | reuses `icon-a04` |
| `config-crusher` | Config Crusher | Every A05 example complete | reuses `icon-a05` |
| `dependency-hell-survivor` | Dependency Hell Survivor | Every A06 example complete | reuses `icon-a06` |
| `session-hijacker` | Session Hijacker | Every A07 example complete | reuses `icon-a07` |
| `supply-chain-saboteur` | Supply Chain Saboteur | Every A08 example complete | reuses `icon-a08` |
| `ghost-in-the-logs` | Ghost in the Logs | Every A09 example complete | reuses `icon-a09` |
| `request-forger` | Request Forger | Every A10 example complete | reuses `icon-a10` |
| `script-kiddie` | Script Kiddie | Every Easy example complete, any category | new |
| `grey-hat` | Grey Hat | Every Medium example complete, any category | new |
| `1337-haxor` | 1337 Haxor | Every Hard example complete, any category | new |
| `red-team-legend` | Red Team Legend | All 105 examples complete | new |
| `purist` | Purist | A whole category complete with zero hints used across it | new |
| `tell-me-everything` | Tell Me Everything | Every hint revealed on one example | new |
| `google-is-my-copilot` | Google Is My Copilot | 25+ hints revealed, lab-wide | new |
| `natural-talent` | Natural Talent | 10+ examples completed with zero hints used | new |
| `consistent-threat` | Consistent Threat | 3-day streak | new |
| `advanced-persistent-threat` | Advanced Persistent Threat | 7-day streak | new |
| `nation-state-actor` | Nation-State Actor | 30-day streak | new |
| `participation-trophy` | Participation Trophy | Always true | new |
| `leet` | Leet | Score ≥ 1337 (only shown/counted when `scoring_enabled`) | new |
| `the-answer` | The Answer | 42+ examples complete | new |

The exact new SVG path data for the 14 "new" icons and the copied path data for the 10 reused ones are specified in full in the implementation plan, not here — this spec fixes the *catalog* (names, conditions, which icon concept each uses), the plan fixes the *exact markup*.

### `compute_badges()`

One function in `app/core/badges.py`, called once per `home()` request:

```python
def compute_badges():
    """Returns {badge.id: bool} for every badge in BADGE_CATALOG."""
```

Internally queries `ExampleProgress.query.all()` and `ActivityDay.query.all()` once each (2 queries) and derives every condition from those two result sets plus static `CATEGORIES` metadata — consistent with `compute_stats()`'s existing 2-query shape. This is a third and fourth query on top of `home()`'s own progress-row fetch and `compute_stats()`'s own two — **deliberately accepted, not an oversight**: this exact kind of redundancy was already reviewed and explicitly parked as a non-blocking minor inefficiency during the Fjord redesign's final review (harmless at this app's single-instance scale), and introducing a shared-query-context refactor now to avoid one more redundant pass would touch already-tested, already-reviewed code for no real performance benefit.

`compute_stats()` (`app/core/stats.py`) **drops its `badges` key** — badges are now entirely `app/core/badges.py`'s concern. `compute_stats()`'s remaining shape (`completed_total`, `score_total`, `streak_days`, `last_active`) is unchanged.

### Home page changes

- **Stat-strip**: gains a 4th tile, "Badges earned / total," counted among only the *visible* badges (`leet` excluded from both the numerator and denominator when `scoring_enabled` is `False`, matching how the rest of the app already hides scoring-dependent UI). 4 tiles when scoring is enabled, 3 when disabled (was 3/2) — a new `stat-strip-4col` CSS class is added alongside the existing `stat-strip-2col`.
- **New "Badge Case" section**, placed between the stat-strip and the category dash-grid: one chip per *visible* badge (23 or 24 depending on scoring), each showing its icon, name, and description (the description doubles as the "how to earn this" hint when locked). Locked chips are visually dimmed (muted icon-box color, reduced opacity); earned chips use the same `--fjord-accent`/`--fjord-accent-dim` icon-box treatment already established for every other icon on the site — no new color language, just the existing locked/earned state applied to the existing token system.
- **Dash-cards lose their inline badge marker** — the old `{% if cs.badge_earned %}🏅{% endif %}` block and the `cs.badge_earned` key computed in `home()` are removed; the Badge Case is now the single place badges are shown.

### Settings default

`Settings.scoring_enabled`'s column default and `Settings.get()`'s creation default both become `True`. This is a one-line-times-two change with a real ripple: every existing test that asserts on scoring-disabled behavior (e.g. `test_score_ui_absent_when_scoring_disabled`) must now explicitly set `scoring_enabled = False` itself rather than relying on the fresh-database default — the plan must survey the whole test suite for this, not just the tests already known to touch scoring.

## Data Model Approach

None — every badge condition is computed from existing tables plus static nav metadata. No new columns, no new tables, no migration caveat needed (unlike the last two schema-touching sub-projects).

## Self-Review

**Placeholder scan:** the catalog table above is complete and final (all 24 entries, names and conditions locked in) — only the exact SVG path data and exact Jinja/CSS diffs are deferred to the plan, which is the same division of labor every prior spec in this session has used (design decisions here, exact code there).

**Internal consistency:** `compute_badges()`'s 2-query shape mirrors `compute_stats()`'s already-established, already-tested pattern (`test_stats.py`'s `test_compute_stats_runs_at_most_two_queries`) rather than inventing a new convention.

**Scope check:** this is a presentation-and-computation-layer feature exactly like the Fjord redesign and the roadmap-homepage work — no new tables, but real ripple into the test suite (both from the badge system itself and from the `scoring_enabled` default flip) and into `home.html`'s layout. Comparable in size to the "global progress" revert, not a small tweak.
