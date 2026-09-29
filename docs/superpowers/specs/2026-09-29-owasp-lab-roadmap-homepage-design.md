# Visual Roadmap Homepage — Design

## Goal

Sub-project 4 of 4 (per-user foundation ✅ → gamification ✅ → Fjord redesign ✅ → **roadmap homepage**). Replace the home page's 2-column grid of 10 category cards with a single connected "trail" of 10 nodes — a game-world-map-style visual showing per-category progress, badge status, and score inline, using the now-finalized Fjord icon/color/type system. Pure presentation layer: zero route/model changes.

## Current State (verified fresh)

- `app/core/views.py`'s `home()` already computes everything a node needs, per category, in `category_stats`: `category` (with `.id`, `.short_id`, `.title`, `.overview_endpoint`), `completed`, `total`, `percent`, `earned_points`, `max_points`, `badge_earned`. Nothing here changes.
- `app/core/templates/core/home.html` currently renders: an "Overall" summary card (unchanged by this spec), a "pick a user" alert for anonymous visitors (unchanged), then a `<div class="row row-cols-1 row-cols-md-2 g-3 mt-2">` grid of Bootstrap `.card`s — **this grid is what gets replaced**.
- Fjord (sub-project 3) already provides `.category-icon`, `.icon-box`, `.fjord-card`, the icon sprite (`static/icons/category-icons.svg`, ids `icon-a01`..`icon-a10`), and the `--bs-*`/`--fjord-accent` token system in both light and dark themes. This sub-project adds new CSS classes on top of that system, not a new design language.

## Design

### Layout

A vertical trail: 10 nodes in `A01`→`A10` order, connected by a spine line. On narrow/mobile widths, a single-column list with the spine on the left. On wider (`≥768px`) widths, nodes alternate left/right of a centered spine (zigzag), via CSS `nth-child(odd)`/`nth-child(even)` alone — no JavaScript, matching this app's existing "minimal custom JS" convention (`static/js/lab.js` is small and purely for the theme toggle, sidebar, and dropdown wiring).

### The spine "fills in" with overall progress

Two stacked, absolutely-positioned elements at the same horizontal position: a full-height muted track, and an accent-colored fill sized via an inline `style="height: {{ overall_percent }}%"` (the same pattern already used for the existing progress bars — an inline percentage-driven `style`, no new mechanism). This is a small, "free" bit of storytelling using data the route already computes — not a new metric.

### Per-node progress ring (new visual element)

A CSS-only conic-gradient "ring" around each node's icon, using the standard donut trick (an outer element with a `conic-gradient` background plus padding, and an inner element with a solid background matching whatever it sits on, punching a hole so only the ring shows):

```css
.roadmap-node-ring {
  background: conic-gradient(var(--fjord-accent) calc(var(--pct) * 1%), var(--bs-border-color) 0);
  border-radius: 50%;
  padding: 4px;
}
.roadmap-node-inner {
  background: var(--bs-body-bg);
  border-radius: 50%;
  display: grid;
  place-items: center;
}
```

`--pct` is set per node via an inline `style="--pct: {{ cs.percent }}"` (mirrors the spine-fill and existing progress-bar inline-percentage pattern — this app already sets per-instance numeric values this way, nothing new conceptually). A fully-completed, badge-earned node gets a small `🏅` marker absolutely positioned at its corner — reusing the exact badge condition (`cs.badge_earned`) and emoji already used on the current card grid, just repositioned.

### Node content

Each node is a single `<a href="{{ url_for(cs.category.overview_endpoint) }}">` (the whole node is clickable, exactly as "Open overview" already links today) containing: the ring+icon, the category short_id/title, "`X of Y completed`", and — when `settings.scoring_enabled` — the score fraction. Every one of these values already exists in `category_stats`; this task only changes their arrangement, never their computation.

### What does NOT change

- The "Overall" summary card and its progress bar (unchanged, stays above the trail).
- The anonymous-visitor "pick a user" alert (unchanged).
- `settings.scoring_enabled` gating logic (unchanged — same conditional, now guarding the score line inside a node instead of inside a card).
- Badge semantics (`text-bg-success`/`text-bg-secondary` classes, `cs.badge_earned` condition) — carried over unchanged, just repositioned as a marker on the ring instead of a badge pill in a card header.
- No new routes, no new template files elsewhere — this is a `home.html`-only change (plus its supporting CSS in `static/css/lab.css`), the smallest-scope sub-project of the four.

## Data Model Approach

None. Zero changes to `app/core/views.py`, `app/core/models.py`, or `app/core/stats.py` — every value the roadmap needs is already computed and passed to the template today.

## Self-Review

**Placeholder scan:** the ring/spine CSS techniques are given in full, not described vaguely — the plan will only need to fill in exact selector nesting, media-query breakpoints, and the zigzag `nth-child` rules, all mechanical extensions of the two techniques already specified here.

**Internal consistency:** every new visual element (ring percentage, spine fill percentage, badge marker) is sourced from a `category_stats`/`overall_percent` value that already exists — no new data flows are introduced anywhere in this design.

**Scope check:** confirmed this touches exactly one template (`home.html`) plus an addition to the existing single stylesheet (`static/css/lab.css`) — no new files beyond what a single implementation task naturally produces. This is the smallest of the four sub-projects.
