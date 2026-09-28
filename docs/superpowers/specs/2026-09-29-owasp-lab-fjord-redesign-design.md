# Site-Wide Fjord Visual Redesign — Design

## Goal

Sub-project 3 of 4 (per-user foundation ✅ → gamification ✅ → **Fjord visual redesign** → roadmap homepage). Apply the previously-approved "Fjord" Nordic design direction (dark-first mockup at the design-comparison Artifact, palette `#10151c`/`#171f2a`/`#6dd3c9`, IBM Plex Sans/Mono, 10 custom category SVG icons, fill-on-load progress bars, card-hover lift) across the entire app, with a new light companion palette, while preserving the existing 🌗 dark/light toggle and every page's current functionality.

## Current State (verified fresh)

- Bootstrap 5 (vendored, `static/vendor/bootstrap/`), theming via `data-bs-theme="light"|"dark"` on `<html>` plus Bootstrap's own `--bs-*` CSS custom properties. `static/css/lab.css` (112 lines) is a small existing overlay that already follows this same light/`[data-bs-theme="dark"]` pattern for a handful of components (sidebar, cards, hover states) — this file is the natural home for every new Fjord rule, not a new parallel stylesheet.
- Theme choice persists via `localStorage` (`labTheme`), applied by an inline `<script>` in `base.html`'s `<head>` before paint (no flash of wrong theme), and is fully reload-based (`toggleLabTheme()` in `static/js/lab.js` sets storage then `location.reload()`).
- `static/js/lab.js` already switches Mermaid's built-in theme (`"dark"` vs `"default"`) and highlight.js's stylesheet link based on the stored theme — this plumbing needs no changes; Mermaid diagrams keep using Mermaid's own built-in dark/default themes rather than a custom Fjord-matched theme (exact diagram color-matching is a nice-to-have, not required — YAGNI).
- Only **10 shared layout templates** actually need visual changes; every other template (109 example-content files, 10 category-content files) extends one of two shared bases and inherits the restyle automatically:
  - `app/core/templates/core/base.html` — nav, sidebar, page skeleton, theme-boot script
  - `app/core/templates/core/example_page_base.html` — six-block example page frame (used by all 109 examples)
  - `app/core/templates/core/overview_base.html` — category overview frame (used by all 10 categories)
  - `app/core/templates/core/home.html`, `leaderboard.html`, `instructor.html`, `switch_user.html`, `settings.html`, `tools.html`, `about.html`
- No new SVG icons need designing — the 10 category icons already exist (verified against the Fjord mockup's `<symbol>` definitions: `icon-a01` through `icon-a10`, viewBox 24x24, stroke-based, `currentColor`).

## Design

### Color tokens

New CSS custom properties, defined on `:root` (light) and redefined under `[data-bs-theme="dark"]` (dark) — added to `static/css/lab.css`, not a new file, matching this app's existing single-stylesheet convention:

| Token | Light | Dark |
| --- | --- | --- |
| `--fjord-bg` | `#f4f6f7` | `#10151c` |
| `--fjord-surface` | `#ffffff` | `#171f2a` |
| `--fjord-border` | `#dde3e7` | `#29323f` |
| `--fjord-fg` | `#172029` | `#e8edf2` |
| `--fjord-muted` | `#5b6b78` | `#8a97a6` |
| `--fjord-accent` | `#1f8f84` | `#6dd3c9` |

The light accent (`#1f8f84`) is deliberately a darker shade than the dark mode's `#6dd3c9`, not the same value reused — `#6dd3c9` fails WCAG AA contrast against a white/near-white background for text and icon use, so light mode needs its own accent dark enough to stay accessible while dark mode's can stay pale and glow-like against near-black.

**Bootstrap's own semantic colors (success/warning/danger) are left alone.** Difficulty badges (Easy/Medium/Hard) and gamification badges (earned/unearned) keep using `text-bg-success`/`text-bg-warning`/`text-bg-danger`/`text-bg-secondary` exactly as today — these carry meaning (pass/fail, easy/hard) that shouldn't be overloaded with the brand accent. Fjord's palette governs the app's *chrome* (background, surface, borders, body text, links, active-nav-item, progress-bar fill, icon color, card-hover accents) — not status indicators.

### Typography

IBM Plex Sans (headings + body) and IBM Plex Mono (code blocks, the nav score display, and anywhere else monospace is already used) via `@font-face`, vendored locally:
- New directory `static/vendor/ibm-plex/`, holding `IBMPlexSans-Regular.woff2`, `IBMPlexSans-Medium.woff2`, `IBMPlexSans-SemiBold.woff2`, `IBMPlexMono-Regular.woff2` (4 files — the minimal weight set the mockup actually uses: regular body text, medium for card titles/nav, semibold for page `<h1>`s).
- This matches the app's existing convention of vendoring every third-party asset locally (`static/vendor/bootstrap/`, `static/vendor/highlightjs/`, `static/vendor/mermaid/`) rather than depending on a CDN at runtime.

### Icons

The 10 existing category SVG `<symbol>` definitions become one sprite file, `static/icons/category-icons.svg`, referenced from templates via `<svg class="category-icon"><use href="{{ url_for('static', filename='icons/category-icons.svg') }}#icon-a01"></use></svg>` (or category-driven, e.g. `#icon-{{ category.id[:3] }}` using `a01`..`a10` derived from `category.short_id.lower()`). `currentColor` fill means the same file works unmodified in both themes — icon color follows whatever CSS color context it's placed in (typically `--fjord-accent` or `--fjord-fg`).

### Animation

- Progress bars (home page, category cards, leaderboard/instructor implicitly via badge counts) animate their width from 0 to their target value on load via a CSS transition/keyframe (`@keyframes fjord-fill`), matching the mockup's `cubic-bezier(.16,.84,.44,1)` easing.
- Cards (category cards on home, example list items) get a hover micro-interaction: `transform: translateY(-3px)` on the card plus `transform: scale(1.08) rotate(-3deg)` on its icon, both on a short transition — matching the mockup exactly.
- No new animation vocabulary beyond what the mockup already established — this task doesn't invent new motion, it ports the existing approved motion design.

### Per-template scope

- **`base.html`**: nav bar restyled with Fjord tokens (background, active-link color, brand accent), sidebar restyled to match (replacing its current hardcoded `var(--bs-tertiary-bg)`/`var(--bs-border-color)` refs with the new `--fjord-*` tokens), `@font-face` and font-family rules apply globally from here (loaded once, inherited everywhere).
- **`example_page_base.html`**: the six-block cards (Explanation/Detect/Exploitation/Tasks/Vulnerable vs Secure/Live example) get Fjord surface/border styling; difficulty badge and Mark-as-done button keep Bootstrap's semantic colors, everything else (headings, card chrome) picks up Fjord tokens/type.
- **`overview_base.html`**: same card/section restyle; the category's own icon (from the new sprite) appears next to the `<h1>`.
- **`home.html`**: category cards get the icon, the hover lift/rotate, and the fill-on-load progress bar animation; the per-category badge indicator (from sub-project 2) keeps its existing `text-bg-success`/`text-bg-secondary` semantic coloring, restyled only insofar as it now sits inside a Fjord-styled card.
- **`leaderboard.html` / `instructor.html`**: table styling picks up Fjord surface/border/type; no structural changes.
- **`switch_user.html` / `settings.html` / `tools.html` / `about.html`**: restyled via the same shared tokens/type; no structural changes — these are simple enough that inheriting `base.html`'s restyle plus a font/color pass is sufficient, no bespoke layout work needed.

## Data Model Approach

None — this is a pure presentation-layer change. No models, routes, or migrations.

## Self-Review

**Placeholder scan:** no TBD/TODO; every section states concrete values (hex codes, file paths, exact font files, exact CSS token names).

**Internal consistency:** the color table's light/dark pairs are symmetric in structure (bg↔fg mirrored, single accent per theme); the "Bootstrap semantic colors stay untouched" rule is stated once and then referenced consistently in the per-template scope section rather than re-litigated per page.

**Scope check:** confirmed via direct template inspection that only 10 files need visual changes — not the ~150 that a naive per-page count would suggest. Suggested implementation-plan decomposition (for the writing-plans skill to refine): (1) design-system foundation — fonts, icon sprite, color tokens, keyframes, added to `lab.css`; (2) `base.html` nav/sidebar restyle; (3) `example_page_base.html` + `overview_base.html` (the two highest-leverage shared templates); (4) `home.html` category cards + animations; (5) remaining smaller pages (`leaderboard.html`, `instructor.html`, `switch_user.html`, `settings.html`, `tools.html`, `about.html`) in one batched task, since each is a small, similar, low-risk restyle.

**Ambiguity check:** "micro animations" from the original request is fully pinned down to the two specific, already-mocked-up interactions (progress fill, card hover) — no open-ended animation scope remains.
