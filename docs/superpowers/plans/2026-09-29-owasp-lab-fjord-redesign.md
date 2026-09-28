# Site-Wide Fjord Visual Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the previously-approved "Fjord" Nordic visual design (dark palette `#10151c`/`#171f2a`/`#6dd3c9` plus a new light companion palette, IBM Plex Sans/Mono, 10 custom category SVG icons, fill-on-load progress bars, card-hover lift) across the whole OWASP Top 10 Training Lab, while preserving the existing 🌗 light/dark toggle and every page's current behavior.

**Architecture:** Bootstrap 5.3.3 (vendored) themes entirely through its own `--bs-*` CSS custom properties, redefined once for `:root,[data-bs-theme=light]` and again for `[data-bs-theme=dark]`. Instead of a parallel custom-property namespace, `static/css/lab.css` (which already loads after `bootstrap.min.css`) overrides Bootstrap's own variables directly, so every existing component (cards, tables, list-groups, nav, sidebar) re-themes automatically. A `--fjord-accent`/`--fjord-accent-dim` pair is added for the one brand-accent use Bootstrap has no native slot for (progress-bar fill, icon color, card-hover accents). Fonts and the icon sprite are new static assets, vendored locally to match this app's existing convention (Bootstrap, highlight.js, Mermaid are all vendored, never CDN-loaded at runtime).

**Tech Stack:** Bootstrap 5.3.3 CSS custom properties, vendored IBM Plex Sans/Mono (woff2), one SVG `<symbol>` sprite, Flask/Jinja2 templates, pytest with the real Flask test client.

**Spec:** docs/superpowers/specs/2026-09-29-owasp-lab-fjord-redesign-design.md

## Global Constraints

- No new CSS framework — every rule targets Bootstrap 5.3.3's existing `--bs-*` custom properties or is a small hand-written addition to the single `static/css/lab.css` file. No new stylesheet files.
- Fonts and icons are vendored locally under `static/vendor/ibm-plex/` and `static/icons/` — never loaded from a CDN at runtime, matching every other third-party asset in this app.
- Bootstrap's own semantic status colors (`text-bg-success`/`text-bg-warning`/`text-bg-danger`/`text-bg-secondary`, used for difficulty badges and gamification badges) are never touched — Fjord's palette governs chrome (background, surface, borders, body text, links, active-nav, progress-bar fill, icon color, hover accents), not status indicators.
- The existing 🌗 theme toggle (`toggleLabTheme()` in `static/js/lab.js`, `data-bs-theme` attribute, `localStorage` persistence) must keep working exactly as today — no changes to that mechanism, only to what the two theme states visually resolve to.
- No route, model, or template *logic* changes anywhere in this plan — this is a pure presentation-layer change. Every existing test must keep passing unmodified except where a test asserts on now-superseded literal CSS/markup this plan intentionally changes (rare; called out per task).
- Full suite baseline at plan-writing time: 626 passed, 3 skipped, at commit 903a377 on `main`.

---

### Task 1: Design-system foundation — fonts, icon sprite, color tokens, animation

**Files:**
- Create: `static/vendor/ibm-plex/IBMPlexSans-Regular.woff2`, `IBMPlexSans-Medium.woff2`, `IBMPlexSans-SemiBold.woff2`, `IBMPlexMono-Regular.woff2`, `LICENSE-IBM-Plex-Sans.txt`, `LICENSE-IBM-Plex-Mono.txt`
- Create: `static/icons/category-icons.svg`
- Modify: `static/css/lab.css` (currently 112 lines — append everything below to the end of the file)
- Test: `tests/test_fjord_design_system.py` (new)

**Interfaces:**
- Produces: CSS custom properties `--bs-body-bg`, `--bs-body-color`, `--bs-body-bg-rgb`, `--bs-body-color-rgb`, `--bs-card-bg`, `--bs-tertiary-bg`, `--bs-tertiary-bg-rgb`, `--bs-border-color`, `--bs-border-color-translucent`, `--bs-secondary-color`, `--bs-link-color`, `--bs-link-hover-color`, `--fjord-accent`, `--fjord-accent-dim` (all overridden on `:root,[data-bs-theme="light"]` and `[data-bs-theme="dark"]`) — consumed by every later task's templates, since they rely on Bootstrap's own classes picking these up automatically.
- Produces: CSS classes `.category-icon`, `.icon-box`, `.fjord-card`, `.fjord-fill` and the `@keyframes fjord-fill` animation — consumed by Task 2 (nav brand icon), Task 3 (example/overview page icons), Task 4 (home page cards).
- Produces: `static/icons/category-icons.svg` with `<symbol>` ids `icon-a01` through `icon-a10` and `icon-shield` — consumed by Tasks 2-4 via `<svg class="category-icon"><use href="{{ url_for('static', filename='icons/category-icons.svg') }}#icon-a01"></use></svg>`.

- [ ] **Step 1: Fetch and verify the exact IBM Plex font files**

These exact commands were run and verified during plan-writing — the URLs are pinned to specific release tags (not "latest"), so they are fully reproducible:

```bash
mkdir -p /tmp/plex-fetch && cd /tmp/plex-fetch
curl -sL "https://github.com/IBM/plex/releases/download/%40ibm/plex-sans%401.1.0/ibm-plex-sans.zip" -o plex-sans.zip
curl -sL "https://github.com/IBM/plex/releases/download/%40ibm/plex-mono%402.5.0/ibm-plex-mono.zip" -o plex-mono.zip
unzip -o -j plex-sans.zip \
  "ibm-plex-sans/fonts/complete/woff2/IBMPlexSans-Regular.woff2" \
  "ibm-plex-sans/fonts/complete/woff2/IBMPlexSans-Medium.woff2" \
  "ibm-plex-sans/fonts/complete/woff2/IBMPlexSans-SemiBold.woff2" \
  -d sans
unzip -o -j plex-mono.zip "ibm-plex-mono/fonts/complete/woff2/IBMPlexMono-Regular.woff2" -d mono
unzip -p plex-sans.zip "ibm-plex-sans/LICENSE.txt" > LICENSE-IBM-Plex-Sans.txt
unzip -p plex-mono.zip "ibm-plex-mono/LICENSE.txt" > LICENSE-IBM-Plex-Mono.txt
```

Verify checksums exactly match (these were computed during plan-writing against the same pinned URLs above):

```bash
shasum -a 256 sans/IBMPlexSans-Regular.woff2 sans/IBMPlexSans-Medium.woff2 sans/IBMPlexSans-SemiBold.woff2 mono/IBMPlexMono-Regular.woff2
```

Expected output (exact):
```
ba711a3085ff9f27440b6b9c4550cfc47c97bf36591d5da958b975bb3add8c1a  sans/IBMPlexSans-Regular.woff2
5660f8a658f8bb50dbc005232f885eadffd2bc1c235c4f6fbb63469d1f9cde6d  sans/IBMPlexSans-Medium.woff2
f78048030eab62e860efa39a0df79e2e5581bf122eb95b9bc42c0b8a4988d205  sans/IBMPlexSans-SemiBold.woff2
ba204497f16b6d334cee9d1e963a831b73e3a56e1d6300a8489d18df7214b350  mono/IBMPlexMono-Regular.woff2
```

If any checksum differs, STOP and report — do not proceed with unverified binary files.

- [ ] **Step 2: Vendor the fonts into the repo**

```bash
mkdir -p static/vendor/ibm-plex
cp /tmp/plex-fetch/sans/IBMPlexSans-Regular.woff2 static/vendor/ibm-plex/
cp /tmp/plex-fetch/sans/IBMPlexSans-Medium.woff2 static/vendor/ibm-plex/
cp /tmp/plex-fetch/sans/IBMPlexSans-SemiBold.woff2 static/vendor/ibm-plex/
cp /tmp/plex-fetch/mono/IBMPlexMono-Regular.woff2 static/vendor/ibm-plex/
cp /tmp/plex-fetch/LICENSE-IBM-Plex-Sans.txt static/vendor/ibm-plex/
cp /tmp/plex-fetch/LICENSE-IBM-Plex-Mono.txt static/vendor/ibm-plex/
```

Both license files are the SIL Open Font License 1.1 (Copyright © 2017 IBM Corp. with Reserved Font Name "Plex") — permissive, redistribution-friendly, consistent with this app's other vendored assets.

- [ ] **Step 3: Create the icon sprite**

Create `static/icons/category-icons.svg` with exactly this content (extracted verbatim from the approved Fjord mockup's shared icon set — do not redraw or approximate these paths):

```html
<svg xmlns="http://www.w3.org/2000/svg" style="display:none" aria-hidden="true">
  <defs>
    <symbol id="icon-a01" viewBox="0 0 24 24"><path d="M6 3h9a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H6"/><path d="M6 3 3 5v14l3 2"/><circle cx="12.6" cy="12" r="0.9" fill="currentColor" stroke="none"/></symbol>
    <symbol id="icon-a02" viewBox="0 0 24 24"><circle cx="8" cy="8" r="4"/><path d="m10.8 10.8 8.6 8.6"/><path d="M16 16.5 18.5 14"/><path d="M18 18.5 20.5 16"/><path d="M9.5 6.2 7 8.7"/></symbol>
    <symbol id="icon-a03" viewBox="0 0 24 24"><path d="M20 4 16 8"/><path d="m17.5 5.5-9 9-3.5 5 5-3.5 9-9z"/><path d="m13 9 2 2"/><path d="M4.5 19.5 6 18"/></symbol>
    <symbol id="icon-a04" viewBox="0 0 24 24"><rect x="3.5" y="3.5" width="17" height="17" rx="1.2"/><path d="M3.5 9h5.5M15 9h5.5M3.5 15h3M17.5 15h3"/><path d="m10 9 2 3-2 3 2 3"/></symbol>
    <symbol id="icon-a05" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3.4"/><path d="M12 3.5v2.3M12 18.2v2.3M20.5 12h-2.3M5.8 12H3.5M18 6l-1.6 1.6M7.6 16.4 6 18M18 18l-1.6-1.6M7.6 7.6 6 6"/><path d="M20.8 5.2 19 7" stroke-dasharray="1 2.4"/></symbol>
    <symbol id="icon-a06" viewBox="0 0 24 24"><path d="M12 3 20.5 7.5v9L12 21 3.5 16.5v-9z"/><path d="M3.5 7.5 12 12l8.5-4.5M12 12v9"/><path d="m9.5 9-1.5 3 1.5 3"/></symbol>
    <symbol id="icon-a07" viewBox="0 0 24 24"><path d="M12 4a6 6 0 0 1 6 6v2.5"/><path d="M12 4a6 6 0 0 0-6 6v3"/><path d="M9 20v-6a3 3 0 0 1 5.5-1.7"/><path d="M15 20v-6.3"/><path d="M6 20v-4a6 6 0 0 1 .3-1.9"/></symbol>
    <symbol id="icon-a08" viewBox="0 0 24 24"><rect x="3" y="8" width="7" height="10" rx="3.5" transform="rotate(-20 6.5 13)"/><rect x="14" y="6" width="7" height="10" rx="3.5" transform="rotate(-20 17.5 11)"/><path d="m10.5 12.5 1.6-1.8"/></symbol>
    <symbol id="icon-a09" viewBox="0 0 24 24"><path d="M3 12s3.5-6 9-6 9 6 9 6-3.5 6-9 6-9-6-9-6Z"/><circle cx="12" cy="12" r="2.4"/><path d="m4 19 16-14" stroke-dasharray="1.6 2"/></symbol>
    <symbol id="icon-a10" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="6" rx="1.2"/><rect x="4" y="14" width="16" height="6" rx="1.2"/><circle cx="7.3" cy="7" r=".6" fill="currentColor" stroke="none"/><circle cx="7.3" cy="17" r=".6" fill="currentColor" stroke="none"/><path d="M14 10.5v3a3.5 3.5 0 0 1-3.5 3.5H10"/><path d="m11.6 15.6-1.9 1.4 1.9 1.4"/></symbol>
    <symbol id="icon-shield" viewBox="0 0 24 24"><path d="M12 3 5 6v6c0 4.5 3 7.5 7 9 4-1.5 7-4.5 7-9V6z"/><path d="m9 12 2 2 4-4"/></symbol>
  </defs>
</svg>
```

- [ ] **Step 4: Append the design-system CSS to `static/css/lab.css`**

Append exactly this to the end of the existing 112-line file (do not modify anything above it):

```css

/* ===================================================================
   Fjord design system
   =================================================================== */

:root,
[data-bs-theme="light"] {
  --bs-body-bg: #f4f6f7;
  --bs-body-bg-rgb: 244, 246, 247;
  --bs-body-color: #172029;
  --bs-body-color-rgb: 23, 32, 41;
  --bs-card-bg: #ffffff;
  --bs-tertiary-bg: #ffffff;
  --bs-tertiary-bg-rgb: 255, 255, 255;
  --bs-border-color: #dde3e7;
  --bs-border-color-translucent: #dde3e7;
  --bs-secondary-color: #5b6b78;
  --bs-link-color: #1f8f84;
  --bs-link-hover-color: #17766d;
  --fjord-accent: #1f8f84;
  --fjord-accent-dim: rgba(31, 143, 132, 0.12);
}

[data-bs-theme="dark"] {
  --bs-body-bg: #10151c;
  --bs-body-bg-rgb: 16, 21, 28;
  --bs-body-color: #e8edf2;
  --bs-body-color-rgb: 232, 237, 242;
  --bs-card-bg: #171f2a;
  --bs-tertiary-bg: #171f2a;
  --bs-tertiary-bg-rgb: 23, 31, 42;
  --bs-border-color: #29323f;
  --bs-border-color-translucent: #29323f;
  --bs-secondary-color: #8a97a6;
  --bs-link-color: #6dd3c9;
  --bs-link-hover-color: #8fdcd4;
  --fjord-accent: #6dd3c9;
  --fjord-accent-dim: rgba(109, 211, 201, 0.14);
}

@font-face {
  font-family: "IBM Plex Sans";
  font-weight: 400;
  font-style: normal;
  font-display: swap;
  src: url("../vendor/ibm-plex/IBMPlexSans-Regular.woff2") format("woff2");
}

@font-face {
  font-family: "IBM Plex Sans";
  font-weight: 500;
  font-style: normal;
  font-display: swap;
  src: url("../vendor/ibm-plex/IBMPlexSans-Medium.woff2") format("woff2");
}

@font-face {
  font-family: "IBM Plex Sans";
  font-weight: 600;
  font-style: normal;
  font-display: swap;
  src: url("../vendor/ibm-plex/IBMPlexSans-SemiBold.woff2") format("woff2");
}

@font-face {
  font-family: "IBM Plex Mono";
  font-weight: 400;
  font-style: normal;
  font-display: swap;
  src: url("../vendor/ibm-plex/IBMPlexMono-Regular.woff2") format("woff2");
}

body {
  font-family: "IBM Plex Sans", -apple-system, BlinkMacSystemFont, sans-serif;
}

h1, h2, h3, h4, h5, h6, .navbar-brand, .card-title {
  font-weight: 600;
  letter-spacing: -0.01em;
}

code, pre, kbd, samp, .navuser {
  font-family: "IBM Plex Mono", monospace;
}

.progress-bar {
  background-color: var(--fjord-accent);
}

.category-icon {
  width: 20px;
  height: 20px;
  stroke: currentColor;
  fill: none;
  stroke-width: 1.6;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.icon-box {
  width: 34px;
  height: 34px;
  border-radius: 9px;
  background: var(--fjord-accent-dim);
  color: var(--fjord-accent);
  display: inline-grid;
  place-items: center;
  flex-shrink: 0;
  transition: transform 0.18s ease;
}

.fjord-card {
  transition: transform 0.18s ease, border-color 0.18s ease;
}

.fjord-card:hover {
  transform: translateY(-3px);
}

.fjord-card:hover .icon-box {
  transform: scale(1.08) rotate(-3deg);
}

@keyframes fjord-fill {
  from { transform: scaleX(0); }
  to { transform: scaleX(1); }
}

.fjord-fill {
  transform-origin: left;
  animation: fjord-fill 1.1s cubic-bezier(0.16, 0.84, 0.44, 1) both;
}

@media (prefers-reduced-motion: reduce) {
  .fjord-fill {
    animation: none;
  }
}
```

- [ ] **Step 5: Write and run the verification tests**

Create `tests/test_fjord_design_system.py`:

```python
import hashlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

EXPECTED_FONT_CHECKSUMS = {
    "static/vendor/ibm-plex/IBMPlexSans-Regular.woff2": "ba711a3085ff9f27440b6b9c4550cfc47c97bf36591d5da958b975bb3add8c1a",
    "static/vendor/ibm-plex/IBMPlexSans-Medium.woff2": "5660f8a658f8bb50dbc005232f885eadffd2bc1c235c4f6fbb63469d1f9cde6d",
    "static/vendor/ibm-plex/IBMPlexSans-SemiBold.woff2": "f78048030eab62e860efa39a0df79e2e5581bf122eb95b9bc42c0b8a4988d205",
    "static/vendor/ibm-plex/IBMPlexMono-Regular.woff2": "ba204497f16b6d334cee9d1e963a831b73e3a56e1d6300a8489d18df7214b350",
}


def test_font_files_exist_with_correct_checksums():
    for relative_path, expected_sha256 in EXPECTED_FONT_CHECKSUMS.items():
        path = REPO_ROOT / relative_path
        assert path.is_file(), f"missing vendored font: {relative_path}"
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        assert actual == expected_sha256, f"{relative_path} checksum mismatch"


def test_font_license_files_exist():
    assert (REPO_ROOT / "static/vendor/ibm-plex/LICENSE-IBM-Plex-Sans.txt").is_file()
    assert (REPO_ROOT / "static/vendor/ibm-plex/LICENSE-IBM-Plex-Mono.txt").is_file()


def test_icon_sprite_has_all_ten_category_icons():
    sprite = (REPO_ROOT / "static/icons/category-icons.svg").read_text()
    for n in range(1, 11):
        assert f'id="icon-a{n:02d}"' in sprite


def test_icon_sprite_has_shield_mark():
    sprite = (REPO_ROOT / "static/icons/category-icons.svg").read_text()
    assert 'id="icon-shield"' in sprite


def test_lab_css_defines_fjord_tokens_for_both_themes():
    css = (REPO_ROOT / "static/css/lab.css").read_text()
    assert '[data-bs-theme="light"] {' in css
    assert '[data-bs-theme="dark"] {' in css
    assert "--bs-body-bg: #f4f6f7;" in css
    assert "--bs-body-bg: #10151c;" in css
    assert "--fjord-accent: #1f8f84;" in css
    assert "--fjord-accent: #6dd3c9;" in css


def test_lab_css_defines_font_faces_and_animation():
    css = (REPO_ROOT / "static/css/lab.css").read_text()
    assert '@font-face' in css
    assert '"IBM Plex Sans"' in css
    assert '"IBM Plex Mono"' in css
    assert "@keyframes fjord-fill" in css
    assert ".fjord-fill" in css
    assert "prefers-reduced-motion" in css
```

Run: `pytest tests/test_fjord_design_system.py -v`
Expected: PASS (6 tests).

- [ ] **Step 6: Run the full suite to confirm no regressions**

Run: `pytest -q`
Expected: 632 passed, 3 skipped (626 + 6 new).

- [ ] **Step 7: Commit**

```bash
git add static/vendor/ibm-plex static/icons/category-icons.svg static/css/lab.css tests/test_fjord_design_system.py
git commit -m "feat: add Fjord design-system foundation (fonts, icons, color tokens)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: Nav bar and sidebar restyle

**Files:**
- Modify: `app/core/templates/core/base.html`
- Modify: `static/css/lab.css` (append; this task's own small addition, on top of Task 1's)
- Test: `tests/test_fjord_nav.py` (new)

**Interfaces:**
- Consumes: `.category-icon`, `--fjord-accent`, `--bs-*` tokens from Task 1.

**Orchestration note:** Re-read `app/core/templates/core/base.html` fresh before editing — Task 1 does not touch this file, so it should be unchanged from its last-known state, but confirm.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_fjord_nav.py`:

```python
from app.core.seed import seed_database


def test_home_page_references_icon_sprite(app, client):
    seed_database(app)
    response = client.get("/")
    assert b"category-icons.svg" in response.data


def test_nav_brand_uses_shield_icon(app, client):
    seed_database(app)
    response = client.get("/")
    assert b"#icon-shield" in response.data


def test_nav_no_longer_forces_bg_dark(app, client):
    seed_database(app)
    response = client.get("/")
    body = response.data.decode()
    assert 'class="navbar navbar-expand-lg bg-dark"' not in body
    assert 'navbar-dark' not in body
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_fjord_nav.py -v`
Expected: FAIL (nav doesn't reference the icon sprite yet, still has the old `bg-dark navbar-dark` classes).

- [ ] **Step 3: Update the nav markup in `base.html`**

Find this line (the nav's opening tag):

```html
  <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
```

Replace with:

```html
  <nav class="navbar navbar-expand-lg bg-body-tertiary border-bottom">
```

(Dropping the hardcoded `navbar-dark bg-dark` — which forced a permanently-dark, non-theme-aware nav bar regardless of the page's own light/dark mode — in favor of `bg-body-tertiary`, a Bootstrap utility class that resolves to the `--bs-tertiary-bg` variable Task 1 already themes per-mode. `border-bottom` adds a themed separator line using `--bs-border-color`.)

Find the brand link:

```html
      <a class="navbar-brand" href="{{ url_for('core.home') }}">OWASP Top 10 Lab</a>
```

Replace with:

```html
      <a class="navbar-brand d-flex align-items-center gap-2" href="{{ url_for('core.home') }}">
        <span class="icon-box" style="width: 26px; height: 26px; border-radius: 7px;">
          <svg class="category-icon" style="width: 16px; height: 16px;" viewBox="0 0 24 24">
            <use href="{{ url_for('static', filename='icons/category-icons.svg') }}#icon-shield"></use>
          </svg>
        </span>
        OWASP Top 10 Lab
      </a>
```

Find the "Logged in as" nav item:

```html
          <li class="nav-item d-flex align-items-center text-light me-3">Logged in as {{ current_user.username }}</li>
```

Replace `text-light` (which forces white text, correct only against the old permanently-dark nav) with nothing — the surrounding nav now themes via `--bs-body-color` automatically:

```html
          <li class="nav-item d-flex align-items-center me-3">Logged in as {{ current_user.username }}</li>
```

Similarly find the score nav item:

```html
          <li class="nav-item d-flex align-items-center text-light me-3">Score: {{ nav_score_earned }} / {{ nav_score_max }}</li>
```

Replace with (dropping `text-light`, adding the `navuser` class Task 1 defined to render the score in IBM Plex Mono, matching the mockup's monospace data treatment):

```html
          <li class="nav-item d-flex align-items-center me-3 navuser">Score: {{ nav_score_earned }} / {{ nav_score_max }}</li>
```

- [ ] **Step 4: Add light-mode sidebar styling to `static/css/lab.css`**

The existing sidebar CSS (lines 1-112, untouched by Task 1) only styles `#sidebar` explicitly for `[data-bs-theme="dark"]` — append this small addition so light mode gets an equivalent themed sidebar background instead of relying on an unset default:

```css

/* ===================================================================
   Fjord: light-mode sidebar (dark mode's #sidebar rule already exists
   above and now picks up Task 1's --bs-tertiary-bg/--bs-border-color
   overrides automatically)
   =================================================================== */

[data-bs-theme="light"] #sidebar {
  background-color: var(--bs-tertiary-bg);
  border-color: var(--bs-border-color) !important;
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_fjord_nav.py -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Run the full suite to confirm no regressions**

Run: `pytest -q`
Expected: 635 passed, 3 skipped (632 + 3 new).

- [ ] **Step 7: Commit**

```bash
git add app/core/templates/core/base.html static/css/lab.css tests/test_fjord_nav.py
git commit -m "feat: restyle nav bar and sidebar with Fjord tokens

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: Example page and category overview page restyle

**Files:**
- Modify: `app/core/templates/core/example_page_base.html`
- Modify: `app/core/templates/core/overview_base.html`
- Test: `tests/test_fjord_example_and_overview_pages.py` (new)

**Interfaces:**
- Consumes: `.category-icon`, `.icon-box` from Task 1; nothing from Task 2.

**Orchestration note:** these two shared templates are used by all 109 example pages and all 10 category overview pages respectively — every other per-example/per-category template file only fills in Jinja `{% block %}`s inside these two files and needs no changes at all. Re-read both files fresh before editing (neither was touched by Tasks 1-2).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_fjord_example_and_overview_pages.py`:

```python
from app.core.seed import seed_database


def test_example_page_has_no_structural_regression(app, client):
    """Sanity check: an example page still renders its six-block structure
    (this test does not assert on new Fjord markup -- it just confirms the
    existing page didn't break)."""
    seed_database(app)
    response = client.get("/a03/login")
    assert response.status_code == 200
    assert b"Explanation" in response.data


def test_overview_page_shows_its_category_icon(app, client):
    seed_database(app)
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"#icon-a03" in response.data


def test_overview_page_for_every_category_shows_matching_icon(app, client):
    seed_database(app)
    category_paths_and_icons = [
        ("/a01/", "#icon-a01"),
        ("/a02/", "#icon-a02"),
        ("/a03/", "#icon-a03"),
        ("/a04/", "#icon-a04"),
        ("/a05/", "#icon-a05"),
        ("/a06/", "#icon-a06"),
        ("/a07/", "#icon-a07"),
        ("/a08/", "#icon-a08"),
        ("/a09/", "#icon-a09"),
        ("/a10/", "#icon-a10"),
    ]
    for path, icon_ref in category_paths_and_icons:
        response = client.get(path)
        assert response.status_code == 200
        assert icon_ref.encode() in response.data, f"{path} missing {icon_ref}"
```

**Before writing Step 3's code**, confirm the exact category overview URL prefixes and one example page's real URL by reading `app/categories/a01_access_control/__init__.py` through `a10_ssrf/__init__.py`'s `url_prefix=` values fresh (these should be `/a01` through `/a10` based on the blueprint registration pattern already seen in `a01_access_control/__init__.py`, but confirm before trusting the test above) and confirm `/a03/login` is `sqli-login`'s real route (used in prior sub-projects' tests as a safe, no-login-required example route).

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_fjord_example_and_overview_pages.py -v`
Expected: FAIL (overview pages don't reference category icons yet).

- [ ] **Step 3: Add the category icon to `overview_base.html`**

Find:

```html
{% block content %}
<h1>{{ category_short_id }}: {{ category_title }}</h1>
```

Replace with:

```html
{% block content %}
<h1 class="d-flex align-items-center gap-2">
  <span class="icon-box">
    <svg class="category-icon" viewBox="0 0 24 24">
      <use href="{{ url_for('static', filename='icons/category-icons.svg') }}#icon-{{ active_category.id[:3] }}"></use>
    </svg>
  </span>
  {{ category_short_id }}: {{ category_title }}
</h1>
```

(`active_category` is already available in every template via `inject_globals()`'s context processor — confirmed in `app/core/__init__.py`. `active_category.id[:3]` yields `"a01"`..`"a10"`, matching the sprite's `icon-a01`..`icon-a10` ids, since every category id is prefixed exactly `"a0N_"` or `"a10_"`.)

- [ ] **Step 4: Restyle the example page's six-block cards in `example_page_base.html`**

Find the `<section class="card mb-4">` blocks (Explanation, Detect, Exploitation/Tasks, etc. — there are several, one per conditionally-shown block) and add the `fjord-card` class to each. Read the file fresh to find every occurrence of `class="card mb-4"` and change it to `class="card mb-4 fjord-card"`. Do this for every such occurrence in the file — the six-block structure means there are multiple (Explanation, Detect, Exploitation, Tasks, Vulnerable vs Secure, Live example), each independently conditional on settings, so grep the file first to confirm the exact count before editing:

```bash
grep -c 'class="card mb-4"' app/core/templates/core/example_page_base.html
```

Replace every occurrence found (do not skip any).

- [ ] **Step 5: Restyle the overview page's sections in `overview_base.html`**

The overview page currently uses plain `<section class="mb-4">` (no `.card` wrapper) for What It Is / Why It Matters / etc. Wrap each in a card to match the example pages' visual language — find:

```html
<section class="mb-4">
  <h2>What It Is</h2>
  {% block what_it_is %}{% endblock %}
</section>
```

and every other `<section class="mb-4">...</section>` block in this file (What It Is, Why It Matters, How It's Exploited, Real-World Impact, Vulnerable vs. Secure), and wrap each one's content in a card body, e.g.:

```html
<section class="card mb-4 fjord-card">
  <div class="card-body">
    <h2 class="h5">What It Is</h2>
    {% block what_it_is %}{% endblock %}
  </div>
</section>
```

Apply the same transformation (section → card+card-body, `<h2>` → `<h2 class="h5">` to avoid an oversized heading inside a card) to the Why It Matters, How It's Exploited (including its nested Mermaid diagram div, which stays inside the card body unchanged), Real-World Impact, and Vulnerable vs. Secure sections. Leave the final "Examples in This Category" `<section>` (the list-group of example links) as a plain section, NOT a card — it already reads as a list, and the existing per-example `<li class="list-group-item ...">` styling picks up the new border/bg tokens automatically without needing a card wrapper.

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_fjord_example_and_overview_pages.py -v`
Expected: PASS (12 tests: 1 sanity + 1 single-icon + 10 per-category).

- [ ] **Step 7: Run the full suite to confirm no regressions**

Run: `pytest -q`
Expected: 647 passed, 3 skipped (635 + 12 new).

- [ ] **Step 8: Commit**

```bash
git add app/core/templates/core/example_page_base.html app/core/templates/core/overview_base.html tests/test_fjord_example_and_overview_pages.py
git commit -m "feat: restyle example and category overview pages with Fjord cards/icons

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 4: Home page cards, icons, and animation

**Files:**
- Modify: `app/core/templates/core/home.html`
- Test: `tests/test_fjord_home.py` (new)

**Interfaces:**
- Consumes: `.category-icon`, `.icon-box`, `.fjord-card`, `.fjord-fill` from Task 1.

**Orchestration note:** re-read `app/core/templates/core/home.html` fresh before editing — sub-project 2's Task 5 (badge indicators) already modified this file; find the actual current content by reading it, not by assuming the version quoted in earlier specs.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_fjord_home.py`:

```python
from app.core.seed import seed_database


def test_home_page_category_cards_have_icons(app, client):
    seed_database(app)
    response = client.get("/")
    body = response.data.decode()
    for n in range(1, 11):
        assert f"#icon-a{n:02d}" in body


def test_home_page_category_cards_have_fjord_card_class(app, client):
    seed_database(app)
    response = client.get("/")
    assert b"fjord-card" in response.data


def test_home_page_progress_bars_animate_on_load(app, client):
    seed_database(app)
    response = client.get("/")
    assert b"fjord-fill" in response.data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_fjord_home.py -v`
Expected: FAIL.

- [ ] **Step 3: Update `home.html`**

Read the file fresh. Find the overall-progress bar (currently `<div class="progress-bar" style="width: {{ overall_percent }}%"></div>`) and add the animation class:

```html
    <div class="progress-bar fjord-fill" style="width: {{ overall_percent }}%"></div>
```

Find the per-category card (currently `<div class="card h-100">`) and add both the hover class and an icon box before the title. The card title block (post sub-project-2) looks like:

```html
        <h5 class="card-title d-flex justify-content-between align-items-center">
          <span>{{ cs.category.short_id }}: {{ cs.category.title }}</span>
          {% if cs.badge_earned %}
          <span class="badge text-bg-success" title="All {{ cs.category.short_id }} examples completed">🏅 {{ cs.category.short_id }}</span>
          {% else %}
          <span class="badge text-bg-secondary" title="Complete every {{ cs.category.short_id }} example to earn this badge">{{ cs.category.short_id }}</span>
          {% endif %}
        </h5>
```

Change the outer card:

```html
    <div class="card h-100 fjord-card">
```

And add the icon inside the title's left `<span>`:

```html
        <h5 class="card-title d-flex justify-content-between align-items-center">
          <span class="d-flex align-items-center gap-2">
            <span class="icon-box" style="width: 28px; height: 28px; border-radius: 8px;">
              <svg class="category-icon" style="width: 16px; height: 16px;" viewBox="0 0 24 24">
                <use href="{{ url_for('static', filename='icons/category-icons.svg') }}#icon-{{ cs.category.id[:3] }}"></use>
              </svg>
            </span>
            {{ cs.category.short_id }}: {{ cs.category.title }}
          </span>
          {% if cs.badge_earned %}
          <span class="badge text-bg-success" title="All {{ cs.category.short_id }} examples completed">🏅 {{ cs.category.short_id }}</span>
          {% else %}
          <span class="badge text-bg-secondary" title="Complete every {{ cs.category.short_id }} example to earn this badge">{{ cs.category.short_id }}</span>
          {% endif %}
        </h5>
```

Find the per-category progress bar (`<div class="progress-bar" style="width: {{ cs.percent }}%"></div>`) and add the animation class the same way:

```html
        <div class="progress-bar fjord-fill" style="width: {{ cs.percent }}%"></div>
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_fjord_home.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Run the full suite to confirm no regressions**

Run: `pytest -q`
Expected: 650 passed, 3 skipped (647 + 3 new).

- [ ] **Step 6: Commit**

```bash
git add app/core/templates/core/home.html tests/test_fjord_home.py
git commit -m "feat: add category icons and fill-on-load animation to home page

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 5: Remaining pages — batched restyle + final verification

**Files:**
- Modify: `app/core/templates/core/leaderboard.html`, `instructor.html`, `switch_user.html`, `settings.html`, `tools.html`, `about.html`
- Test: `tests/test_fjord_remaining_pages.py` (new)

**Interfaces:**
- Consumes: `.fjord-card`, `.fjord-fill` from Task 1 (leaderboard/instructor tables get no new markup beyond confirming they inherit tokens correctly — see below).

**Orchestration note:** re-read all six files fresh before editing. `leaderboard.html` and `instructor.html` were both added by sub-project 2 (gamification) — confirm their exact current markup rather than assuming.

This is one batched task (per the spec's suggestion) because each of these six pages is a small, structurally-simple page needing the same kind of minimal touch-up, not its own bespoke design:

- [ ] **Step 1: Write the failing tests**

Create `tests/test_fjord_remaining_pages.py`:

```python
from app.core.models import User
from app.core.seed import seed_database


def _login_as(client, app, username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        user_id = user.id
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
    return user_id


def test_leaderboard_table_uses_fjord_card_wrapper(app, client):
    seed_database(app)
    response = client.get("/leaderboard")
    assert response.status_code == 200
    assert b"fjord-card" in response.data


def test_instructor_view_table_uses_fjord_card_wrapper(app, client):
    seed_database(app)
    _login_as(client, app, "admin")
    response = client.get("/instructor")
    assert response.status_code == 200
    assert b"fjord-card" in response.data


def test_switch_user_page_still_renders(app, client):
    seed_database(app)
    response = client.get("/switch-user")
    assert response.status_code == 200
    assert b"Choose Who You're Logged In As" in response.data


def test_settings_page_still_renders(app, client):
    seed_database(app)
    response = client.get("/settings")
    assert response.status_code == 200


def test_tools_page_still_renders(app, client):
    seed_database(app)
    response = client.get("/tools")
    assert response.status_code == 200


def test_about_page_still_renders(app, client):
    seed_database(app)
    response = client.get("/about")
    assert response.status_code == 200
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_fjord_remaining_pages.py -v`
Expected: `test_leaderboard_table_uses_fjord_card_wrapper` and `test_instructor_view_table_uses_fjord_card_wrapper` FAIL (no `fjord-card` yet); the four "still renders" tests already PASS (they assert pre-existing behavior, added here as a regression net for this task's edits).

- [ ] **Step 3: Wrap the leaderboard and instructor tables in Fjord cards**

In `leaderboard.html`, read the file fresh to find the `<table class="table">` element and wrap it:

```html
<div class="card fjord-card mb-3">
  <div class="card-body">
    <table class="table mb-0">
      ...
    </table>
  </div>
</div>
```

(Keep every existing `<thead>`/`<tbody>`/row/column content exactly as-is — only add the wrapping `<div class="card fjord-card mb-3"><div class="card-body">...</div></div>` around the existing `<table class="table">...</table>`, and add `mb-0` to the table itself since the card now provides the bottom margin.)

Apply the identical wrapping to `instructor.html`'s table.

- [ ] **Step 4: Verify the remaining four pages need no markup changes**

`switch_user.html`, `settings.html`, `tools.html`, `about.html` all use plain Bootstrap components (`list-group`, forms, plain text) that inherit Task 1's token overrides automatically with zero markup changes — confirm this by reading each file fresh and checking it uses only `.card`, `.list-group`, `.btn`, `.form-*`, or plain text elements (no hardcoded colors like `text-light`, `bg-dark`, `text-white` that would fight the new theme). If any hardcoded color utility class is found in any of these four files, remove it (following the same pattern as Task 2's nav fix) and note which file/class in the task's completion report.

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_fjord_remaining_pages.py -v`
Expected: PASS (6 tests).

- [ ] **Step 6: Run the full suite**

Run: `pytest -q`
Expected: 656 passed, 3 skipped (650 + 6 new).

- [ ] **Step 7: Commit**

```bash
git add app/core/templates/core/leaderboard.html app/core/templates/core/instructor.html tests/test_fjord_remaining_pages.py
git commit -m "feat: wrap leaderboard and instructor tables in Fjord cards

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

(If Step 4 found and fixed any hardcoded color classes in `switch_user.html`/`settings.html`/`tools.html`/`about.html`, `git add` those files too before committing, and mention the fix in the commit body.)

- [ ] **Step 8: Update README if needed**

Read `README.md` fresh. If it describes the app's visual design anywhere (check the "What this is" section and any screenshots references), no text changes are needed — the existing screenshots (`docs/screenshots/*.png`) will simply be stale until someone retakes them, which is expected and not blocking (screenshot refresh is a manual, human step outside this plan's scope — do not attempt to regenerate them).

---

## Self-Review

**1. Spec coverage:**
- Color tokens (light + dark, via Bootstrap's own `--bs-*` variables) → Task 1. ✅
- IBM Plex Sans/Mono, vendored locally → Task 1. ✅
- Icon sprite, all 10 category icons + shield mark → Task 1, consumed by Tasks 2-4. ✅
- Fill-on-load progress bar animation, card-hover lift/icon-rotate → Task 1 (CSS), Task 4 (applied to home page, the only page with per-category progress bars). ✅
- `base.html` nav/sidebar restyle → Task 2. ✅
- `example_page_base.html` + `overview_base.html` → Task 3. ✅
- `home.html` → Task 4. ✅
- `leaderboard.html`, `instructor.html`, `switch_user.html`, `settings.html`, `tools.html`, `about.html` → Task 5. ✅
- "Bootstrap semantic colors untouched" constraint → never overridden in any task; difficulty/gamification badges keep `text-bg-*` classes unchanged throughout.
- "🌗 toggle keeps working" constraint → no task touches `toggleLabTheme()`, the `data-bs-theme` attribute mechanism, or `localStorage` key; only what each theme state visually resolves to changes.

**2. Placeholder scan:** every step has literal, complete code (exact CSS, exact SVG markup, exact Jinja diffs, exact download URLs with pre-verified checksums). No "add appropriate styling" or "similar to Task N" without the actual repeated content.

**3. Type/naming consistency:** `.category-icon`/`.icon-box`/`.fjord-card`/`.fjord-fill` are defined once in Task 1 and referenced with those exact class names in every later task. The icon-id derivation (`category.id[:3]` → `"a01"`..`"a10"`) is used identically in Task 3 (overview pages) and Task 4 (home page cards).

**4. Running total sanity check:** 626 (baseline) + 6 (Task 1) + 3 (Task 2) + 12 (Task 3) + 3 (Task 4) + 6 (Task 5) = 656 passed, 3 skipped at completion. Each task's "expected" full-suite count matches this running total.

**5. Risk note carried to execution:** Task 3's exact count of `class="card mb-4"` occurrences in `example_page_base.html` is discovered via `grep -c` at execution time rather than hardcoded here, since the plan-writer's own read of the file did not re-count every conditional block precisely — the step explicitly instructs finding and replacing *every* occurrence, not a fixed number, to avoid under-replacing if the count differs from what's implied above.
