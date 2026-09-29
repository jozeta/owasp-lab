# Visual Roadmap Homepage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the home page's 2-column grid of 10 category cards with a single connected "trail" of 10 nodes (conic-gradient progress rings, a progress-filled spine, CSS-only responsive zigzag), using the Fjord design system finalized in sub-project 3.

**Architecture:** Pure presentation layer, one template (`home.html`) plus an addition to the existing single stylesheet (`static/css/lab.css`) — zero route/model changes. `app/core/views.py`'s `home()` already computes every value each node needs.

**Tech Stack:** CSS `conic-gradient` (progress rings), CSS Grid (desktop 2-column zigzag via `nth-of-type`), Jinja2, Flask test client.

**Spec:** docs/superpowers/specs/2026-09-29-owasp-lab-roadmap-homepage-design.md

## Global Constraints

- No new routes, models, or JS — the existing `home()` view function in `app/core/views.py` is not touched by this plan at all.
- The "Overall" summary card (top of the page) and the anonymous-visitor "pick a user" alert are unchanged — only the category grid below them is replaced.
- Every pre-existing test that asserts on home-page text must keep passing. Verified during plan-writing which exact substrings other test files depend on:
  - `tests/test_progress.py::test_home_page_shows_correct_per_category_count` asserts `f"1 of {len(a03.examples)} completed"` and `"A03: Injection"` are present — the new node markup must render `{{ cs.completed }} of {{ cs.total }} completed` and `{{ cs.category.short_id }}: {{ cs.category.title }}` as contiguous text, exactly as today.
  - `tests/test_core_views.py::test_home_page_lists_categories_sorted_by_short_id` asserts `"A01"` appears before `"A02"` in the body — preserved automatically since `category_stats`'s iteration order is untouched.
  - `tests/test_progress.py`/`tests/test_per_user_progress.py` assert the *Overall* card's `f"0 of {len(examples)} completed — 0%"` text — untouched, since that card isn't touched by this plan.
  - `tests/test_home_badges.py` asserts presence/absence of `"text-bg-success"` (never `"text-bg-secondary"`) — the earned-badge marker keeps the `text-bg-success` class; the unearned pill is dropped per the spec's refined badge-semantics section (verified no test depends on it).
  - `tests/test_fjord_nav.py` asserts `"category-icons.svg"` is present — still true (both the nav brand icon and every roadmap node reference the same sprite file).
  - `tests/test_fjord_home.py::test_home_page_progress_bars_animate_on_load` asserts `"fjord-fill"` is present — still true, sourced from the unchanged Overall card's progress bar (the per-category `fjord-fill` bars are removed, but the Overall one remains).
  - `tests/test_fjord_home.py::test_home_page_category_cards_have_fjord_card_class` asserts `"fjord-card"` is present — **this one breaks and must be updated** (Task 2, Step 6) since the new node markup has no `.card`/`.fjord-card` element at all; this is an intentional, expected consequence of replacing the card grid, not a regression.
- Baseline at plan-writing time: 647 passed, 3 skipped, at commit 037849e on `main`.

---

### Task 1: Roadmap CSS foundation

**Files:**
- Modify: `static/css/lab.css` (currently 265 lines — append everything below to the end)
- Test: `tests/test_roadmap_css.py` (new)

**Interfaces:**
- Produces: CSS classes `.roadmap`, `.roadmap-track`, `.roadmap-track-fill`, `.roadmap-node`, `.roadmap-node-ring`, `.roadmap-node-inner`, `.roadmap-badge`, `.roadmap-node-info`, `.roadmap-node-title`, plus a `min-width: 768px` media query with `nth-of-type(odd)`/`nth-of-type(even)` grid-column rules — consumed by Task 2's `home.html`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_roadmap_css.py`:

```python
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _lab_css():
    return (REPO_ROOT / "static/css/lab.css").read_text()


def test_roadmap_classes_defined():
    css = _lab_css()
    for cls in (
        ".roadmap {",
        ".roadmap-track,",
        ".roadmap-track-fill {",
        ".roadmap-node {",
        ".roadmap-node-ring {",
        ".roadmap-node-inner {",
        ".roadmap-badge {",
        ".roadmap-node-info {",
        ".roadmap-node-title {",
    ):
        assert cls in css, f"missing rule: {cls}"


def test_roadmap_ring_uses_conic_gradient_and_pct_variable():
    css = _lab_css()
    assert "conic-gradient(var(--fjord-accent) calc(var(--pct) * 1%)" in css


def test_roadmap_has_desktop_zigzag_breakpoint():
    css = _lab_css()
    assert "@media (min-width: 768px) {" in css
    assert "grid-template-columns: 1fr 1fr;" in css
    assert ":nth-of-type(odd)" in css
    assert ":nth-of-type(even)" in css


def test_roadmap_track_fill_uses_fjord_accent():
    css = _lab_css()
    assert ".roadmap-track-fill {\n  background: var(--fjord-accent);" in css


def test_lab_css_original_content_untouched():
    """Sanity check: the file has grown, not been rewritten -- the
    pre-existing sidebar/card/font-face rules from earlier sub-projects
    must still be present verbatim."""
    css = _lab_css()
    assert "#sidebar .nav-link {" in css
    assert '@font-face {\n  font-family: "IBM Plex Sans";' in css
    assert "@keyframes fjord-fill {" in css
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_roadmap_css.py -v`
Expected: FAIL (none of the new classes exist yet).

- [ ] **Step 3: Append the roadmap CSS to `static/css/lab.css`**

Append exactly this to the end of the existing 265-line file (do not modify anything above it):

```css

/* ===================================================================
   Roadmap homepage
   =================================================================== */

.roadmap {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 1.75rem;
  margin: 2rem 0 0;
  padding: 0;
}

.roadmap-track,
.roadmap-track-fill {
  position: absolute;
  left: 24px;
  top: 0;
  width: 3px;
  border-radius: 999px;
}

.roadmap-track {
  bottom: 0;
  background: var(--bs-border-color);
}

.roadmap-track-fill {
  background: var(--fjord-accent);
}

.roadmap-node {
  position: relative;
  display: flex;
  align-items: center;
  gap: 1rem;
  text-decoration: none;
  color: inherit;
}

.roadmap-node:hover .roadmap-node-title {
  color: var(--fjord-accent);
}

.roadmap-node-ring {
  position: relative;
  flex: 0 0 48px;
  width: 48px;
  height: 48px;
  border-radius: 50%;
  padding: 3px;
  background: conic-gradient(var(--fjord-accent) calc(var(--pct) * 1%), var(--bs-border-color) 0);
  transition: transform 0.18s ease;
}

.roadmap-node:hover .roadmap-node-ring {
  transform: scale(1.06);
}

.roadmap-node-inner {
  width: 100%;
  height: 100%;
  border-radius: 50%;
  background: var(--bs-body-bg);
  display: grid;
  place-items: center;
}

.roadmap-node-inner .category-icon {
  width: 22px;
  height: 22px;
  color: var(--fjord-accent);
}

.roadmap-badge {
  position: absolute;
  top: -6px;
  right: -8px;
  font-size: 0.7rem;
  padding: 0.15rem 0.35rem;
}

.roadmap-node-info {
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
}

.roadmap-node-title {
  font-weight: 600;
  transition: color 0.15s ease;
}

@media (min-width: 768px) {
  .roadmap {
    display: grid;
    grid-template-columns: 1fr 1fr;
    column-gap: 48px;
    row-gap: 1.75rem;
  }

  .roadmap-track,
  .roadmap-track-fill {
    left: 50%;
    transform: translateX(-50%);
  }

  .roadmap-node:nth-of-type(odd) {
    grid-column: 1;
    flex-direction: row-reverse;
    text-align: right;
  }

  .roadmap-node:nth-of-type(even) {
    grid-column: 2;
  }
}
```

(Design notes for the implementer, not to be added as CSS comments: the mobile track sits at `left: 24px` because each node's ring is a `flex: 0 0 48px` first child with no leading margin, so the ring's horizontal center is exactly 24px from the container's left edge. On desktop, CSS Grid's `grid-column: 1`/`grid-column: 2` placement combined with `nth-of-type` deterministically zigzags nodes without relying on flexbox auto-margins; `flex-direction: row-reverse` on odd/left-column nodes puts their ring on the side nearest the center spine, matching even/right-column nodes' normal-order ring placement on their own near-center side. `.roadmap-track`/`.roadmap-track-fill` are `<div>` elements and every node is an `<a>` element — this different-tag-name split is what makes `:nth-of-type` count correctly among only the node siblings, ignoring the track divs.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_roadmap_css.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Run the full suite to confirm no regressions**

Run: `pytest -q`
Expected: 652 passed, 3 skipped (647 + 5 new).

- [ ] **Step 6: Commit**

```bash
git add static/css/lab.css tests/test_roadmap_css.py
git commit -m "feat: add roadmap CSS (progress rings, spine, zigzag)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 2: Replace the home-page category grid with the roadmap

**Files:**
- Modify: `app/core/templates/core/home.html`
- Modify: `tests/test_fjord_home.py` (one test needs updating — see Step 6)
- Test: `tests/test_roadmap_homepage.py` (new)

**Interfaces:**
- Consumes: `.roadmap`/`.roadmap-node`/`.roadmap-node-ring`/etc. (Task 1); `category_stats`, `overall_percent`, `settings.scoring_enabled` (all pre-existing, unchanged, from `home()`).

**Orchestration note:** re-read `app/core/templates/core/home.html` fresh before editing — this brief quotes its current exact content below, but confirm it still matches before making any change.

- [ ] **Step 1: Confirm the current exact content of `home.html`**

It should currently read exactly:

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

<div class="card mb-4">
  <div class="card-body">
    <div class="d-flex justify-content-between mb-1">
      <span class="fw-bold">Overall</span>
      <span>{{ completed_total }} of {{ total }} completed — {{ overall_percent }}%</span>
    </div>
    <div class="progress" role="progressbar" aria-label="Overall progress" aria-valuenow="{{ completed_total }}" aria-valuemin="0" aria-valuemax="{{ total }}">
      <div class="progress-bar fjord-fill" style="width: {{ overall_percent }}%"></div>
    </div>
    {% if settings.scoring_enabled %}
    <div class="mt-2 text-muted">Score: {{ earned_points_total }} / {{ max_points_total }} points</div>
    {% endif %}
  </div>
</div>

<div class="row row-cols-1 row-cols-md-2 g-3 mt-2">
  {% for cs in category_stats %}
  <div class="col">
    <div class="card h-100 fjord-card">
      <div class="card-body">
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
        <div class="mb-1">{{ cs.completed }} of {{ cs.total }} completed</div>
        <div class="progress mb-3" role="progressbar" aria-label="{{ cs.category.short_id }} progress" aria-valuenow="{{ cs.completed }}" aria-valuemin="0" aria-valuemax="{{ cs.total }}">
          <div class="progress-bar fjord-fill" style="width: {{ cs.percent }}%"></div>
        </div>
        {% if settings.scoring_enabled %}
        <div class="mb-2 text-muted small">Score: {{ cs.earned_points }} / {{ cs.max_points }} points</div>
        {% endif %}
        <a href="{{ url_for(cs.category.overview_endpoint) }}" class="btn btn-outline-primary btn-sm">Open overview</a>
      </div>
    </div>
  </div>
  {% endfor %}
</div>
{% endblock %}
```

If it differs, stop and reconcile before proceeding — do not blindly apply Step 3's diff to a file that doesn't match this.

- [ ] **Step 2: Write the failing tests**

Create `tests/test_roadmap_homepage.py`:

```python
from datetime import datetime

from app.core.models import ExampleProgress, User
from app.core.nav import CATEGORIES
from app.core.seed import seed_database
from app.extensions import db


def _login_as(client, app, username):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        user_id = user.id
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
    return user_id


def test_home_page_has_roadmap_with_all_ten_nodes(app, client):
    seed_database(app)
    response = client.get("/")
    body = response.data.decode()
    assert '<div class="roadmap">' in body
    assert body.count('class="roadmap-node"') == 10


def test_roadmap_nodes_link_to_their_overview_pages(app, client):
    seed_database(app)
    response = client.get("/")
    body = response.data.decode()
    for category in CATEGORIES:
        assert f'href="/{category.short_id.lower()}/"' in body


def test_roadmap_node_shows_correct_percent_and_icon(app, client):
    seed_database(app)
    user_id = _login_as(client, app, "alice")
    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")

    with app.app_context():
        db.session.add(
            ExampleProgress(
                user_id=user_id,
                example_id=a10.examples[0].id,
                completed_at=datetime.utcnow(),
                points_awarded=a10.examples[0].base_points(),
            )
        )
        db.session.commit()

    response = client.get("/")
    body = response.data.decode()
    expected_percent = round(1 / len(a10.examples) * 100)
    assert f"--pct: {expected_percent}" in body
    assert "#icon-a10" in body


def test_roadmap_shows_badge_marker_only_when_earned(app, client):
    seed_database(app)
    user_id = _login_as(client, app, "alice")
    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")

    response = client.get("/")
    assert b"text-bg-success" not in response.data

    with app.app_context():
        for example in a10.examples:
            db.session.add(
                ExampleProgress(
                    user_id=user_id,
                    example_id=example.id,
                    completed_at=datetime.utcnow(),
                    points_awarded=example.base_points(),
                )
            )
        db.session.commit()

    response = client.get("/")
    assert b"text-bg-success" in response.data


def test_roadmap_track_fill_reflects_overall_percent(app, client):
    seed_database(app)
    response = client.get("/")
    assert b'class="roadmap-track-fill" style="height: 0%"' in response.data
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_roadmap_homepage.py -v`
Expected: FAIL (no `.roadmap` markup exists yet).

- [ ] **Step 4: Replace the category grid in `home.html`**

Replace the entire `<div class="row row-cols-1 row-cols-md-2 g-3 mt-2">...</div>` block (everything from that opening tag through its matching closing `</div>`, just before `{% endblock %}`) with:

```html
<div class="roadmap">
  <div class="roadmap-track"></div>
  <div class="roadmap-track-fill" style="height: {{ overall_percent }}%"></div>
  {% for cs in category_stats %}
  <a href="{{ url_for(cs.category.overview_endpoint) }}" class="roadmap-node">
    <span class="roadmap-node-ring" style="--pct: {{ cs.percent }}">
      <span class="roadmap-node-inner">
        <svg class="category-icon" viewBox="0 0 24 24">
          <use href="{{ url_for('static', filename='icons/category-icons.svg') }}#icon-{{ cs.category.id[:3] }}"></use>
        </svg>
      </span>
      {% if cs.badge_earned %}
      <span class="badge text-bg-success roadmap-badge" title="All {{ cs.category.short_id }} examples completed">🏅</span>
      {% endif %}
    </span>
    <span class="roadmap-node-info">
      <span class="roadmap-node-title">{{ cs.category.short_id }}: {{ cs.category.title }}</span>
      <span class="text-muted small">{{ cs.completed }} of {{ cs.total }} completed</span>
      {% if settings.scoring_enabled %}
      <span class="text-muted small">Score: {{ cs.earned_points }} / {{ cs.max_points }} points</span>
      {% endif %}
    </span>
  </a>
  {% endfor %}
</div>
```

Leave every other part of `home.html` (the `<h1>`, the lead paragraph, the anonymous-visitor alert, and the "Overall" summary card above this block) completely untouched.

- [ ] **Step 5: Run the new tests to verify they pass**

Run: `pytest tests/test_roadmap_homepage.py -v`
Expected: PASS (5 tests).

- [ ] **Step 6: Update the one pre-existing test this change intentionally breaks**

Run: `pytest tests/test_fjord_home.py -v`
Expected: `test_home_page_category_cards_have_fjord_card_class` FAILS (the `.card`/`fjord-card` grid it asserted on no longer exists — this is expected, not a regression, per this plan's Global Constraints).

Edit `tests/test_fjord_home.py`: rename `test_home_page_category_cards_have_fjord_card_class` to `test_home_page_roadmap_nodes_are_present` and change its body to assert on the new markup instead:

```python
def test_home_page_roadmap_nodes_are_present(app, client):
    seed_database(app)
    response = client.get("/")
    assert b'class="roadmap-node"' in response.data
```

Leave the other two tests in this file (`test_home_page_category_cards_have_icons`, `test_home_page_progress_bars_animate_on_load`) completely unchanged — both still pass against the new markup without modification (verified during plan-writing: icons are still referenced per-node, and `fjord-fill` still appears via the unchanged Overall card's progress bar).

- [ ] **Step 7: Run the full suite to confirm no regressions**

Run: `pytest -q`
Expected: 657 passed, 3 skipped (652 + 5 new; the renamed test replaces a test 1-for-1, no net count change from that edit).

- [ ] **Step 8: Commit**

```bash
git add app/core/templates/core/home.html tests/test_roadmap_homepage.py tests/test_fjord_home.py
git commit -m "feat: replace home-page category grid with a visual roadmap

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

### Task 3: Final integration

**Files:**
- (README check only — no expected changes; see Step 1)

- [ ] **Step 1: Check `README.md`'s Home-page description**

Read `README.md`'s "More pages" section fresh. Its existing **Home** bullet describes behavior ("your own progress across every example, overall and per category... Progress is tracked per user...") — this remains equally true of the roadmap layout; the bullet does not describe the grid specifically. Confirm this and make NO changes — this step exists to verify, not to edit.

- [ ] **Step 2: Run the full suite fresh**

Run: `pytest -q`
Expected: 657 passed, 3 skipped.

- [ ] **Step 3: Manually sanity-check both themes and both breakpoints**

Since this plan's core value is visual, and pytest cannot assert on rendered pixel layout, the final whole-branch review (per the subagent-driven-development process) MUST include genuine rendering verification: fetch `/` via the test client with real progress data (some categories complete, some partial, some untouched, at least one earning a badge) and confirm the returned HTML has plausible, well-formed structure (balanced tags, exactly 10 `roadmap-node` elements, exactly one `roadmap-track`/`roadmap-track-fill` pair). A live browser check (if tooling is available) or a careful manual trace of the CSS Grid zigzag geometry described in Task 1 is strongly encouraged given this plan introduces genuinely new, from-scratch CSS layout that no existing precedent in this app has visually validated.

---

## Self-Review

**1. Spec coverage:**
- Conic-gradient progress ring, exact CSS → Task 1. ✅
- Progress-filled spine → Task 1 (CSS) + Task 2 (inline `style="height: ..."`). ✅
- CSS-only responsive zigzag (mobile stack, desktop 2-column) → Task 1. ✅
- Node content (icon, title, completed count, score) → Task 2. ✅
- Refined badge semantics (earned marker kept, unearned pill dropped) → Task 2. ✅
- "What does NOT change" (Overall card, anonymous alert, `scoring_enabled` gating) → respected; Task 2's diff touches only the grid block, nothing above it.
- Every pre-existing test dependency identified during plan-writing (Global Constraints list) → cross-checked against Task 2's exact new markup; only one test needed updating, and that update is spelled out exactly, not left as "update as needed."

**2. Placeholder scan:** every step has complete, literal CSS/HTML/test code. No "similar to Task N," no vague styling instructions.

**3. Type/naming consistency:** `.roadmap-node`/`.roadmap-node-ring`/`.roadmap-node-inner`/`.roadmap-node-info`/`.roadmap-node-title`/`.roadmap-track`/`.roadmap-track-fill`/`.roadmap-badge` are defined once in Task 1 and used with those exact names, unchanged, in Task 2's markup and tests.

**4. Running total sanity check:** 647 (baseline) + 5 (Task 1) + 5 (Task 2, net — one test renamed/redirected, not added) = 657 passed, 3 skipped at Task 3. Matches each task's stated expected count.

**5. Risk note carried to execution:** this is the first sub-project in the whole 4-part initiative introducing CSS layout with no prior working precedent in this codebase to copy from (sub-project 3 only re-skinned existing Bootstrap components). The CSS Grid zigzag geometry was reasoned through carefully during plan-writing but not empirically rendered — Task 3 explicitly calls out that the final whole-branch review must do real rendering verification, not just diff-reading, given this elevated risk.
