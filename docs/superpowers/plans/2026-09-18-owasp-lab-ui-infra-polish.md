# UI/Infra Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add hover tooltips on the top nav, highlight.js line numbers, a dark-mode toggle, a Tools page, and an About page to the existing shared UI framework, so every category (A01–A10) benefits without touching any category's vulnerable logic.

**Architecture:** All changes live in `app/core/` (nav data model, base template, two new routes/templates) and `static/` (two newly vendored files, JS/CSS additions). `CategoryNav` gains a `blurb` field consumed by the tooltip markup; the dark-mode toggle sets `data-bs-theme` on `<html>` and reloads the page rather than attempting live re-render of Mermaid/highlight.js output.

**Tech Stack:** Flask, Jinja2, Bootstrap 5 (vendored, native dark-mode + tooltip support), highlight.js 11.9.0 (already vendored) plus two newly vendored static files (`highlightjs-line-numbers.min.js`, `github-dark.min.css`), vanilla JS (no new JS framework), pytest.

**Spec:** docs/superpowers/specs/2026-09-18-owasp-lab-ui-infra-polish-design.md

## Global Constraints

- No CDN references anywhere in HTML — every asset is vendored under `static/vendor/` and served locally, exactly like the existing Bootstrap/Mermaid/highlight.js assets.
- No new JS framework or build step — plain `<script>` tags and vanilla JS in `static/js/lab.js`, matching the existing pattern.
- No changes to any category's vulnerable routes, models, or templates — this plan touches only `app/core/`, each category's `__init__.py` (one new kwarg each), and `static/`.
- Dark mode must not attempt live re-render of Mermaid SVGs or highlight.js output — toggling saves the preference to `localStorage` and reloads the page.
- Every new/changed template still extends `core/base.html` (or is `base.html` itself) so the warning banner, nav, and sidebar remain consistent.
- This project has no JS test harness — do not add one. JS behavior (tooltip hover, theme toggle round-trip, line numbers rendering) is verified manually in the final Docker-verification task, the same way every prior category's UI was manually spot-checked.

---

### Task 1: `CategoryNav.blurb` field + retrofit onto A01–A04

**Files:**
- Modify: `app/core/nav.py`
- Modify: `app/categories/a01_access_control/__init__.py`
- Modify: `app/categories/a02_crypto_failures/__init__.py`
- Modify: `app/categories/a03_injection/__init__.py`
- Modify: `app/categories/a04_insecure_design/__init__.py`
- Test: `tests/test_nav.py`

**Interfaces:**
- Consumes: nothing new — `CategoryNav` already exists at `app/core/nav.py:19-27`.
- Produces: `CategoryNav.blurb: str` (default `""`), a one-sentence tooltip description. Task 2 reads `category.blurb` in `base.html`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_nav.py`:

```python
def test_category_nav_defaults_to_empty_blurb():
    category = CategoryNav(
        id="x",
        short_id="X",
        title="X",
        blueprint_name="x",
        overview_endpoint="core.home",
    )
    assert category.blurb == ""


def test_every_registered_category_has_a_nonempty_blurb(app):
    # `app` fixture forces create_app() to run, which is what actually
    # imports every category blueprint and populates CATEGORIES -- without
    # it this test could vacuously pass on an empty list depending on
    # pytest's collection order.
    from app.core.nav import CATEGORIES

    for category in CATEGORIES:
        assert category.blurb.strip() != "", f"{category.short_id} is missing a blurb"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_nav.py -v`
Expected: both new tests FAIL with `AttributeError: 'CategoryNav' object has no attribute 'blurb'` (the field doesn't exist on the dataclass yet).

- [ ] **Step 3: Add the `blurb` field to `CategoryNav`**

In `app/core/nav.py`, the current `CategoryNav` dataclass reads:

```python
@dataclass
class CategoryNav:
    id: str
    short_id: str
    title: str
    blueprint_name: str
    overview_endpoint: str
    examples: list = field(default_factory=list)
    seed_fn: object = None
```

Change it to:

```python
@dataclass
class CategoryNav:
    id: str
    short_id: str
    title: str
    blueprint_name: str
    overview_endpoint: str
    examples: list = field(default_factory=list)
    seed_fn: object = None
    blurb: str = ""
```

- [ ] **Step 4: Run the first test to verify it passes**

Run: `pytest tests/test_nav.py::test_category_nav_defaults_to_empty_blurb -v`
Expected: PASS

- [ ] **Step 5: Retrofit the `blurb=` kwarg onto all 4 existing categories**

In `app/categories/a01_access_control/__init__.py`, the `CategoryNav(...)` call currently opens:

```python
    CategoryNav(
        id="a01_access_control",
        short_id="A01",
        title="Broken Access Control",
        blueprint_name="a01_access_control",
```

Insert a `blurb=` line immediately after `title=`:

```python
    CategoryNav(
        id="a01_access_control",
        short_id="A01",
        title="Broken Access Control",
        blurb="Access control that is not enforced on the server, letting users act outside their intended permissions.",
        blueprint_name="a01_access_control",
```

In `app/categories/a02_crypto_failures/__init__.py`, the call opens:

```python
    CategoryNav(
        id="a02_crypto_failures",
        short_id="A02",
        title="Cryptographic Failures",
        blueprint_name="a02_crypto_failures",
```

Change to:

```python
    CategoryNav(
        id="a02_crypto_failures",
        short_id="A02",
        title="Cryptographic Failures",
        blurb="Weak or misused cryptography that exposes passwords and sensitive data instead of protecting them.",
        blueprint_name="a02_crypto_failures",
```

In `app/categories/a03_injection/__init__.py`, the call opens:

```python
    CategoryNav(
        id="a03_injection",
        short_id="A03",
        title="Injection",
        blueprint_name="a03_injection",
```

Change to:

```python
    CategoryNav(
        id="a03_injection",
        short_id="A03",
        title="Injection",
        blurb="Untrusted input executed by an interpreter, such as SQL, a shell, or the browser, instead of being treated as data.",
        blueprint_name="a03_injection",
```

In `app/categories/a04_insecure_design/__init__.py`, the call opens:

```python
    CategoryNav(
        id="a04_insecure_design",
        short_id="A04",
        title="Insecure Design",
        blueprint_name="a04_insecure_design",
```

Change to:

```python
    CategoryNav(
        id="a04_insecure_design",
        short_id="A04",
        title="Insecure Design",
        blurb="Missing security controls baked into the design itself, not just a coding mistake.",
        blueprint_name="a04_insecure_design",
```

- [ ] **Step 6: Run the full test file to verify it passes**

Run: `pytest tests/test_nav.py -v`
Expected: PASS (4 tests: the 2 pre-existing plus the 2 new ones)

- [ ] **Step 7: Run the full suite to confirm nothing else broke**

Run: `pytest tests/ -v`
Expected: all PASS (102 existing + 2 new = 104)

- [ ] **Step 8: Commit**

```bash
git add app/core/nav.py app/categories/a01_access_control/__init__.py \
  app/categories/a02_crypto_failures/__init__.py app/categories/a03_injection/__init__.py \
  app/categories/a04_insecure_design/__init__.py tests/test_nav.py
git commit -m "feat: add CategoryNav.blurb field and retrofit onto A01-A04"
```

---

### Task 2: Hover tooltips on the top nav

**Files:**
- Modify: `app/core/templates/core/base.html`
- Modify: `static/js/lab.js`
- Test: `tests/test_core_views.py`

**Interfaces:**
- Consumes: `category.blurb` from Task 1's `CategoryNav`.
- Produces: nothing new consumed by later tasks — this is a leaf feature.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_core_views.py`:

```python
def test_home_page_category_links_include_tooltip_attributes(client):
    response = client.get("/")
    assert response.status_code == 200
    body = response.data.decode()
    assert 'data-bs-toggle="tooltip"' in body
    assert "Access control that is not enforced on the server" in body
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_core_views.py::test_home_page_category_links_include_tooltip_attributes -v`
Expected: FAIL — `assert 'data-bs-toggle="tooltip"' in body` is False (attribute not yet in the template).

- [ ] **Step 3: Add tooltip attributes to the category nav links**

In `app/core/templates/core/base.html`, the top-nav category loop currently reads:

```html
          {% for category in categories %}
          <li class="nav-item">
            <a class="nav-link {% if active_category and active_category.id == category.id %}active{% endif %}"
               href="{{ url_for(category.overview_endpoint) }}">{{ category.short_id }}</a>
          </li>
          {% endfor %}
```

Change the `<a>` tag to add the tooltip attributes:

```html
          {% for category in categories %}
          <li class="nav-item">
            <a class="nav-link {% if active_category and active_category.id == category.id %}active{% endif %}"
               href="{{ url_for(category.overview_endpoint) }}"
               data-bs-toggle="tooltip" data-bs-placement="bottom" title="{{ category.blurb }}">{{ category.short_id }}</a>
          </li>
          {% endfor %}
```

- [ ] **Step 4: Wire up Bootstrap's tooltip initialization**

In `static/js/lab.js`, the `DOMContentLoaded` handler currently ends with:

```js
  if (window.mermaid) {
    mermaid.initialize({ startOnLoad: true, theme: "default" });
  }
});
```

Add tooltip initialization right after the mermaid block, still inside the same listener:

```js
  if (window.mermaid) {
    mermaid.initialize({ startOnLoad: true, theme: "default" });
  }

  if (window.bootstrap) {
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(function (el) {
      new bootstrap.Tooltip(el);
    });
  }
});
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `pytest tests/test_core_views.py::test_home_page_category_links_include_tooltip_attributes -v`
Expected: PASS

- [ ] **Step 6: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (104 + 1 = 105)

- [ ] **Step 7: Commit**

```bash
git add app/core/templates/core/base.html static/js/lab.js tests/test_core_views.py
git commit -m "feat: add hover tooltips to top-nav category links"
```

---

### Task 3: highlight.js line numbers

**Files:**
- Create: `static/vendor/highlightjs/highlightjs-line-numbers.min.js` (vendored, not hand-written)
- Modify: `app/core/templates/core/base.html`
- Modify: `static/js/lab.js`
- Create: `tests/test_vendored_assets.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing consumed by later tasks — this is a leaf feature. (Task 4 adds a second file to the same new `tests/test_vendored_assets.py`, but doesn't depend on this task's code.)

- [ ] **Step 1: Vendor the line-numbers plugin**

Fetch the file from its canonical upstream source (the `wcoder/highlightjs-line-numbers.js` repository's built `dist/` output — a single-file, MIT-licensed plugin with no build step, compatible with highlight.js 11.x, which is the version already vendored in this project):

```bash
curl -sL https://raw.githubusercontent.com/wcoder/highlightjs-line-numbers.js/master/dist/highlightjs-line-numbers.min.js \
  -o static/vendor/highlightjs/highlightjs-line-numbers.min.js
```

Verify it downloaded correctly before continuing:

```bash
wc -c static/vendor/highlightjs/highlightjs-line-numbers.min.js
head -c 120 static/vendor/highlightjs/highlightjs-line-numbers.min.js
```

Expected: file size around 3.2–3.5 KB (not 0 bytes, not an HTML error page), and the first ~120 characters start with `!function(r,o){"use strict";var e,a="hljs-ln"` (confirms it's the real minified plugin, not a 404 page or truncated download).

- [ ] **Step 2: Write the failing test**

Create `tests/test_vendored_assets.py`:

```python
import pathlib

STATIC_ROOT = pathlib.Path(__file__).resolve().parent.parent / "static"


def test_line_numbers_plugin_is_vendored():
    path = STATIC_ROOT / "vendor" / "highlightjs" / "highlightjs-line-numbers.min.js"
    assert path.exists(), f"expected vendored file at {path}"
    content = path.read_text()
    assert len(content) > 1000
    assert "hljs-ln" in content
```

- [ ] **Step 3: Run test to verify it passes**

Run: `pytest tests/test_vendored_assets.py -v`
Expected: PASS (the file was already vendored in Step 1 — this test documents and locks in that the vendoring happened correctly; if it fails, Step 1's download didn't complete correctly and must be redone).

- [ ] **Step 4: Wire the plugin into the page**

In `app/core/templates/core/base.html`, the script tags currently read:

```html
  <script src="{{ url_for('static', filename='vendor/bootstrap/bootstrap.bundle.min.js') }}"></script>
  <script src="{{ url_for('static', filename='vendor/highlightjs/highlight.min.js') }}"></script>
  <script src="{{ url_for('static', filename='vendor/mermaid/mermaid.min.js') }}"></script>
  <script src="{{ url_for('static', filename='js/lab.js') }}"></script>
```

Add the new plugin's `<script>` tag right after highlight.js's:

```html
  <script src="{{ url_for('static', filename='vendor/bootstrap/bootstrap.bundle.min.js') }}"></script>
  <script src="{{ url_for('static', filename='vendor/highlightjs/highlight.min.js') }}"></script>
  <script src="{{ url_for('static', filename='vendor/highlightjs/highlightjs-line-numbers.min.js') }}"></script>
  <script src="{{ url_for('static', filename='vendor/mermaid/mermaid.min.js') }}"></script>
  <script src="{{ url_for('static', filename='js/lab.js') }}"></script>
```

In `static/js/lab.js`, the highlight.js block currently reads:

```js
  if (window.hljs) {
    hljs.highlightAll();
  }
```

Change it to also initialize line numbers:

```js
  if (window.hljs) {
    hljs.highlightAll();
    if (window.hljs.initLineNumbersOnLoad) {
      hljs.initLineNumbersOnLoad();
    }
  }
```

- [ ] **Step 5: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (105 + 1 = 106)

- [ ] **Step 6: Commit**

```bash
git add static/vendor/highlightjs/highlightjs-line-numbers.min.js \
  app/core/templates/core/base.html static/js/lab.js tests/test_vendored_assets.py
git commit -m "feat: add highlight.js line numbers to code panels"
```

---

### Task 4: Dark mode toggle

**Files:**
- Create: `static/vendor/highlightjs/github-dark.min.css` (vendored, not hand-written)
- Modify: `app/core/templates/core/base.html`
- Modify: `static/js/lab.js`
- Modify: `static/css/lab.css`
- Modify: `tests/test_vendored_assets.py`
- Test: `tests/test_core_views.py`

**Interfaces:**
- Consumes: nothing from earlier tasks in this plan (independent of tooltips/line-numbers).
- Produces: `window.__labTheme` (a global JS string, `"light"` or `"dark"`, set by the inline head script) and `toggleLabTheme()` (a global JS function). Neither is consumed by any later task in this plan — both are leaf-level, referenced here for completeness since they're new global JS surface.

- [ ] **Step 1: Vendor the dark theme stylesheet**

Fetch highlight.js's own official dark theme, pinned to the exact version already vendored in this project (11.9.0), from cdnjs:

```bash
curl -sL https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css \
  -o static/vendor/highlightjs/github-dark.min.css
```

Verify it downloaded correctly:

```bash
wc -c static/vendor/highlightjs/github-dark.min.css
head -c 150 static/vendor/highlightjs/github-dark.min.css
```

Expected: file size around 1.2–1.4 KB, and the content contains the text `Theme: GitHub Dark` near the start (confirms it's the real official dark theme file, not a 404 page).

- [ ] **Step 2: Write the failing tests**

Append to `tests/test_vendored_assets.py`:

```python
def test_github_dark_theme_is_vendored():
    path = STATIC_ROOT / "vendor" / "highlightjs" / "github-dark.min.css"
    assert path.exists(), f"expected vendored file at {path}"
    content = path.read_text()
    assert "Theme: GitHub Dark" in content
```

Append to `tests/test_core_views.py`:

```python
def test_home_page_includes_theme_toggle_button(client):
    response = client.get("/")
    assert response.status_code == 200
    assert 'id="theme-toggle"' in response.data.decode()


def test_html_tag_does_not_hardcode_light_theme(client):
    response = client.get("/")
    body = response.data.decode()
    assert 'data-bs-theme="light"' not in body
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_vendored_assets.py::test_github_dark_theme_is_vendored tests/test_core_views.py::test_home_page_includes_theme_toggle_button tests/test_core_views.py::test_html_tag_does_not_hardcode_light_theme -v`
Expected: `test_github_dark_theme_is_vendored` PASSes already (Step 1 vendored the file). `test_home_page_includes_theme_toggle_button` FAILs (no button yet). `test_html_tag_does_not_hardcode_light_theme` FAILs (the `<html>` tag still hardcodes it).

- [ ] **Step 4: Update the `<head>` — remove hardcoded theme, add the theme-detection script, tag the highlight.js stylesheet link**

In `app/core/templates/core/base.html`, the top of the file currently reads:

```html
<!doctype html>
<html lang="en" data-bs-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}OWASP Top 10 Training Lab{% endblock %}</title>
  <link rel="stylesheet" href="{{ url_for('static', filename='vendor/bootstrap/bootstrap.min.css') }}">
  <link rel="stylesheet" href="{{ url_for('static', filename='vendor/highlightjs/github.min.css') }}">
  <link rel="stylesheet" href="{{ url_for('static', filename='css/lab.css') }}">
</head>
```

Change it to:

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}OWASP Top 10 Training Lab{% endblock %}</title>
  <link rel="stylesheet" href="{{ url_for('static', filename='vendor/bootstrap/bootstrap.min.css') }}">
  <link rel="stylesheet" id="hljs-theme" href="{{ url_for('static', filename='vendor/highlightjs/github.min.css') }}">
  <link rel="stylesheet" href="{{ url_for('static', filename='css/lab.css') }}">
  <script>
    (function () {
      var stored = null;
      try {
        stored = localStorage.getItem("labTheme");
      } catch (e) {
        /* localStorage unavailable -- fall back to OS preference */
      }
      var theme = stored || (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
      document.documentElement.setAttribute("data-bs-theme", theme);
      window.__labTheme = theme;
      if (theme === "dark") {
        var hljsThemeLink = document.getElementById("hljs-theme");
        if (hljsThemeLink) {
          hljsThemeLink.setAttribute(
            "href",
            hljsThemeLink.getAttribute("href").replace("github.min.css", "github-dark.min.css")
          );
        }
      }
    })();
  </script>
</head>
```

- [ ] **Step 5: Add the toggle button to the right-hand nav cluster**

In `app/core/templates/core/base.html`, the right-hand nav cluster currently ends with:

```html
          <li class="nav-item"><a class="nav-link" href="{{ url_for('core.settings_page') }}">Settings</a></li>
        </ul>
```

Insert the toggle button immediately before that Settings `<li>`:

```html
          <li class="nav-item">
            <button type="button" id="theme-toggle" class="btn btn-outline-light btn-sm" onclick="toggleLabTheme()">🌓 Theme</button>
          </li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('core.settings_page') }}">Settings</a></li>
        </ul>
```

- [ ] **Step 6: Make Mermaid theme-aware and add the toggle handler**

In `static/js/lab.js`, the mermaid initialization currently reads:

```js
  if (window.mermaid) {
    mermaid.initialize({ startOnLoad: true, theme: "default" });
  }
```

Change it to:

```js
  if (window.mermaid) {
    mermaid.initialize({ startOnLoad: true, theme: window.__labTheme === "dark" ? "dark" : "default" });
  }
```

Add a new `toggleLabTheme()` function at the bottom of the file, alongside the existing `dismissLabBanner()`:

```js
function toggleLabTheme() {
  var current = document.documentElement.getAttribute("data-bs-theme") === "dark" ? "dark" : "light";
  var next = current === "dark" ? "light" : "dark";
  try {
    localStorage.setItem("labTheme", next);
  } catch (e) {
    /* localStorage unavailable -- theme choice won't persist across reloads */
  }
  location.reload();
}
```

- [ ] **Step 7: Add the dark-mode sidebar override**

Append to `static/css/lab.css`:

```css
[data-bs-theme="dark"] #sidebar {
  background-color: var(--bs-tertiary-bg) !important;
  border-color: var(--bs-border-color) !important;
}
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `pytest tests/test_vendored_assets.py tests/test_core_views.py -v`
Expected: all PASS, including the two new ones from Step 2.

- [ ] **Step 9: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (106 + 3 = 109)

- [ ] **Step 10: Commit**

```bash
git add static/vendor/highlightjs/github-dark.min.css app/core/templates/core/base.html \
  static/js/lab.js static/css/lab.css tests/test_vendored_assets.py tests/test_core_views.py
git commit -m "feat: add dark mode toggle"
```

---

### Task 5: Tools page

**Files:**
- Modify: `app/core/views.py`
- Create: `app/core/templates/core/tools.html`
- Modify: `app/core/templates/core/base.html`
- Test: `tests/test_core_views.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `core.tools_page` endpoint (used by the nav link this task also adds; not consumed elsewhere).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_core_views.py`:

```python
def test_tools_page_loads(client):
    response = client.get("/tools")
    assert response.status_code == 200
    body = response.data.decode()
    assert "sqlmap" in body
    assert "curl" in body
    assert 'href="https://curl.se/download.html"' in body
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_core_views.py::test_tools_page_loads -v`
Expected: FAIL with 404 (route doesn't exist yet).

- [ ] **Step 3: Add the route**

In `app/core/views.py`, the file currently ends with the `force_reset` route (added in a prior fix). Add the new route at the end of the file:

```python
@core_bp.route("/tools")
def tools_page():
    return render_template("core/tools.html")
```

- [ ] **Step 4: Create the template**

Create `app/core/templates/core/tools.html`:

```html
{% extends "core/base.html" %}
{% block title %}Tools{% endblock %}

{% block content %}
<h1>Tools</h1>
<p>
  You won't need every tool below for every exercise — most examples are fully
  exploitable from the browser alone. Where an exercise benefits from one of
  these, its Exploitation section calls it out by name.
</p>

<table class="table table-striped">
  <thead>
    <tr>
      <th>Tool</th>
      <th>What it's for</th>
      <th>Download</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Browser DevTools</td>
      <td>Inspect requests/responses, cookies, and page source — the starting point for almost every exercise.</td>
      <td>Built into Chrome, Firefox, Edge, and Safari — no download needed.</td>
    </tr>
    <tr>
      <td>curl</td>
      <td>Send crafted HTTP requests from the command line — essential for exploits that need custom headers, methods, or raw payloads.</td>
      <td><a href="https://curl.se/download.html">curl.se/download.html</a></td>
    </tr>
    <tr>
      <td>An intercepting proxy (Burp Suite Community or OWASP ZAP)</td>
      <td>Inspect and modify requests/responses in flight; replay and fuzz payloads.</td>
      <td>
        <a href="https://portswigger.net/burp/communitydownload">Burp Suite Community</a>
        /
        <a href="https://www.zaproxy.org/download/">OWASP ZAP</a>
      </td>
    </tr>
    <tr>
      <td>sqlmap</td>
      <td>Automates detecting and exploiting SQL injection — useful once you understand a vulnerability manually and want to see full automated exploitation.</td>
      <td><a href="https://github.com/sqlmapproject/sqlmap">github.com/sqlmapproject/sqlmap</a></td>
    </tr>
    <tr>
      <td>netcat / ncat</td>
      <td>Low-level TCP interaction — useful for command-injection exercises that involve reverse or bind shells.</td>
      <td><a href="https://nmap.org/ncat/">nmap.org/ncat</a></td>
    </tr>
    <tr>
      <td>Python 3</td>
      <td>Write short scripts to compute payloads (e.g. hashing a reset token offline) or automate an exploit.</td>
      <td><a href="https://www.python.org/downloads/">python.org/downloads</a></td>
    </tr>
    <tr>
      <td>A REST client (Postman or Insomnia)</td>
      <td>Build and save HTTP requests with a GUI, as an alternative to curl.</td>
      <td>
        <a href="https://www.postman.com/downloads/">Postman</a>
        /
        <a href="https://insomnia.rest/download">Insomnia</a>
      </td>
    </tr>
  </tbody>
</table>
{% endblock %}
```

- [ ] **Step 5: Add the nav link**

In `app/core/templates/core/base.html`, insert a Tools `<li>` immediately before the Settings `<li>` (which now already has the theme-toggle button directly before it from Task 4):

```html
          <li class="nav-item">
            <button type="button" id="theme-toggle" class="btn btn-outline-light btn-sm" onclick="toggleLabTheme()">🌓 Theme</button>
          </li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('core.tools_page') }}">Tools</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('core.settings_page') }}">Settings</a></li>
        </ul>
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `pytest tests/test_core_views.py::test_tools_page_loads -v`
Expected: PASS

- [ ] **Step 7: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (109 + 1 = 110)

- [ ] **Step 8: Commit**

```bash
git add app/core/views.py app/core/templates/core/tools.html \
  app/core/templates/core/base.html tests/test_core_views.py
git commit -m "feat: add Tools page"
```

---

### Task 6: About page

**Files:**
- Modify: `app/core/views.py`
- Create: `app/core/templates/core/about.html`
- Modify: `app/core/templates/core/base.html`
- Test: `tests/test_core_views.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `core.about_page` endpoint (used by the nav link this task also adds; not consumed elsewhere).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_core_views.py`:

```python
def test_about_page_loads(client):
    response = client.get("/about")
    assert response.status_code == 200
    body = response.data.decode()
    assert "WebGoat" in body
    assert "PostgreSQL" in body
    assert "127.0.0.1" in body
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_core_views.py::test_about_page_loads -v`
Expected: FAIL with 404.

- [ ] **Step 3: Add the route**

In `app/core/views.py`, add after the `tools_page` route added in Task 5:

```python
@core_bp.route("/about")
def about_page():
    return render_template("core/about.html")
```

- [ ] **Step 4: Create the template**

Create `app/core/templates/core/about.html`:

```html
{% extends "core/base.html" %}
{% block title %}About{% endblock %}

{% block content %}
<h1>About This Lab</h1>

<section class="mb-4">
  <h2>What This Is</h2>
  <p>
    A self-contained, intentionally vulnerable training lab teaching the OWASP
    Top 10 (2021) through working, exploitable examples — modeled after OWASP
    WebGoat, Juice Shop, and DVWA. The vulnerabilities are the deliverable:
    every example is a real, working exploit, not a simulation, so you can
    build a genuine feel for how these bugs are found and abused.
  </p>
</section>

<section class="mb-4">
  <h2>Infrastructure</h2>
  <p>
    Flask (Python) serves server-rendered Jinja2 templates styled with
    Bootstrap 5 (vendored locally, no CDN). Data is stored in PostgreSQL via
    SQLAlchemy. The whole stack is packaged with Docker and docker-compose,
    running as a non-root container.
  </p>
</section>

<section class="mb-4">
  <h2>Safety Model</h2>
  <p>
    The app binds only to <code>127.0.0.1</code> on the host — PostgreSQL
    publishes no host port at all. The container runs as a non-root user, and
    every account and data row is synthetic. If the app itself breaks, visit
    <code>/force-reset</code> directly to reset the database and clear your
    session without depending on any other part of the app working.
  </p>
</section>

<section>
  <h2>Why Hiding the Teaching Text Doesn't Disable the Bug</h2>
  <p>
    Settings lets you hide each example's Explanation and Exploitation text so
    you can attempt blind exploitation, the way a real attacker would
    encounter these bugs with no walkthrough at all. Hiding the teaching text
    never disables the underlying vulnerability — only the walkthrough.
  </p>
</section>
{% endblock %}
```

- [ ] **Step 5: Add the nav link**

In `app/core/templates/core/base.html`, insert an About `<li>` immediately before the Settings `<li>` (after the Tools `<li>` added in Task 5):

```html
          <li class="nav-item"><a class="nav-link" href="{{ url_for('core.tools_page') }}">Tools</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('core.about_page') }}">About</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('core.settings_page') }}">Settings</a></li>
        </ul>
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `pytest tests/test_core_views.py::test_about_page_loads -v`
Expected: PASS

- [ ] **Step 7: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (110 + 1 = 111)

- [ ] **Step 8: Commit**

```bash
git add app/core/views.py app/core/templates/core/about.html \
  app/core/templates/core/base.html tests/test_core_views.py
git commit -m "feat: add About page"
```

---

### Task 7: README update + Docker verification

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: nothing new (this task only verifies and documents Tasks 1–6's combined output).
- Produces: nothing — this is the final task.

- [ ] **Step 1: Update the README**

In `README.md`, the "Settings" section currently ends with:

```markdown
Both toggles are global and stored in the database — they affect every example page
immediately for every visitor. Hiding the teaching text never disables the underlying
vulnerability; it only conceals the walkthrough, so you can attempt exploitation blind.
```

Add a new section immediately after it:

```markdown

## More pages

- **Tools** (`/tools`) — what tools are useful for which kinds of exercises, with
  download links.
- **About** (`/about`) — what this app is, its infrastructure, and its safety model.
- A 🌓 **Theme** button in the top nav toggles dark mode; the choice is remembered
  per browser.
```

- [ ] **Step 2: Run the full suite one more time**

Run: `pytest tests/ -v`
Expected: all PASS (111 tests)

- [ ] **Step 3: Docker end-to-end + manual UI verification**

```bash
docker compose up --build -d
```

Then, in a browser at `http://127.0.0.1:5001`:

- Hover over each top-nav category (A01–A04) and confirm a tooltip with that
  category's blurb appears.
- Open any category's Overview page and confirm the Vulnerable/Secure code
  panels show line numbers down the left edge.
- Click the 🌓 Theme button and confirm the page reloads in dark mode (dark
  background, dark code panels, dark Mermaid diagram); click it again and
  confirm it reloads back to light mode. Reload the page without clicking the
  button and confirm the last-chosen theme persists.
- Visit `/tools` and `/about` via their top-nav links and confirm both render
  with the expected content.
- Visit `/force-reset` directly (still works from prior fix) and confirm it
  still resets cleanly with the new pages in place.

Tear down cleanly afterward:

```bash
docker compose down
```

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document Tools/About pages and dark mode in README"
```
