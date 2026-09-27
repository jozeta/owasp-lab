# CSRF, Directory Traversal, Encoding & File Inclusion Additions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 5 new intentionally-vulnerable examples to the OWASP Top 10 Training Lab — a broken-CSRF-token example and two Directory Traversal examples in A01, plus a Unicode-normalization XSS-bypass example and an LFI-to-SSTI example in A03 — bringing the app from 90 to 95 examples and max score from 1880 to 2010.

**Architecture:** All five examples are self-contained additions to their category's existing `routes.py`/`__init__.py`/`templates/`. No new SQLAlchemy models anywhere — the CSRF example reuses the existing `User.display_name` column and adds one session key; the two Directory Traversal examples and the File Inclusion example use only plain module-level path constants and files on disk; the Unicode-normalization example has no persistent state at all.

**Tech Stack:** Flask, Jinja2, Python's `unicodedata`/`os.path` standard-library modules, pytest with Flask's test client (no mocking).

**Spec:** `docs/superpowers/specs/2026-09-27-owasp-lab-csrf-traversal-encoding-file-inclusion-additions-design.md`

## Global Constraints

- No new SQLAlchemy models — plain module-level constants, files on disk, and Flask `session` state only.
- Every `ExampleNav.hints` list has 3-5 entries, each non-empty, no duplicates within the list.
- Within each category's `grouped_examples()` output, every group's examples must be sorted Easy → Medium → Hard.
- Hints render through Jinja's autoescaped `{{ hint }}` expression — write raw, unescaped `<`/`>`/`&` in hint text (Jinja escapes it automatically at render time). The six static template blocks (`explanation`/`detect`/`exploitation`/`tasks`/`vulnerable_code`/`secure_code`/`live_example`) are rendered UNESCAPED (raw HTML written directly in the template source) — any literal `<`/`>`/`&` that must appear as visible TEXT (not real markup) inside those blocks must be manually entity-encoded (`&lt;`/`&gt;`/`&amp;`).
- **The vulnerabilities ARE the deliverable.** Never add sanitization, escaping, validation, authentication, or path restrictions to any new vulnerable code path. The CSRF route must never compare the submitted token to the real session value. Neither Directory Traversal route may validate `name` in any way (the "filtered" one's filter must remain exactly the one narrow check specified — nothing broader). The Unicode-normalization route's filter must never be reordered relative to the normalization step. The File Inclusion routes must never validate the `name` parameter or avoid `render_template_string()`.
- New routes follow each category's existing plain `render_template()`/`redirect()`/`jsonify()` convention — no new abstraction layers.
- Every `ExampleNav.endpoint` must point at a route that renders an HTML explanation page (extending `core/example_page_base.html`, with the "mark as done" UI) — never directly at a raw action/download route. This app's nav-link/mark-as-done flow only works correctly when `endpoint` is the explanation page's own route.

---

### Task 1: A01 CSRF via Token Presence-Only Validation

**Files:**
- Modify: `app/categories/a01_access_control/routes.py` (add `import secrets` and `session` to the flask import line; append one new route at the end of the file)
- Modify: `app/categories/a01_access_control/__init__.py` (append new `ExampleNav` after the `csrf-email-change` entry — the current end of the examples list)
- Create: `app/categories/a01_access_control/templates/a01_access_control/change_display_name.html`
- Create: `tests/test_a01_csrf_broken_token.py`
- Modify: `tests/test_a01_hints.py`
- Modify: `tests/test_a01_overview.py`

**Interfaces:**
- Consumes: `get_current_user()`, `User.display_name` (existing column), `db.session` (all already imported/available). `session` (Flask's, not yet imported in this file — must be added).
- Produces: route `a01_access_control.change_display_name` (GET/POST), session key `a01_csrf_token`, `ExampleNav` id `csrf-token-presence-only` in A01's existing `"Cross-Site Request Forgery"` group.

- [ ] **Step 1: Read A01's current routes.py, __init__.py, and change_email.html fresh**

Before writing anything, read `app/categories/a01_access_control/routes.py` in full, `app/categories/a01_access_control/__init__.py` in full, `app/categories/a01_access_control/templates/a01_access_control/change_email.html` (for tone/style — the sibling CSRF example), and `tests/test_a01_csrf_email_change.py` (for this app's login-in-tests convention: `_login_as(client, user_id)` via `client.session_transaction()`, plus `seed_database(app)` for test data). If anything has changed from what's shown below, adapt accordingly — this plan is accurate as of repo tip `832f065`.

- [ ] **Step 2: Write the failing tests**

Create `tests/test_a01_csrf_broken_token.py`:

```python
from app.core.models import User
from app.core.seed import seed_database
from app.extensions import db


def _login_as(client, user_id):
    with client.session_transaction() as sess:
        sess["user_id"] = user_id


def test_change_display_name_page_renders_with_a_real_token(app, client):
    with app.app_context():
        seed_database(app)
        alice = User.query.filter_by(username="alice").first()
        user_id = alice.id
    _login_as(client, user_id)

    response = client.get("/a01/change-display-name")
    assert response.status_code == 200
    assert b"csrf_token" in response.data


def test_change_display_name_rejects_when_token_missing(app, client):
    with app.app_context():
        seed_database(app)
        alice = User.query.filter_by(username="alice").first()
        user_id = alice.id
    _login_as(client, user_id)

    client.get("/a01/change-display-name")  # establish the real session token
    response = client.post(
        "/a01/change-display-name",
        data={"display_name": "Attacker-Set-Name"},  # no csrf_token field at all
    )
    assert response.status_code == 200

    with app.app_context():
        alice = db.session.get(User, user_id)
        assert alice.display_name != "Attacker-Set-Name"


def test_change_display_name_succeeds_with_wrong_token_value(app, client):
    with app.app_context():
        seed_database(app)
        alice = User.query.filter_by(username="alice").first()
        user_id = alice.id
    _login_as(client, user_id)

    client.get("/a01/change-display-name")  # establish the REAL session token
    # Simulates an attacker's cross-site form: it can never know the real
    # per-session token, but this route only checks that SOME value was
    # submitted, not that it matches -- any non-empty string works.
    response = client.post(
        "/a01/change-display-name",
        data={
            "display_name": "Attacker-Set-Name",
            "csrf_token": "attacker-guessed-wrong-value",
        },
    )
    assert response.status_code == 200

    with app.app_context():
        alice = db.session.get(User, user_id)
        assert alice.display_name == "Attacker-Set-Name"
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_a01_csrf_broken_token.py -v`
Expected: FAIL — `404 NOT FOUND` for `/a01/change-display-name` (route doesn't exist yet).

- [ ] **Step 4: Add the vulnerable route**

At the top of `app/categories/a01_access_control/routes.py`, change:

```python
from flask import flash, jsonify, redirect, render_template, request, url_for
```

to:

```python
import secrets

from flask import flash, jsonify, redirect, render_template, request, session, url_for
```

Append this route to the end of the file (after the existing `password_change_api()`, which currently ends the file):

```python
@a01_bp.route("/change-display-name", methods=["GET", "POST"])
def change_display_name():
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=request.path))
    if "a01_csrf_token" not in session:
        session["a01_csrf_token"] = secrets.token_hex(16)
    changed = False
    if request.method == "POST":
        # VULNERABLE: a CSRF token IS required to be present in the
        # submitted form, but its VALUE is never compared against the
        # real per-session token stored above -- any non-empty string
        # satisfies this check, including one an attacker's cross-site
        # page could never actually know.
        submitted_token = request.form.get("csrf_token", "")
        if submitted_token:
            viewer.display_name = request.form.get("display_name", "")
            db.session.commit()
            changed = True
    return render_template(
        "a01_access_control/change_display_name.html",
        viewer=viewer,
        changed=changed,
        csrf_token=session["a01_csrf_token"],
    )
```

- [ ] **Step 5: Create the template**

Create `app/categories/a01_access_control/templates/a01_access_control/change_display_name.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "CSRF via Token Presence-Only Validation" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A01{% endblock %}

{% block explanation %}
<p>
  This "change your display name" form includes a hidden CSRF token
  field, generated fresh per session — it looks properly protected, and
  it IS checked on every submission. The problem is what "checked" means
  here: the server only verifies that a <code>csrf_token</code> value was
  submitted at all, never that it matches the real token issued to this
  session. Any non-empty string satisfies the check.
</p>
{% endblock %}

{% block detect %}
<p>
  View this page's source and note the hidden <code>csrf_token</code>
  field IS present, unlike the email-change example elsewhere in this
  category. Submit the form once normally to confirm it works, then try
  submitting with the token field present but set to an obviously wrong
  value.
</p>
{% endblock %}

{% block exploitation %}
<p>
  An attacker hosting a page on a completely different site has no way to
  read this session's real token — but they don't need to. Any
  non-empty string in the <code>csrf_token</code> field passes the
  server's check:
</p>
<pre><code class="language-html">&lt;form action="http://127.0.0.1:5001/a01/change-display-name" method="POST" id="f"&gt;
  &lt;input type="hidden" name="display_name" value="Pwned"&gt;
  &lt;input type="hidden" name="csrf_token" value="anything-at-all"&gt;
&lt;/form&gt;
&lt;script&gt;document.getElementById('f').submit();&lt;/script&gt;</code></pre>
<p>
  A logged-in victim who merely visits that attacker page has their
  display name changed, exactly as if this were the completely
  unprotected email-change form elsewhere in this category — the extra
  token field bought nothing, because "a token exists" and "the token is
  correct" are two entirely different checks, and this route only ever
  implements the first one.
</p>
{% endblock %}

{% block vulnerable_code %}if "a01_csrf_token" not in session:
    session["a01_csrf_token"] = secrets.token_hex(16)
if request.method == "POST":
    submitted_token = request.form.get("csrf_token", "")
    if submitted_token:  # only checks PRESENCE, never compares to session value
        viewer.display_name = request.form.get("display_name", "")
        db.session.commit()
{% endblock %}

{% block secure_code %}if "a01_csrf_token" not in session:
    session["a01_csrf_token"] = secrets.token_hex(16)
if request.method == "POST":
    submitted_token = request.form.get("csrf_token", "")
    if submitted_token == session["a01_csrf_token"]:  # compares the VALUE
        viewer.display_name = request.form.get("display_name", "")
        db.session.commit()
{% endblock %}

{% block live_example %}
{% if viewer %}
<p>Logged in as <strong>{{ viewer.username }}</strong> — current display name: <strong>{{ viewer.display_name }}</strong></p>
{% if changed %}
<div class="alert alert-success">Display name updated.</div>
{% endif %}
<form method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <div class="mb-2">
    <label class="form-label">New display name</label>
    <input type="text" class="form-control" name="display_name" placeholder="New Name">
  </div>
  <button type="submit" class="btn btn-primary">Update display name</button>
</form>
{% else %}
<a href="{{ url_for('core.switch_user', next=request.path) }}">Log in to try this example</a>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Register the ExampleNav entry**

In `app/categories/a01_access_control/__init__.py`, insert this new `ExampleNav` immediately after the `csrf-email-change` entry's closing `),` and before the list's closing `],` (this is the current last entry in the file):

```python
            ExampleNav(
                id="csrf-token-presence-only",
                title="CSRF via Token Presence-Only Validation",
                group="Cross-Site Request Forgery",
                difficulty="Medium",
                endpoint="a01_access_control.change_display_name",
                hints=[
                    "This form includes a hidden csrf_token field, unlike the email-change example elsewhere in this category. Before assuming it's safe, check exactly WHAT the server does with that field's value once submitted.",
                    "The route confirms a csrf_token value was submitted at all, but never compares it against the real per-session token this page issued. Submit the form with the token field present but set to an obviously wrong value, like 'wrong' -- does it still work?",
                    "An attacker's cross-site page can never read this session's real token, but it doesn't need to: any non-empty string in the csrf_token field passes the server's check. A hidden field alongside the real display_name field, auto-submitted from a completely different origin, changes the victim's display name exactly as easily as if there were no token check at all.",
                    "This is a common real-world CSRF-protection mistake: implementing 'does a token exist' instead of 'does the submitted token match the one this session was actually issued' -- the presence check makes the form LOOK protected in the page source without providing any actual protection.",
                ],
            ),
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_a01_csrf_broken_token.py -v`
Expected: PASS (all 3 tests).

- [ ] **Step 8: Update A01's cross-cutting test files**

In `tests/test_a01_hints.py`, change the example-count assertion from `5` to `6` (A01 currently has 5 examples — `idor`, `password-change-idor`, `admin-users`, `mass-assignment`, `csrf-email-change` — confirm this count against the file you actually read in Step 1 before changing it; the assertion likely reads `assert len(a01.examples) == 5`).

In `tests/test_a01_overview.py`, change `test_a01_registered_in_nav`'s difficulty-list assertion from:
```python
    assert [e.difficulty for e in a01.examples] == ["Easy", "Medium", "Medium", "Hard", "Medium"]
```
to:
```python
    assert [e.difficulty for e in a01.examples] == ["Easy", "Medium", "Medium", "Hard", "Medium", "Medium"]
```
This file has no per-group membership list assertions (unlike A03's `test_a03_overview.py`) — only the group-name list and a sortedness loop, both in `test_a01_examples_grouped_by_vulnerability_subtype`. Since `csrf-token-presence-only` joins the EXISTING `"Cross-Site Request Forgery"` group rather than creating a new one, the group-name list (lines 22-27) and the group-heading test (`test_a01_overview_shows_vulnerability_subtype_group_headings`) both need NO changes from this task.

- [ ] **Step 9: Run the full A01 test surface**

Run: `pytest tests/test_a01_csrf_broken_token.py tests/test_a01_hints.py tests/test_a01_overview.py tests/test_a01_account_update.py tests/test_a01_admin_users.py tests/test_a01_csrf_email_change.py tests/test_a01_idor.py tests/test_a01_password_change_idor.py -v`
Expected: PASS (all tests, no regressions in existing A01 examples).

- [ ] **Step 10: Commit**

```bash
git add app/categories/a01_access_control/routes.py \
        app/categories/a01_access_control/__init__.py \
        app/categories/a01_access_control/templates/a01_access_control/change_display_name.html \
        tests/test_a01_csrf_broken_token.py \
        tests/test_a01_hints.py \
        tests/test_a01_overview.py
git commit -m "feat(a01): add CSRF via Token Presence-Only Validation example"
```

---

### Task 2: A01 Directory Traversal (2 examples, new "Path Traversal" group)

**Files:**
- Modify: `app/categories/a01_access_control/routes.py` (add `import os`, `from app import BASE_DIR`, two new constants, one helper function, and two new routes at the end of the file)
- Modify: `app/categories/a01_access_control/__init__.py` (append two new `ExampleNav` entries after Task 1's `csrf-token-presence-only` entry — the new end of the examples list once Task 1 has landed)
- Create: `app/categories/a01_access_control/templates/a01_access_control/download_document.html`
- Create: `app/categories/a01_access_control/templates/a01_access_control/download_document_filtered.html`
- Create: `tests/test_a01_directory_traversal.py`
- Modify: `tests/test_a01_hints.py`
- Modify: `tests/test_a01_overview.py`

**Interfaces:**
- Consumes: nothing from Task 1 directly (different feature entirely), but appends to the same two files Task 1 already modified — re-read both fresh (see Orchestration Note below).
- Produces: routes `a01_access_control.download_document` and `a01_access_control.download_document_filtered` (both GET-only, no login required — this vulnerability class doesn't depend on authorization). Module-level constant `DOCUMENTS_DIR`. `ExampleNav` ids `arbitrary-file-read` and `path-traversal-filter-bypass`, both in a brand-new `"Path Traversal"` group.

## Orchestration Note (read before starting Task 2)

Task 1 already modified `app/categories/a01_access_control/routes.py` (added `import secrets`, added `session` to the flask import, appended `change_display_name()`) and `app/categories/a01_access_control/__init__.py` (appended the `csrf-token-presence-only` entry at the very end of the examples list). Task 2's insertions don't physically overlap with Task 1's — Task 2 adds its own constants near wherever `os`/`BASE_DIR` imports should go (check if `os` is already imported; it is not, as of this plan's writing) and appends its two new routes at the very end of `routes.py` (after Task 1's `change_display_name()`), and its two new `ExampleNav` entries go at the very end of `__init__.py`'s list (after Task 1's `csrf-token-presence-only` entry, which will itself be the last entry once Task 1 has landed). **Re-read both files fresh before editing** — don't assume line numbers from this plan still match exactly.

**The fully-composed final A01 example order, after both Task 1 and Task 2 have landed:**

| # | id | group | difficulty |
|---|---|---|---|
| 1 | idor | Insecure Direct Object References (IDOR) | Easy |
| 2 | password-change-idor | Insecure Direct Object References (IDOR) | Medium |
| 3 | admin-users | Missing Function-Level Access Control | Medium |
| 4 | mass-assignment | Mass Assignment | Hard |
| 5 | csrf-email-change | Cross-Site Request Forgery | Medium |
| 6 | csrf-token-presence-only (Task 1) | Cross-Site Request Forgery | Medium |
| 7 | arbitrary-file-read (Task 2) | Path Traversal | Medium |
| 8 | path-traversal-filter-bypass (Task 2) | Path Traversal | Hard |

Final groups (5 total, first-occurrence order): Insecure Direct Object References (IDOR), Missing Function-Level Access Control, Mass Assignment, Cross-Site Request Forgery (now 2 members), Path Traversal (2 members).

Full difficulty list (8 entries): `Easy, Medium, Medium, Hard, Medium, Medium, Medium, Hard`

- [ ] **Step 1: Read A01's current routes.py and __init__.py fresh (after Task 1 has landed)**

Read both files in full to confirm Task 1's changes are present and locate the exact end of each file (the insertion points for this task).

- [ ] **Step 2: Write the failing tests**

Create `tests/test_a01_directory_traversal.py`:

```python
def test_download_document_returns_legitimate_content(client):
    response = client.get("/a01/download-document?name=welcome.txt")
    assert response.status_code == 200
    assert b"Welcome to the OWASP Lab document center" in response.data


def test_download_document_reads_arbitrary_file_via_relative_traversal(client):
    response = client.get("/a01/download-document?name=" + "../" * 20 + "etc/passwd")
    assert response.status_code == 200
    assert b"root:" in response.data


def test_download_document_reads_arbitrary_file_via_absolute_path(client):
    response = client.get("/a01/download-document", query_string={"name": "/etc/passwd"})
    assert response.status_code == 200
    assert b"root:" in response.data


def test_download_document_filtered_blocks_relative_traversal(client):
    response = client.get(
        "/a01/download-document-filtered?name=" + "../" * 20 + "etc/passwd"
    )
    assert response.status_code == 200
    assert b"Blocked" in response.data
    assert b"root:" not in response.data


def test_download_document_filtered_bypassed_via_absolute_path(client):
    response = client.get(
        "/a01/download-document-filtered", query_string={"name": "/etc/passwd"}
    )
    assert response.status_code == 200
    assert b"root:" in response.data
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_a01_directory_traversal.py -v`
Expected: FAIL — `404 NOT FOUND` for both routes (neither exists yet).

- [ ] **Step 4: Add imports, constants, and the two vulnerable routes**

At the top of `app/categories/a01_access_control/routes.py`, add `import os` and `from app import BASE_DIR` (place them following this file's existing import ordering — standard library first, then third-party, then local — matching the convention already visible in A03's `routes.py`).

Add this constant and helper function (near the top, after the imports):

```python
DOCUMENTS_DIR = os.path.join(BASE_DIR, "instance", "a01_documents")


def _ensure_seed_document():
    os.makedirs(DOCUMENTS_DIR, exist_ok=True)
    welcome_path = os.path.join(DOCUMENTS_DIR, "welcome.txt")
    if not os.path.exists(welcome_path):
        with open(welcome_path, "w") as f:
            f.write("Welcome to the OWASP Lab document center!\n")
```

Append these two routes to the end of the file (after Task 1's `change_display_name()`, which will then be the file's last function):

```python
@a01_bp.route("/download-document")
def download_document():
    _ensure_seed_document()
    name = request.args.get("name", "welcome.txt")
    content = None
    error = None
    # VULNERABLE: os.path.join() silently discards DOCUMENTS_DIR entirely
    # if `name` is an absolute path, and a relative "../../../" climbs
    # straight out of this directory just as easily -- there is no
    # check of any kind on `name` here.
    path = os.path.join(DOCUMENTS_DIR, name)
    try:
        with open(path) as f:
            content = f.read()
    except OSError as e:
        error = str(e)
    return render_template(
        "a01_access_control/download_document.html", name=name, content=content, error=error
    )


@a01_bp.route("/download-document-filtered")
def download_document_filtered():
    _ensure_seed_document()
    name = request.args.get("name", "welcome.txt")
    content = None
    error = None
    blocked = ".." in name
    if not blocked:
        # VULNERABLE: this filter only ever checks for the substring
        # "..", never considering that os.path.join() discards
        # DOCUMENTS_DIR entirely when `name` is an absolute path -- an
        # absolute path contains no ".." at all and sails straight
        # through this check.
        path = os.path.join(DOCUMENTS_DIR, name)
        try:
            with open(path) as f:
                content = f.read()
        except OSError as e:
            error = str(e)
    return render_template(
        "a01_access_control/download_document_filtered.html",
        name=name,
        content=content,
        error=error,
        blocked=blocked,
    )
```

- [ ] **Step 5: Create the two templates**

Create `app/categories/a01_access_control/templates/a01_access_control/download_document.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Arbitrary File Read via Document Download" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A01{% endblock %}

{% block explanation %}
<p>
  This "document center" lets you download a file by name from a
  shared documents folder. The name you provide is joined directly onto
  that folder's path with no validation of any kind — Python's
  <code>os.path.join()</code> is not a safety mechanism: if the second
  argument is an absolute path, it discards the first argument entirely,
  and a relative <code>../</code> sequence climbs out of the intended
  folder just as easily as it would in any other language.
</p>
{% endblock %}

{% block detect %}
<p>
  Fetch <code>?name=welcome.txt</code> and note the legitimate content.
  Then try <code>?name=/etc/passwd</code> — no <code>../</code> at all,
  just a bare absolute path.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Two independent techniques both work here, since neither the intended
  folder restriction nor <code>os.path.join()</code>'s own behavior stop
  either one:
</p>
<ol>
  <li>Classic relative traversal: <code>?name=../../../../../../etc/passwd</code>
      climbs out of the documents folder one directory at a time.</li>
  <li><code>os.path.join()</code>'s absolute-path override: <code>?name=/etc/passwd</code> —
      when the second argument to <code>os.path.join()</code> is an
      absolute path, Python discards the first argument entirely and
      returns just the absolute path, no traversal sequence required at
      all.</li>
</ol>
<p>
  Either payload returns the real contents of <code>/etc/passwd</code> —
  a file completely outside the intended documents folder, disclosed
  with no access control of any kind.
</p>
{% endblock %}

{% block vulnerable_code %}name = request.args.get("name", "welcome.txt")
path = os.path.join(DOCUMENTS_DIR, name)
with open(path) as f:
    content = f.read()
{% endblock %}

{% block secure_code %}name = request.args.get("name", "welcome.txt")
# Resolve to a real path and confirm it's genuinely inside DOCUMENTS_DIR
# before ever opening it -- rejects both absolute paths and "../" climbs
candidate = os.path.realpath(os.path.join(DOCUMENTS_DIR, name))
if not candidate.startswith(os.path.realpath(DOCUMENTS_DIR) + os.sep):
    abort(403)
with open(candidate) as f:
    content = f.read()
{% endblock %}

{% block live_example %}
<form method="get" class="mb-3">
  <div class="mb-2">
    <label class="form-label">Document name</label>
    <input type="text" class="form-control" name="name" value="{{ name }}">
  </div>
  <button type="submit" class="btn btn-primary">Download</button>
</form>
{% if content %}
<pre>{{ content }}</pre>
{% endif %}
{% if error %}
<p class="text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

Create `app/categories/a01_access_control/templates/a01_access_control/download_document_filtered.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Path Traversal Filter Bypass via Absolute Path" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A01{% endblock %}

{% block explanation %}
<p>
  This version of the document download feature adds a filter: any
  <code>name</code> containing the substring <code>".."</code> is
  rejected outright before the file is ever opened. This genuinely
  blocks the classic relative-traversal technique from the sibling
  "Arbitrary File Read" example in this same group.
</p>
{% endblock %}

{% block detect %}
<p>
  Confirm the filter works: try <code>?name=../../../../etc/passwd</code>
  — blocked. Now think about the OTHER technique from that sibling
  example — does it contain the substring <code>".."</code> anywhere
  at all?
</p>
{% endblock %}

{% block exploitation %}
<p>
  The filter only ever checks for the literal substring <code>".."</code>.
  It never considers that <code>os.path.join()</code>'s absolute-path
  override doesn't involve <code>".."</code> in any form: submit
  <code>?name=/etc/passwd</code> — a bare absolute path, containing zero
  dots or slashes-in-sequence that the filter is looking for. It sails
  through the check untouched and reaches the exact same unguarded
  <code>open()</code> call as the unfiltered sibling example.
</p>
<p>
  Blacklist filters that enumerate "the obvious" attack shape are a
  recurring, genuinely dangerous real-world pattern throughout this lab
  (the newline-bypass in this app's command-injection filter example is
  the same story) — a filter has to anticipate every equivalent way to
  achieve the same outcome, not just the first one that comes to mind.
</p>
{% endblock %}

{% block vulnerable_code %}name = request.args.get("name", "welcome.txt")
if ".." in name:
    blocked = True
else:
    path = os.path.join(DOCUMENTS_DIR, name)  # still no absolute-path check
    with open(path) as f:
        content = f.read()
{% endblock %}

{% block secure_code %}name = request.args.get("name", "welcome.txt")
candidate = os.path.realpath(os.path.join(DOCUMENTS_DIR, name))
if not candidate.startswith(os.path.realpath(DOCUMENTS_DIR) + os.sep):
    abort(403)
with open(candidate) as f:
    content = f.read()
{% endblock %}

{% block live_example %}
<form method="get" class="mb-3">
  <div class="mb-2">
    <label class="form-label">Document name</label>
    <input type="text" class="form-control" name="name" value="{{ name }}">
  </div>
  <button type="submit" class="btn btn-primary">Download</button>
</form>
{% if blocked %}
<p class="text-danger">Blocked: filename contains a disallowed sequence.</p>
{% endif %}
{% if content %}
<pre>{{ content }}</pre>
{% endif %}
{% if error %}
<p class="text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Register both ExampleNav entries**

In `app/categories/a01_access_control/__init__.py`, insert these two new `ExampleNav` entries immediately after Task 1's `csrf-token-presence-only` entry's closing `),` and before the list's closing `],`:

```python
            ExampleNav(
                id="arbitrary-file-read",
                title="Arbitrary File Read via Document Download",
                group="Path Traversal",
                difficulty="Medium",
                endpoint="a01_access_control.download_document",
                hints=[
                    "This 'document center' downloads a file by name from a shared folder. Look at how the name you provide gets combined with that folder's path -- is there any check at all on what the name can contain?",
                    "The server builds the path with os.path.join(DOCUMENTS_DIR, name) and opens it directly. Try a name containing several ../ sequences to climb out of the documents folder -- e.g. ?name=../../../../../../etc/passwd.",
                    "There's an even simpler technique specific to Python: os.path.join() discards its FIRST argument entirely if the second argument is an absolute path. Try ?name=/etc/passwd -- no ../ needed at all, and the real contents of /etc/passwd come back.",
                ],
            ),
            ExampleNav(
                id="path-traversal-filter-bypass",
                title="Path Traversal Filter Bypass via Absolute Path",
                group="Path Traversal",
                difficulty="Hard",
                endpoint="a01_access_control.download_document_filtered",
                hints=[
                    "This version blocks any name containing the substring '..' before opening the file. Confirm it: try the same ../../../etc/passwd payload that worked on the sibling 'Arbitrary File Read' example in this group -- it's rejected here.",
                    "The filter only ever looks for '..'. Think back to the OTHER technique from that sibling example -- does a bare absolute path contain that substring anywhere at all?",
                    "Submit ?name=/etc/passwd -- zero dots-in-sequence for the filter to catch, so it sails straight through untouched and reaches the exact same unguarded open() call as the unfiltered example.",
                    "This is the same class of mistake as this lab's command-injection filter-bypass example: a blacklist that enumerates 'the obvious' attack shape has to anticipate every equivalent way to reach the same outcome, not just the first one its author thought of.",
                ],
            ),
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_a01_directory_traversal.py -v`
Expected: PASS (all 5 tests).

- [ ] **Step 8: Update A01's cross-cutting test files**

In `tests/test_a01_hints.py`, change the example-count assertion from `6` (after Task 1) to `8` (Task 2 adds 2 examples at once — `arbitrary-file-read` and `path-traversal-filter-bypass` — not 1).

In `tests/test_a01_overview.py`:

Change `test_a01_registered_in_nav`'s difficulty-list assertion (which Task 1 already updated to 6 entries) to the full 8-entry list:
```python
    assert [e.difficulty for e in a01.examples] == [
        "Easy",
        "Medium",
        "Medium",
        "Hard",
        "Medium",
        "Medium",
        "Medium",
        "Hard",
    ]
```

Change `test_a01_examples_grouped_by_vulnerability_subtype`'s group-name list to append the new group:
```python
    assert [name for name, _ in grouped] == [
        "Insecure Direct Object References (IDOR)",
        "Missing Function-Level Access Control",
        "Mass Assignment",
        "Cross-Site Request Forgery",
        "Path Traversal",
    ]
```
(the sortedness loop immediately below this assertion needs no change — it already iterates every group generically)

Change `test_a01_overview_shows_vulnerability_subtype_group_headings` to add one more assertion:
```python
    assert "Path Traversal" in body
```

- [ ] **Step 9: Run the full A01 test surface**

Run: `pytest tests/test_a01_directory_traversal.py tests/test_a01_csrf_broken_token.py tests/test_a01_hints.py tests/test_a01_overview.py tests/test_a01_account_update.py tests/test_a01_admin_users.py tests/test_a01_csrf_email_change.py tests/test_a01_idor.py tests/test_a01_password_change_idor.py -v`
Expected: PASS (all tests, no regressions).

- [ ] **Step 10: Commit**

```bash
git add app/categories/a01_access_control/routes.py \
        app/categories/a01_access_control/__init__.py \
        app/categories/a01_access_control/templates/a01_access_control/download_document.html \
        app/categories/a01_access_control/templates/a01_access_control/download_document_filtered.html \
        tests/test_a01_directory_traversal.py \
        tests/test_a01_hints.py \
        tests/test_a01_overview.py
git commit -m "feat(a01): add Directory Traversal examples (arbitrary read + filter bypass)"
```

---

### Task 3: A03 Unicode Normalization Filter Bypass (XSS)

**Files:**
- Modify: `app/categories/a03_injection/routes.py` (add `import unicodedata`; append one new route at the end of the file)
- Modify: `app/categories/a03_injection/__init__.py` (insert new `ExampleNav` immediately after the existing `filter-challenge` entry — the last member of the "Cross-Site Scripting (XSS)" group)
- Create: `app/categories/a03_injection/templates/a03_injection/feedback.html`
- Create: `tests/test_a03_unicode_normalization_xss.py`
- Modify: `tests/test_a03_hints_remaining_groups.py`
- Modify: `tests/test_a03_overview.py`

**Interfaces:**
- Consumes: `render_template`, `request` (already imported).
- Produces: route `a03_injection.feedback` (GET/POST). `ExampleNav` id `unicode-normalization-xss-bypass`, inserted as the 4th member of the EXISTING "Cross-Site Scripting (XSS)" group.

## Orchestration Note (read before starting Task 3)

Task 3 and Task 4 both modify `app/categories/a03_injection/routes.py` and `app/categories/a03_injection/__init__.py`, sequentially, on top of round 4's already-landed state (repo tip `832f065` as of this plan's writing, but Tasks 1/2 above landed on top of that on A01's files only — A03 is untouched by Tasks 1/2). Task 3's `ExampleNav` insertion point (inside the existing XSS group, near the TOP of the examples list) does not physically overlap with Task 4's insertion point (a brand-new group at the very END of the list) — but **re-read both files fresh before editing either task**, since exact line numbers may have shifted.

**The fully-composed final A03 example order, after both Task 3 and Task 4 have landed:**

| # | id | group | difficulty |
|---|---|---|---|
| 1-7 | (SQL Injection group, unchanged) | SQL Injection | E,M,M,M,H,H,H |
| 8 | reflected-xss | Cross-Site Scripting (XSS) | Medium |
| 9 | stored-xss | Cross-Site Scripting (XSS) | Hard |
| 10 | filter-challenge | Cross-Site Scripting (XSS) | Hard |
| 11 | **unicode-normalization-xss-bypass** (Task 3) | Cross-Site Scripting (XSS) | **Hard** |
| 12-15 | (OS Command Injection group, unchanged) | OS Command Injection | M,H,H,H |
| 16-17 | (XXE group, unchanged) | XML External Entity Injection (XXE) | E,H |
| 18-19 | (SSTI group, unchanged) | Server-Side Template Injection (SSTI) | E,H |
| 20-21 | (LDAP Injection group, unchanged) | LDAP Injection | E,H |
| 22 | css-attribute-exfil | CSS Injection | Hard |
| 23 | csv-formula-injection | CSV Injection | Medium |
| 24 | **file-inclusion-lfi-ssti** (Task 4) | **File Inclusion** | **Hard** |

Final groups (9 total, first-occurrence order): SQL Injection, Cross-Site Scripting (XSS) (now 4 members), OS Command Injection, XML External Entity Injection (XXE), Server-Side Template Injection (SSTI), LDAP Injection, CSS Injection, CSV Injection, File Inclusion.

Full difficulty list (24 entries): `Easy, Medium, Medium, Medium, Hard, Hard, Hard, Medium, Hard, Hard, Hard, Medium, Hard, Hard, Hard, Easy, Hard, Easy, Hard, Easy, Hard, Hard, Medium, Hard`

- [ ] **Step 1: Read A03's current routes.py and __init__.py fresh, and reflected_xss/filter_challenge templates for tone**

Read both files in full to locate the `filter-challenge` `ExampleNav` entry (Task 3's insertion point is immediately after it) and the end of `routes.py` (this task's route insertion point). Also read `app/categories/a03_injection/templates/a03_injection/filter_challenge.html` for entity-encoding tone reference.

- [ ] **Step 2: Write the failing tests**

Create `tests/test_a03_unicode_normalization_xss.py`:

```python
def test_feedback_page_renders(client):
    response = client.get("/a03/feedback")
    assert response.status_code == 200


def test_literal_script_tag_is_blocked(client):
    payload = "<script>alert(1)</script>"
    response = client.post("/a03/feedback", data={"feedback": payload})
    assert response.status_code == 200
    assert b"Blocked" in response.data
    assert b"<script>alert(1)</script>" not in response.data


def test_fullwidth_lookalike_bypasses_filter_and_normalizes_to_real_script_tag(client):
    payload = "＜script＞alert(document.domain)＜/script＞"
    response = client.post("/a03/feedback", data={"feedback": payload})
    assert response.status_code == 200
    assert b"Blocked" not in response.data
    assert b"<script>alert(document.domain)</script>" in response.data
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_a03_unicode_normalization_xss.py -v`
Expected: FAIL — `404 NOT FOUND` for `/a03/feedback` (route doesn't exist yet).

- [ ] **Step 4: Add the vulnerable route**

Add `import unicodedata` to the top of `app/categories/a03_injection/routes.py` (alongside the existing `import csv`/`import io`/`import os`/`import re`/`import subprocess`/`import urllib.request`, keeping alphabetical order: `unicodedata` sorts after `subprocess` and before `urllib.request`).

Append this route to the end of the file (after the current last function — check what that is once Tasks 1/2 have landed, since those only touched A01; the current A03 last function as of this plan's writing is `export_archive()`):

```python
@a03_bp.route("/feedback", methods=["GET", "POST"])
def feedback():
    raw_feedback = ""
    blocked = False
    normalized = None
    if request.method == "POST":
        raw_feedback = request.form.get("feedback", "")
        if "<script" in raw_feedback.lower():
            blocked = True
        else:
            # VULNERABLE: this normalization step exists to make display
            # text consistent (e.g. collapsing fullwidth punctuation a
            # user might paste in from a CJK input method) -- but it
            # runs AFTER the filter above already approved the raw
            # string, and NFKC normalization converts fullwidth
            # lookalike characters into their literal ASCII equivalents,
            # resurrecting exactly what the filter tried to block.
            normalized = unicodedata.normalize("NFKC", raw_feedback)
    return render_template(
        "a03_injection/feedback.html",
        raw_feedback=raw_feedback,
        blocked=blocked,
        normalized=normalized,
    )
```

- [ ] **Step 5: Create the template**

Create `app/categories/a03_injection/templates/a03_injection/feedback.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Unicode Normalization Filter Bypass (XSS)" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This feedback form blocks any submission containing the literal
  substring <code>&lt;script</code> before doing anything else with it —
  a real, working filter against the obvious payload. But once a
  submission passes that check, the app calls Python's
  <code>unicodedata.normalize("NFKC", ...)</code> on the text before
  rendering it, framed as a display-consistency step (collapsing
  fullwidth punctuation someone might paste in from a CJK input method).
  That normalization step runs entirely AFTER the filter has already
  approved the raw string.
</p>
{% endblock %}

{% block detect %}
<p>
  Confirm the filter works: submit the literal text
  <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> — blocked. Then try
  the exact same tag, but typed using Unicode FULLWIDTH angle brackets
  (U+FF1C <code>＜</code> and U+FF1E <code>＞</code>) instead of the
  ordinary ASCII ones.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Submit this as your feedback (using fullwidth angle brackets, not
  ordinary ones):
</p>
<pre>＜script＞alert(document.domain)＜/script＞</pre>
<p>
  The literal-substring filter finds no <code>&lt;script</code> anywhere
  in this raw input — there isn't a single ordinary <code>&lt;</code>
  character in it — so it passes straight through. The app then runs the
  approved text through <code>unicodedata.normalize("NFKC", ...)</code>,
  which converts each fullwidth lookalike character into its literal
  ASCII equivalent: <code>＜</code> becomes <code>&lt;</code> and
  <code>＞</code> becomes <code>&gt;</code>. What gets rendered — and
  executed — is a real, ordinary <code>&lt;script&gt;</code> tag, entirely
  reconstructed by a step the filter never knew was coming.
</p>
<p>
  This is exactly why filtering untrusted input and normalizing it are
  two operations that must happen in a fixed, deliberate order — any
  normalization, decoding, or unescaping step performed AFTER a security
  check can resurrect whatever that check was trying to block, no matter
  how thorough the check itself is against the input it actually saw.
</p>
{% endblock %}

{% block vulnerable_code %}raw_feedback = request.form.get("feedback", "")
if "&lt;script" in raw_feedback.lower():
    blocked = True
else:
    normalized = unicodedata.normalize("NFKC", raw_feedback)
# template: {% raw %}{{ normalized|safe }}{% endraw %}
{% endblock %}

{% block secure_code %}raw_feedback = request.form.get("feedback", "")
# Normalize FIRST, then filter the normalized result -- so the filter
# always sees the same text that will actually be rendered:
normalized = unicodedata.normalize("NFKC", raw_feedback)
if "&lt;script" in normalized.lower():
    blocked = True
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Your feedback</label>
    <textarea class="form-control" name="feedback" rows="3">{{ raw_feedback }}</textarea>
  </div>
  <button type="submit" class="btn btn-primary">Submit feedback</button>
</form>
{% if blocked %}
<p class="text-danger mt-3">Blocked: feedback contains a disallowed tag.</p>
{% endif %}
{% if normalized %}
<p class="mt-3 mb-1">Rendered feedback:</p>
<div class="border rounded p-2">{{ normalized | safe }}</div>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Register the ExampleNav entry**

In `app/categories/a03_injection/__init__.py`, insert this new `ExampleNav` immediately after the `filter-challenge` entry's closing `),` and before the `filtered-host-lookup` entry (the current first member of the "OS Command Injection" group):

```python
            ExampleNav(
                id="unicode-normalization-xss-bypass",
                title="Unicode Normalization Filter Bypass (XSS)",
                group="Cross-Site Scripting (XSS)",
                difficulty="Hard",
                endpoint="a03_injection.feedback",
                hints=[
                    "This feedback form genuinely blocks the literal substring '<script' before doing anything else. Confirm that first, then think about what happens to your text AFTER the filter approves it -- is it rendered exactly as submitted, or does something transform it first?",
                    "The app calls Python's unicodedata.normalize(\"NFKC\", ...) on approved text before rendering it, meant to tidy up fullwidth punctuation someone might paste in. NFKC normalization converts many 'compatibility' Unicode characters into their ordinary ASCII equivalents -- including fullwidth angle brackets.",
                    "Submit your feedback using the FULLWIDTH Unicode angle brackets U+FF1C (＜) and U+FF1E (＞) instead of ordinary '<'/'>': ＜script＞alert(document.domain)＜/script＞. The literal-substring filter finds no ordinary '<script' anywhere in this text and lets it straight through.",
                    "The normalization step that runs afterward converts each fullwidth character into its literal ASCII equivalent -- ＜ becomes < and ＞ becomes > -- reconstructing a real <script> tag from text the filter never recognized as dangerous, and it executes exactly as if you'd typed it in plain ASCII.",
                ],
            ),
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_a03_unicode_normalization_xss.py -v`
Expected: PASS (all 3 tests).

- [ ] **Step 8: Update A03's cross-cutting test files**

In `tests/test_a03_hints_remaining_groups.py`, add `"unicode-normalization-xss-bypass"` to `REMAINING_GROUP_IDS` — insert it right after `"filter-challenge"` (matching its position in `__init__.py`):

```python
REMAINING_GROUP_IDS = [
    "reflected-xss",
    "stored-xss",
    "filter-challenge",
    "unicode-normalization-xss-bypass",
    "filtered-host-lookup",
    "command-injection",
    "blind-report-injection",
    "argument-injection-tar-export",
    "xml-import",
    "xxe-ssrf",
    "ssti-email-preview",
    "ssti-blacklist-bypass",
    "ldap-directory-login",
    "ldap-directory-search",
    "css-attribute-exfil",
    "csv-formula-injection",
]
```

**Important:** at this point in the plan, only Task 3's example has landed in A03 — Task 4 (File Inclusion) has NOT landed yet, so A03 has 23 examples, not the 24 shown in the Orchestration Note's fully-composed table (that table shows the state after BOTH Task 3 and Task 4). Update `tests/test_a03_overview.py` to this 23-entry intermediate state:

```python
    assert [e.difficulty for e in a03.examples] == [
        "Easy",
        "Medium",
        "Medium",
        "Medium",
        "Hard",
        "Hard",
        "Hard",
        "Medium",
        "Hard",
        "Hard",
        "Hard",
        "Medium",
        "Hard",
        "Hard",
        "Hard",
        "Easy",
        "Hard",
        "Easy",
        "Hard",
        "Easy",
        "Hard",
        "Hard",
        "Medium",
    ]
```

```python
    assert [e.id for e in grouped[1][1]] == [
        "reflected-xss",
        "stored-xss",
        "filter-challenge",
        "unicode-normalization-xss-bypass",
    ]
```

The group-name list itself still ends with `"CSV Injection"` as the 8th and final group at this point (`grouped[7][1] == ["csv-formula-injection"]`, already correct in the file and unchanged by this task) — do NOT add a `"File Inclusion"` group or a `grouped[8]` assertion yet; Task 4 does that.

(the group-name list itself and every other group's membership assertion need no further change from this task — `grouped[0][1]` and `grouped[2][1]` through `grouped[7][1]` are untouched by Task 3; Task 4 below adds `grouped[8][1]`)

- [ ] **Step 9: Run the full A03 test surface**

Run: `pytest tests/test_a03_unicode_normalization_xss.py tests/test_a03_csv_injection.py tests/test_a03_argument_injection.py tests/test_a03_hints_remaining_groups.py tests/test_a03_hints_sqli_group.py tests/test_a03_overview.py -v`
Expected: PASS (all tests, no regressions).

- [ ] **Step 10: Commit**

```bash
git add app/categories/a03_injection/routes.py \
        app/categories/a03_injection/__init__.py \
        app/categories/a03_injection/templates/a03_injection/feedback.html \
        tests/test_a03_unicode_normalization_xss.py \
        tests/test_a03_hints_remaining_groups.py \
        tests/test_a03_overview.py
git commit -m "feat(a03): add Unicode Normalization Filter Bypass (XSS) example"
```

---

### Task 4: A03 File Inclusion (LFI-to-SSTI via Unsanitized Snippet Include, new "File Inclusion" group)

**Files:**
- Modify: `app/categories/a03_injection/routes.py` (add two new constants near the top; append three new routes at the end of the file)
- Modify: `app/categories/a03_injection/__init__.py` (append new `ExampleNav` at the very end of the examples list — the new end once Task 3 has landed)
- Create: `app/categories/a03_injection/file_inclusion_secret.txt` (a static secret file, matching the existing `xxe_secret.txt`/`cmd_secret.txt` precedent)
- Create: `app/categories/a03_injection/templates/a03_injection/file_inclusion.html`
- Create: `app/categories/a03_injection/templates/a03_injection/render_snippet.html`
- Create: `tests/test_a03_file_inclusion.py`
- Modify: `tests/test_a03_hints_remaining_groups.py`
- Modify: `tests/test_a03_overview.py`

**Interfaces:**
- Consumes: `render_template`, `render_template_string`, `redirect`, `url_for`, `request` (already imported).
- Produces: routes `a03_injection.file_inclusion` (GET, the six-block explanation page), `a03_injection.save_snippet` (POST, action route), `a03_injection.render_snippet` (GET, the actual vulnerable read+render action). Module-level constants `FILE_INCLUSION_SECRET_PATH` and `SNIPPETS_DIR`. `ExampleNav` id `file-inclusion-lfi-ssti`, new group `"File Inclusion"` at the very end of A03's list.

- [ ] **Step 1: Read A03's current routes.py and __init__.py fresh (after Task 3 has landed), and email_preview.html/xml_import.html for reuse reference**

Read both files in full. Also read `app/categories/a03_injection/templates/a03_injection/email_preview.html` (for the exact SSTI payload chain style and `{% raw %}` escaping convention to reuse) and `app/categories/a03_injection/templates/a03_injection/xml_import.html` (for the `{{ secret_path }}` reveal convention already used for `XXE_SECRET_PATH`).

- [ ] **Step 2: Create the static secret file**

Create `app/categories/a03_injection/file_inclusion_secret.txt`:

```
Internal Notes -- Do Not Distribute
Deploy webhook secret: fi7-webhook-secret-2024
```

- [ ] **Step 3: Write the failing tests**

Create `tests/test_a03_file_inclusion.py`:

```python
from app.categories.a03_injection.routes import FILE_INCLUSION_SECRET_PATH


def test_file_inclusion_page_renders(client):
    response = client.get("/a03/file-inclusion")
    assert response.status_code == 200
    assert b"LFI-to-SSTI" in response.data


def test_save_and_render_snippet_round_trip(client):
    client.post("/a03/save-snippet", data={"name": "greeting", "content": "Hello there!"})
    response = client.get("/a03/render-snippet", query_string={"name": "greeting"})
    assert response.status_code == 200
    assert b"Hello there!" in response.data


def test_included_snippet_content_is_evaluated_as_a_template(client):
    client.post("/a03/save-snippet", data={"name": "math-proof", "content": "{{ 7*7 }}"})
    response = client.get("/a03/render-snippet", query_string={"name": "math-proof"})
    assert response.status_code == 200
    assert b"49" in response.data
    assert b"{{ 7*7 }}" not in response.data


def test_planted_snippet_achieves_real_code_execution(client):
    payload = (
        "{{ self.__init__.__globals__.__builtins__.__import__('os')"
        ".popen('id').read() }}"
    )
    client.post("/a03/save-snippet", data={"name": "pwn", "content": payload})
    response = client.get("/a03/render-snippet", query_string={"name": "pwn"})
    assert response.status_code == 200
    assert b"uid=" in response.data


def test_render_snippet_discloses_arbitrary_file_via_absolute_path(client):
    response = client.get(
        "/a03/render-snippet", query_string={"name": FILE_INCLUSION_SECRET_PATH}
    )
    assert response.status_code == 200
    with open(FILE_INCLUSION_SECRET_PATH) as f:
        expected_first_line = f.read().splitlines()[0]
    assert expected_first_line.encode() in response.data
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `pytest tests/test_a03_file_inclusion.py -v`
Expected: FAIL — `404 NOT FOUND` for `/a03/file-inclusion` (routes don't exist yet).

- [ ] **Step 5: Add constants and the three vulnerable routes**

Near the top of `app/categories/a03_injection/routes.py`, alongside the existing `ACCOUNT_RECOVERY_PIN`/`CSS_EXFIL_LOG_PATH`/`ARCHIVE_EXPORT_DIR`/`ARGUMENT_INJECTION_PROOF_PATH` constants, add:

```python
FILE_INCLUSION_SECRET_PATH = os.path.join(os.path.dirname(__file__), "file_inclusion_secret.txt")
SNIPPETS_DIR = os.path.join(BASE_DIR, "instance", "a03_snippets")
```

Append these three routes to the end of the file (after Task 3's `feedback()`, which will then be the file's last function):

```python
@a03_bp.route("/file-inclusion")
def file_inclusion():
    saved_name = request.args.get("saved")
    return render_template(
        "a03_injection/file_inclusion.html",
        saved_name=saved_name,
        secret_path=FILE_INCLUSION_SECRET_PATH,
    )


@a03_bp.route("/save-snippet", methods=["POST"])
def save_snippet():
    name = request.form.get("name", "")
    content = request.form.get("content", "")
    os.makedirs(SNIPPETS_DIR, exist_ok=True)
    snippet_path = os.path.join(SNIPPETS_DIR, name)
    with open(snippet_path, "w") as f:
        f.write(content)
    return redirect(url_for("a03_injection.file_inclusion", saved=name))


@a03_bp.route("/render-snippet")
def render_snippet():
    name = request.args.get("name", "")
    result = None
    error = None
    if name:
        # VULNERABLE: `name` is joined directly onto SNIPPETS_DIR with no
        # validation at all -- a relative "../" climbs out of the
        # snippets directory entirely, and an absolute path discards it
        # outright (the same os.path.join() behavior demonstrated in
        # A01's Path Traversal examples). Whatever text comes back is
        # then rendered as a LIVE Jinja template via
        # render_template_string(), not displayed as inert data -- this
        # is this app's other SSTI examples' exact vulnerability, just
        # reached through a file path instead of a text field.
        snippet_path = os.path.join(SNIPPETS_DIR, name)
        try:
            with open(snippet_path) as f:
                content = f.read()
            result = render_template_string(content)
        except Exception as e:
            error = str(e)
    return render_template(
        "a03_injection/render_snippet.html", name=name, result=result, error=error
    )
```

- [ ] **Step 6: Create the two templates**

Create `app/categories/a03_injection/templates/a03_injection/file_inclusion.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "LFI-to-SSTI via Unsanitized Snippet Include" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This "custom snippet" feature lets you save a small piece of text
  under a name of your choosing — a stand-in for a mundane real feature
  like a saved email signature — and a separate "render snippet"
  feature reads that saved text back and displays it. The read happens
  via <code>open(os.path.join(SNIPPETS_DIR, name))</code>, with zero
  validation of <code>name</code>, and whatever comes back is passed
  through <code>render_template_string()</code> — executed as a live
  Jinja template, not displayed as inert text. Path Traversal lets an
  attacker READ an unintended file; File Inclusion, as demonstrated
  here, lets them EXECUTE one.
</p>
{% endblock %}

{% block detect %}
<p>
  Save a snippet named <code>test</code> with content
  <code>{% raw %}{{ 7*7 }}{% endraw %}</code>, then render it back by
  name. If the result shows <code>49</code> instead of the literal text
  <code>{% raw %}{{ 7*7 }}{% endraw %}</code>, the included file's
  content is being evaluated as a template, not displayed as data.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Save a snippet named <code>pwn</code> with this content:
      <pre><code class="language-python">{% raw %}{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}{% endraw %}</code></pre>
  </li>
  <li>Render it back by name: <code>?name=pwn</code>. The result shows
      the real output of the <code>id</code> command, run on the server
      itself — the exact same SSTI payload chain used elsewhere in this
      category, just reached by planting a file and including it by
      path instead of typing the payload directly into a template-string
      field.</li>
  <li>The include path also reaches files that were never saved through
      this feature at all. Try
      <code>?name={{ secret_path }}</code> — a bare absolute path,
      exactly like the technique demonstrated in this app's Path
      Traversal examples — and its real contents come back, proving
      arbitrary file disclosure works independently of the code-execution
      angle above.</li>
</ol>
<p>
  This is the Flask-native shape of classic PHP Local File Inclusion
  (<code>include($_GET['page'])</code>): the vulnerable feature is
  rarely the "obviously dangerous" one — it's usually a mundane
  content-include mechanism that happens to feed a file's contents into
  something that executes template or script syntax, with the actual
  attacker-controlled file planted through a completely unrelated,
  innocent-looking upload or save feature elsewhere in the app.
</p>
{% endblock %}

{% block vulnerable_code %}snippet_path = os.path.join(SNIPPETS_DIR, name)
with open(snippet_path) as f:
    content = f.read()
result = render_template_string(content)
{% endblock %}

{% block secure_code %}# Confirm the resolved path is genuinely inside SNIPPETS_DIR, and never
# execute included content as a template -- treat it as plain data:
candidate = os.path.realpath(os.path.join(SNIPPETS_DIR, name))
if not candidate.startswith(os.path.realpath(SNIPPETS_DIR) + os.sep):
    abort(403)
with open(candidate) as f:
    content = f.read()
result = content  # displayed as plain text, never passed to render_template_string()
{% endblock %}

{% block live_example %}
{% if saved_name %}
<div class="alert alert-success">Saved snippet: {{ saved_name }}</div>
{% endif %}
<h5>Save a snippet</h5>
<form method="post" action="{{ url_for('a03_injection.save_snippet') }}" class="mb-4">
  <div class="mb-2">
    <label class="form-label">Snippet name</label>
    <input type="text" class="form-control" name="name" placeholder="pwn">
  </div>
  <div class="mb-2">
    <label class="form-label">Snippet content</label>
    <textarea class="form-control" name="content" rows="3"></textarea>
  </div>
  <button type="submit" class="btn btn-primary">Save snippet</button>
</form>
<h5>Render a snippet by name</h5>
<form method="get" action="{{ url_for('a03_injection.render_snippet') }}">
  <div class="mb-2">
    <input type="text" class="form-control" name="name" placeholder="pwn">
  </div>
  <button type="submit" class="btn btn-primary">Render snippet</button>
</form>
<p class="mt-3 text-muted small">
  This lab's own secret file for this example lives at
  <code>{{ secret_path }}</code>, for use in the traversal step above.
</p>
{% endblock %}
```

Create `app/categories/a03_injection/templates/a03_injection/render_snippet.html`:

```html
{% extends "core/base.html" %}
{% block title %}Render Snippet Result{% endblock %}
{% block content %}
<h1>Render Snippet Result</h1>
<p>Snippet name: <strong>{{ name }}</strong></p>
{% if result %}
<pre>{{ result }}</pre>
{% endif %}
{% if error %}
<p class="text-danger">{{ error }}</p>
{% endif %}
<p><a href="{{ url_for('a03_injection.file_inclusion') }}">&larr; Back</a></p>
{% endblock %}
```

- [ ] **Step 7: Register the ExampleNav entry**

In `app/categories/a03_injection/__init__.py`, insert this new `ExampleNav` immediately after the `csv-formula-injection` entry's closing `),` and before the list's closing `],` (the current last entry in the file):

```python
            ExampleNav(
                id="file-inclusion-lfi-ssti",
                title="LFI-to-SSTI via Unsanitized Snippet Include",
                group="File Inclusion",
                difficulty="Hard",
                endpoint="a03_injection.file_inclusion",
                hints=[
                    "This 'custom snippet' feature saves text under a name you choose, and a separate feature reads a saved snippet back by that same name. Look at how the read side handles the name -- and what it does with the file's CONTENT once read.",
                    "Save a snippet named test with the content {{ 7*7 }}, then render it back by name. If the result shows 49 instead of the literal text {{ 7*7 }}, the file's content is being evaluated as a live Jinja template, not displayed as data.",
                    "Save a snippet containing the same SSTI payload chain used elsewhere in this category: {{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}. Render it back by name -- the real output of the id command comes back, proving genuine code execution through a feature that only ever looked like a text-storage tool.",
                    "The include path also has zero validation on the name parameter itself -- exactly like this app's Path Traversal examples. Try rendering a snippet 'name' that's actually a bare absolute path to a file that was never saved through this feature at all -- its real contents come back too, proving arbitrary file disclosure works completely independently of the code-execution angle above.",
                ],
            ),
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `pytest tests/test_a03_file_inclusion.py -v`
Expected: PASS (all 5 tests).

- [ ] **Step 9: Update A03's cross-cutting test files**

In `tests/test_a03_hints_remaining_groups.py`, add `"file-inclusion-lfi-ssti"` to the end of `REMAINING_GROUP_IDS`.

In `tests/test_a03_overview.py`:

Task 3 left `tests/test_a03_overview.py`'s difficulty list at 23 entries, ending in `"Medium"` (the `csv-formula-injection` entry). Append `"Hard"` as the 24th (final) entry — this task's example is always the last entry in A03's flat list. The full 24-entry list should now read exactly as the Orchestration Note's fully-composed table shows it.

Append `"File Inclusion"` as the 9th (final) group name (the group list currently ends with `"CSV Injection"`, per Task 3), and add:

```python
    assert [e.id for e in grouped[8][1]] == ["file-inclusion-lfi-ssti"]
```

- [ ] **Step 10: Run the full A03 test surface**

Run: `pytest tests/test_a03_file_inclusion.py tests/test_a03_unicode_normalization_xss.py tests/test_a03_csv_injection.py tests/test_a03_argument_injection.py tests/test_a03_hints_remaining_groups.py tests/test_a03_hints_sqli_group.py tests/test_a03_overview.py -v`
Expected: PASS (all tests, no regressions).

- [ ] **Step 11: Commit**

```bash
git add app/categories/a03_injection/routes.py \
        app/categories/a03_injection/__init__.py \
        app/categories/a03_injection/file_inclusion_secret.txt \
        app/categories/a03_injection/templates/a03_injection/file_inclusion.html \
        app/categories/a03_injection/templates/a03_injection/render_snippet.html \
        tests/test_a03_file_inclusion.py \
        tests/test_a03_hints_remaining_groups.py \
        tests/test_a03_overview.py
git commit -m "feat(a03): add LFI-to-SSTI via Unsanitized Snippet Include example"
```

---

### Task 5: Final Integration

**Files:**
- Modify: `tests/test_all_examples_have_hints.py`
- Modify: `tests/test_hints.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: the final state of A01 and A03 after Tasks 1-4 — 95 total examples across all categories, max score 2010.
- Produces: nothing further downstream; this is the plan's last task.

- [ ] **Step 1: Confirm the actual current totals**

Before editing anything, run:

```bash
python3 -c "
from app import create_app
from app.core.nav import CATEGORIES
app = create_app()
with app.app_context():
    total = sum(len(c.examples) for c in CATEGORIES)
    print('total examples:', total)
"
```

Expected: `total examples: 95` (90 + Task 1's 1 + Task 2's 2 + Task 3's 1 + Task 4's 1). If this doesn't read 95, stop and investigate before proceeding.

- [ ] **Step 2: Update the cross-cutting count assertion**

In `tests/test_all_examples_have_hints.py`, change `assert total == 90` to `assert total == 95`.

- [ ] **Step 3: Update the max-score assertions**

In `tests/test_hints.py`, change both `1880` occurrences to `2010`:

```python
    assert "Score: 10 / 2010 points" in body
```
and:
```python
    assert b"Score: 10 / 2010" in response.data
```

- [ ] **Step 4: Update README.md's intro paragraph**

Find the A01 parenthetical, currently:
```
Currently implemented: **A01 Broken Access Control** (IDOR, missing function-level
authorization, mass assignment / role escalation, IDOR on a password-change API,
CSRF-based email-address takeover), **A02 Cryptographic Failures**
```
and change it to:
```
Currently implemented: **A01 Broken Access Control** (IDOR, missing function-level
authorization, mass assignment / role escalation, IDOR on a password-change API,
CSRF-based email-address takeover, CSRF via token presence-only validation,
arbitrary file read via document download, path traversal filter bypass via
absolute path), **A02 Cryptographic Failures**
```

Find the A03 parenthetical, currently:
```
**A03 Injection** (SQL injection auth bypass, UNION-based exfiltration, reflected XSS,
blind time-based SQLi, error-based SQLi, OS command injection, SQL injection escalating
to remote code execution, stored XSS, XXE file disclosure, XXE SSRF, CSS
attribute-selector data exfiltration via a profile theme, argument injection via an
unsanitized tar export, and CSV formula injection via comment export),
```
and change it to:
```
**A03 Injection** (SQL injection auth bypass, UNION-based exfiltration, reflected XSS,
blind time-based SQLi, error-based SQLi, OS command injection, SQL injection escalating
to remote code execution, stored XSS, XXE file disclosure, XXE SSRF, CSS
attribute-selector data exfiltration via a profile theme, argument injection via an
unsanitized tar export, CSV formula injection via comment export, Unicode
normalization filter bypass, and LFI-to-SSTI via an unsanitized snippet include),
```

- [ ] **Step 5: Update README.md's category summary table**

Change the A01 row, currently:
```
| A01 Broken Access Control | Implemented | IDOR (Easy), IDOR on Password-Change API (Medium), Hidden Admin Panel (Medium), Mass Assignment Role Escalation (Hard), Account Takeover via CSRF (Email Change) (Medium) |
```
to:
```
| A01 Broken Access Control | Implemented | IDOR (Easy), IDOR on Password-Change API (Medium), Hidden Admin Panel (Medium), Mass Assignment Role Escalation (Hard), Account Takeover via CSRF (Email Change) (Medium), CSRF via Token Presence-Only Validation (Medium), Arbitrary File Read via Document Download (Medium), Path Traversal Filter Bypass via Absolute Path (Hard) |
```

Change the A03 row, currently:
```
| A03 Injection | Implemented | SQLi Auth Bypass (Easy), UNION SQLi Exfiltration (Medium), Error-Based SQLi (Medium), Reflected XSS (Medium), Blind Time-Based SQLi (Hard), OS Command Injection (Hard), SQLi to RCE (Hard), Stored XSS (Hard), XXE File Disclosure (Easy), XXE SSRF (Hard), CSS Attribute-Selector Data Exfiltration (Hard), Argument Injection via tar Export (Hard), CSV Formula Injection (Medium) |
```
to:
```
| A03 Injection | Implemented | SQLi Auth Bypass (Easy), UNION SQLi Exfiltration (Medium), Error-Based SQLi (Medium), Reflected XSS (Medium), Blind Time-Based SQLi (Hard), OS Command Injection (Hard), SQLi to RCE (Hard), Stored XSS (Hard), XXE File Disclosure (Easy), XXE SSRF (Hard), CSS Attribute-Selector Data Exfiltration (Hard), Argument Injection via tar Export (Hard), CSV Formula Injection (Medium), Unicode Normalization Filter Bypass (Hard), LFI-to-SSTI via Snippet Include (Hard) |
```

- [ ] **Step 6: Run the full test suite**

Run: `pytest -q`
Expected: green, zero failures. Compute the exact expected pass count from the actual new-test counts across Tasks 1-4 (3 + 5 + 3 + 5 = 16 new tests) plus the prior baseline (551 passed + 1 approved GNU-tar-only skip, from round 4's final state) — expect approximately `567 passed, 1 skipped`, but **verify this arithmetic against the actual observed new-test counts from each task's own Step 7/8 runs rather than trusting this estimate blindly** (matching this plan's own practice from prior rounds of never trusting a predicted count over an actually-observed one).

- [ ] **Step 7: Commit**

```bash
git add tests/test_all_examples_have_hints.py tests/test_hints.py README.md
git commit -m "test(nav): update total/max-score assertions and README for 5 new examples"
```

---

## Self-Review Notes (for the plan author, not an execution step)

**Spec coverage:** all 5 examples from the spec are fully covered by Tasks 1-4, including exact route names, the empirically-verified `os.path.join()` absolute-path-override primitive (reused identically across Task 2's two Directory Traversal examples and Task 4's File Inclusion example), the empirically-verified NFKC normalization behavior, and the confirmed Jinja2 template-loader traversal-safety finding that ruled out a `render_template(name)`-based design in favor of `open()` + `render_template_string()`.

**Placeholder scan:** no TBD/TODO; every step has literal, complete code.

**Type/naming consistency:** `DOCUMENTS_DIR`, `SNIPPETS_DIR`, `FILE_INCLUSION_SECRET_PATH` are each defined once and referenced identically everywhere else (templates, tests, hints). Endpoint names match between route decorators, `ExampleNav.endpoint` values, and every `url_for()` call across all four tasks' templates. Every new `ExampleNav.endpoint` points at an HTML-rendering route, never a raw action route (Task 4's `save_snippet`/`render_snippet` action routes are correctly NOT the `ExampleNav.endpoint` — `file_inclusion` is).

**Both Orchestration Notes' fully-composed orders:** independently derived from each category's actual current `__init__.py` content (read fresh during plan-writing) plus each task's own stated insertion point, cross-checked against each task's own Step 8/9 test-file edits — consistent throughout (A01: 8 examples/5 groups; A03: 24 examples/9 groups).

**Task 5's final assertions:** the 90→95 and 1880→2010 changes are arithmetically exact (Task 1: +1 Medium = +20; Task 2: +1 Medium +1 Hard = +50; Task 3: +1 Hard = +30; Task 4: +1 Hard = +30; total +130). Task 5 Step 1 has the implementer verify the actual total before touching any assertion, rather than trusting this arithmetic blindly, matching this plan's own Global Constraints spirit and the practice established in every prior round's Task 3/5.
