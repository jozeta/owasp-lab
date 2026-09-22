# A09 Security Logging and Monitoring Failures Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build A09 (OWASP Top 10 2021: Security Logging and Monitoring
Failures) as a new category with six examples, two per difficulty tier,
covering missing audit logging, insecure log storage, and the absence of
any alerting/detection for active attacks.

**Architecture:** New Flask blueprint `app/categories/a09_logging_monitoring_failures/`
registered in `app/__init__.py`, following the exact A01–A08 scaffold. One
new database model (`SecurityEvent`) plus a `log_security_event(event_type,
detail)` helper — directly modeled on A08's `RceProof`/`write_rce_proof()`
pattern — provides a DB-backed audit trail that some routes call correctly
and others deliberately skip. A second, independent mechanism — a real
on-disk log file at `<BASE_DIR>/instance/a09_app.log`, written via a plain
file-append helper (not Python's `logging` module) — backs the two
log-storage examples specifically. A shared, non-nav utility page
`/a09/security-events` (mirroring A08's `/a08/rce-proof`) shows the
`SecurityEvent` table, a hardcoded, permanently-empty "Active Alerts (0)"
panel, and the on-disk log's contents.

**Tech Stack:** Flask 3.0.3, Flask-SQLAlchemy, Python stdlib `os` (file
I/O), Flask's built-in `session` (signed cookie), Jinja2 templates, pytest.

**Spec:** `docs/superpowers/specs/2026-09-22-owasp-lab-a09-logging-monitoring-design.md`

## Global Constraints

- Every "was this logged?" claim in this plan flows through the shared
  `SecurityEvent` database table via `log_security_event(event_type,
  detail)` — a real, working call used correctly by some routes and
  deliberately omitted by others. Do not use an in-memory Python global for
  this; it must be DB-backed so it's visible regardless of which gunicorn
  worker handles a later request (the same reasoning as A08's `RceProof`).
- Example 2's demo user list is carried in the Flask `session` cookie
  (`session["a09_demo_users"]`), **never** a module-level Python global or
  in-memory set — a module-level global is invisible to a request handled
  by a different gunicorn worker process; a signed cookie is not.
- The on-disk log file lives at `<BASE_DIR>/instance/a09_app.log` (`BASE_DIR`
  is already defined in `app/__init__.py`; import it via `from app import
  BASE_DIR`). The `instance/` directory does not exist on disk yet and must
  be created lazily (`os.makedirs(..., exist_ok=True)`) on first write —
  `instance/` is already listed in `.gitignore`, so nothing here needs a git
  or Dockerfile change (the existing `chown -R appuser:appuser /app` step in
  the `Dockerfile` already makes this location writable).
- No new third-party dependency is added anywhere in this plan.
- Example 6's user-controlled search query is always rendered through a
  normal Jinja `{{ query }}` expression (auto-escaped), never marked safe
  and never placed in raw/unescaped template block text — this example is
  about logging visibility and missing detection, not injection, and an
  unescaped reflection would duplicate A03's territory.
- No test in this plan may assert on a proof string that also appears,
  unconditionally, in that same page's own static teaching prose — this bug
  class has recurred in A06, A07, and twice in A08. Every example's
  templates below deliberately avoid stating concrete secret/marker values
  in their own static HTML text for exactly this reason; tests choose their
  own literal values independently of template prose wherever a template
  shows an illustrative example.
- `tests/conftest.py` is off-limits — never modify it, for any reason, in
  any task. Two test files in this plan (Tasks 3 and 4) touch a real file
  on disk and need their own per-file cleanup fixture; define that fixture
  locally in each of those test files (pytest fully supports file-local
  fixtures), never in `conftest.py`.

---

## Task 1: Category Scaffold, SecurityEvent Model, Shared Monitoring Page, and Example 1 (Failed Login Attempts Never Logged)

**Files:**
- Create: `app/categories/a09_logging_monitoring_failures/__init__.py`
- Create: `app/categories/a09_logging_monitoring_failures/models.py`
- Create: `app/categories/a09_logging_monitoring_failures/routes.py`
- Create: `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/overview.html`
- Create: `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/security_events.html`
- Create: `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/login.html`
- Modify: `app/__init__.py`
- Test: `tests/test_a09_failed_logins_not_logged.py`

**Interfaces:**
- Produces: `a09_bp` (Blueprint, `url_prefix="/a09"`). `SecurityEvent`
  model (`app.categories.a09_logging_monitoring_failures.models`) with
  fields `id`, `event_type` (str), `detail` (str), `logged_at` (datetime).
  `log_security_event(event_type: str, detail: str) -> None`
  (`app.categories.a09_logging_monitoring_failures.routes`) — every later
  task calls this exact function with these exact two positional
  arguments. Route endpoints `a09_logging_monitoring_failures.overview` →
  `GET /a09/`, `a09_logging_monitoring_failures.security_events` → `GET
  /a09/security-events` (non-nav utility page, reused unchanged by every
  later task), `a09_logging_monitoring_failures.login` → `GET/POST
  /a09/login`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a09_failed_logins_not_logged.py`:

```python
def test_successful_login_is_logged(app, client):
    from app.categories.a09_logging_monitoring_failures.models import SecurityEvent

    with app.app_context():
        before = SecurityEvent.query.count()

    response = client.post(
        "/a09/login", data={"username": "demo", "password": "demo-password"}
    )
    assert response.status_code == 200

    with app.app_context():
        after = SecurityEvent.query.count()
        latest = SecurityEvent.query.order_by(SecurityEvent.id.desc()).first()

    assert after == before + 1
    assert latest.event_type == "user_login_success"


def test_failed_logins_are_never_logged(app, client):
    from app.categories.a09_logging_monitoring_failures.models import SecurityEvent

    with app.app_context():
        before = SecurityEvent.query.count()

    for _ in range(10):
        response = client.post(
            "/a09/login", data={"username": "demo", "password": "wrong-password"}
        )
        assert response.status_code == 200

    with app.app_context():
        after = SecurityEvent.query.count()

    assert after == before


def test_security_events_page_renders_with_empty_alerts_panel(client):
    response = client.get("/a09/security-events")
    assert response.status_code == 200
    assert b"Active Alerts (0)" in response.data


def test_failed_logins_not_logged_link_appears_in_overview_once_registered(client):
    response = client.get("/a09/")
    assert response.status_code == 200
    assert b"Failed Login Attempts Never Logged" in response.data
    assert b'href="/a09/login"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a09_failed_logins_not_logged.py -v`
Expected: FAIL — `ModuleNotFoundError` / 404s (nothing exists yet).

- [ ] **Step 3: Create the blueprint package**

Create `app/categories/a09_logging_monitoring_failures/__init__.py`:

```python
from flask import Blueprint

a09_bp = Blueprint(
    "a09_logging_monitoring_failures",
    __name__,
    template_folder="templates",
    url_prefix="/a09",
)

from app.categories.a09_logging_monitoring_failures import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a09_logging_monitoring_failures",
        short_id="A09",
        title="Security Logging and Monitoring Failures",
        blurb="Auditable events go unrecorded, logs leak sensitive data or sit exposed to anyone, and nothing ever alerts on an attack already in progress.",
        blueprint_name="a09_logging_monitoring_failures",
        overview_endpoint="a09_logging_monitoring_failures.overview",
        examples=[
            ExampleNav(
                id="failed-logins-not-logged",
                title="Failed Login Attempts Never Logged",
                group="Missing Audit Logging",
                difficulty="Easy",
                endpoint="a09_logging_monitoring_failures.login",
            ),
        ],
    )
)
```

- [ ] **Step 4: Create the SecurityEvent model**

Create `app/categories/a09_logging_monitoring_failures/models.py`:

```python
from datetime import datetime

from app.extensions import db


class SecurityEvent(db.Model):
    __tablename__ = "a09_security_events"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(64), nullable=False)
    detail = db.Column(db.String(255), nullable=False)
    logged_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
```

- [ ] **Step 5: Create the routes**

Create `app/categories/a09_logging_monitoring_failures/routes.py`:

```python
from flask import render_template, request

from app.categories.a09_logging_monitoring_failures import a09_bp
from app.categories.a09_logging_monitoring_failures.models import SecurityEvent
from app.extensions import db

DEMO_USERNAME = "demo"
DEMO_PASSWORD = "demo-password"


def log_security_event(event_type, detail):
    # DB-backed so the event is visible regardless of which gunicorn
    # worker handles a later request -- mirrors A08's write_rce_proof().
    db.session.add(SecurityEvent(event_type=event_type, detail=detail))
    db.session.commit()


@a09_bp.route("/")
def overview():
    return render_template("a09_logging_monitoring_failures/overview.html")


@a09_bp.route("/security-events")
def security_events():
    events = SecurityEvent.query.order_by(SecurityEvent.logged_at.desc()).all()
    return render_template(
        "a09_logging_monitoring_failures/security_events.html", events=events
    )


@a09_bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == DEMO_USERNAME and password == DEMO_PASSWORD:
            log_security_event("user_login_success", f"user={username}")
        else:
            # VULNERABLE: a failed login attempt is a textbook auditable
            # event -- this branch never logs anything at all, no matter
            # how many times it's hit.
            error = "Invalid username or password."
    return render_template("a09_logging_monitoring_failures/login.html", error=error)
```

- [ ] **Step 6: Create the templates**

Create `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/security_events.html`:

```html
{% extends "core/base.html" %}
{% block title %}Security Events — A09{% endblock %}

{% block content %}
<h1>Security Monitoring Dashboard</h1>
<p>This is the operator-facing view every A09 example writes to (or fails to write to).</p>

<section class="mb-4">
  <h2 class="h5">Active Alerts (0)</h2>
  <p>No alerting or detection logic exists anywhere in this application -- this count never changes, no matter what appears below.</p>
</section>

<section class="mb-4">
  <h2 class="h5">Security Event Log</h2>
  {% if events %}
  <table class="table table-sm">
    <thead><tr><th>Time</th><th>Event Type</th><th>Detail</th></tr></thead>
    <tbody>
      {% for event in events %}
      <tr><td>{{ event.logged_at }}</td><td>{{ event.event_type }}</td><td>{{ event.detail }}</td></tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p>No events recorded yet.</p>
  {% endif %}
</section>
{% endblock %}
```

Create `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/login.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Failed Login Attempts Never Logged" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A09{% endblock %}

{% block explanation %}
<p>
  This login form checks credentials the same way any login form does. A
  successful login writes a real audit-log entry. A failed login --
  arguably the more security-relevant event of the two -- writes nothing
  at all, no matter how many times it happens.
</p>
{% endblock %}

{% block detect %}
<p>
  Log in successfully first (username <code>demo</code>, password
  <code>demo-password</code>) and check the
  <a href="{{ url_for('a09_logging_monitoring_failures.security_events') }}">security event log</a>
  -- a new entry appears immediately, proving the logging mechanism itself
  works. Then submit several wrong passwords and check again.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Submit the wrong password below 10 or more times in a row, then check the
  <a href="{{ url_for('a09_logging_monitoring_failures.security_events') }}">security event log</a>
  again. The event count hasn't moved at all -- every one of those
  attempts vanished the instant the response was sent, leaving no record
  an operator could ever review, alert on, or use to detect an attack in
  progress.
</p>
{% endblock %}

{% block vulnerable_code %}if username == DEMO_USERNAME and password == DEMO_PASSWORD:
    log_security_event("user_login_success", f"user={username}")
else:
    # no log_security_event() call at all on this branch
    error = "Invalid username or password."
{% endblock %}

{% block secure_code %}if username == DEMO_USERNAME and password == DEMO_PASSWORD:
    log_security_event("user_login_success", f"user={username}")
else:
    log_security_event("user_login_failed", f"user={username}")
    error = "Invalid username or password."
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Username</label>
    <input class="form-control" type="text" name="username">
  </div>
  <div class="mb-2">
    <label class="form-label">Password</label>
    <input class="form-control" type="password" name="password">
  </div>
  <button type="submit" class="btn btn-primary">Log In</button>
</form>
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
<p class="mt-3">
  <a href="{{ url_for('a09_logging_monitoring_failures.security_events') }}">View security event log</a>
</p>
{% endblock %}
```

Create `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/overview.html`:

```html
{% extends "core/overview_base.html" %}
{% set category_short_id = "A09" %}
{% set category_title = "Security Logging and Monitoring Failures" %}
{% block title %}A09: Security Logging and Monitoring Failures{% endblock %}

{% block what_it_is %}
<p>
  Security Logging and Monitoring Failures cover the gap between an attack
  happening and anyone finding out about it -- auditable events that are
  never recorded, logs that are recorded but leak sensitive data or sit
  exposed with no access control, and attack signatures that show up
  clearly in the data but never trigger any alert, escalation, or
  response.
</p>
{% endblock %}

{% block why_it_matters %}
<p>
  Every other category in this app is about stopping an attack. This one
  is about noticing it happened at all. Real breaches are frequently
  discovered months after the fact, by a third party, not by the
  organization that was breached -- almost always because nothing was
  logged, what was logged wasn't reviewed or protected, or nothing was in
  place to raise an alarm while the attack was still in progress.
</p>
{% endblock %}

{% block how_exploited %}
<p>
  Attackers don't need to evade detection that doesn't exist. They can
  brute-force a login with no failed-attempt record ever created, perform
  a destructive admin action with zero audit trail, or leave an obvious
  attack signature sitting in plaintext logs that nothing ever reviews or
  flags -- all while any of it would have been trivially visible to a
  monitoring system that was actually looking.
</p>
{% endblock %}

{% block attack_flow_diagram %}
sequenceDiagram
    participant Attacker
    participant App as Vulnerable App
    participant Log as Security Event Log
    Attacker->>App: Repeated failed logins, a destructive action, or an obvious attack signature
    App-->>Log: (nothing written -- or written but never reviewed, protected, or alerted on)
    Note over Log: Active Alerts stays at 0 regardless
{% endblock %}

{% block real_world_impact %}
<p>
  Real incidents in this category include breaches that went undetected
  for months because failed-login and account-takeover activity was never
  logged or reviewed, and countless CWE-532 "insertion of sensitive
  information into log file" findings where plaintext credentials sat in
  operational logs that were themselves exposed to unauthorized access.
</p>
{% endblock %}

{% block vulnerable_code %}if username == DEMO_USERNAME and password == DEMO_PASSWORD:
    log_security_event("user_login_success", f"user={username}")
else:
    # no log_security_event() call at all on this branch
    error = "Invalid username or password."
{% endblock %}

{% block secure_code %}if username == DEMO_USERNAME and password == DEMO_PASSWORD:
    log_security_event("user_login_success", f"user={username}")
else:
    log_security_event("user_login_failed", f"user={username}")
    error = "Invalid username or password."
{% endblock %}
```

- [ ] **Step 7: Register the blueprint**

Modify `app/__init__.py` — add, immediately after the existing A08
registration block (after `app.register_blueprint(a08_bp)` and before the
`/healthz` route):

```python
    from app.categories.a09_logging_monitoring_failures import a09_bp

    app.register_blueprint(a09_bp)
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a09_failed_logins_not_logged.py -v`
Expected: PASS (4 passed)

- [ ] **Step 9: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all pass (363 baseline + 4 new = 367).

- [ ] **Step 10: Commit**

```bash
git add app/categories/a09_logging_monitoring_failures app/__init__.py tests/test_a09_failed_logins_not_logged.py
git commit -m "feat(a09): add category scaffold, SecurityEvent model, and failed-logins-not-logged example"
```

---

## Task 2: Example 2 (High-Value Admin Action With No Audit Trail)

**Files:**
- Modify: `app/categories/a09_logging_monitoring_failures/routes.py`
- Modify: `app/categories/a09_logging_monitoring_failures/__init__.py`
- Create: `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/admin_actions.html`
- Test: `tests/test_a09_admin_action_no_audit.py`

**Interfaces:**
- Consumes: `a09_bp`, `log_security_event()` from Task 1 (unchanged).
- Produces: Route endpoint `a09_logging_monitoring_failures.admin_actions`
  → `GET/POST /a09/admin-actions`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a09_admin_action_no_audit.py`:

```python
def test_create_user_action_is_logged(app, client):
    from app.categories.a09_logging_monitoring_failures.models import SecurityEvent

    with app.app_context():
        before = SecurityEvent.query.count()

    response = client.post(
        "/a09/admin-actions", data={"action": "create", "username": "carol"}
    )
    assert response.status_code == 200

    with app.app_context():
        after = SecurityEvent.query.count()
        latest = SecurityEvent.query.order_by(SecurityEvent.id.desc()).first()

    assert after == before + 1
    assert latest.event_type == "admin_user_created"
    assert "carol" in latest.detail


def test_delete_user_action_is_never_logged(app, client):
    from app.categories.a09_logging_monitoring_failures.models import SecurityEvent

    client.post("/a09/admin-actions", data={"action": "create", "username": "carol"})

    with app.app_context():
        before = SecurityEvent.query.count()

    response = client.post(
        "/a09/admin-actions", data={"action": "delete", "username": "carol"}
    )
    assert response.status_code == 200

    with app.app_context():
        after = SecurityEvent.query.count()

    assert after == before


def test_admin_action_no_audit_link_appears_in_overview_once_registered(client):
    response = client.get("/a09/")
    assert response.status_code == 200
    assert b"High-Value Admin Action With No Audit Trail" in response.data
    assert b'href="/a09/admin-actions"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a09_admin_action_no_audit.py -v`
Expected: FAIL — 404 (no route yet).

- [ ] **Step 3: Add the route**

Modify `app/categories/a09_logging_monitoring_failures/routes.py` — change
the `flask` import line to also import `session`:

```python
from flask import render_template, request, session
```

Then, after the `login()` route, add:

```python


ADMIN_ACTIONS_SESSION_KEY = "a09_demo_users"
DEFAULT_DEMO_USERS = ["alice", "bob"]


@a09_bp.route("/admin-actions", methods=["GET", "POST"])
def admin_actions():
    users = session.get(ADMIN_ACTIONS_SESSION_KEY, list(DEFAULT_DEMO_USERS))
    if request.method == "POST":
        action = request.form.get("action")
        username = request.form.get("username", "")
        if action == "create":
            if username and username not in users:
                users.append(username)
            log_security_event("admin_user_created", f"username={username}")
        elif action == "delete":
            if username in users:
                users.remove(username)
            # VULNERABLE: a destructive, high-value admin action -- the
            # exact kind of event OWASP's A09 calls out by name -- and it
            # writes nothing to the audit log at all.
        session[ADMIN_ACTIONS_SESSION_KEY] = users
    return render_template(
        "a09_logging_monitoring_failures/admin_actions.html", users=sorted(users)
    )
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a09_logging_monitoring_failures/__init__.py` — in
the `examples=[...]` list, after the `failed-logins-not-logged` entry, add:

```python
            ExampleNav(
                id="admin-action-no-audit",
                title="High-Value Admin Action With No Audit Trail",
                group="Missing Audit Logging",
                difficulty="Medium",
                endpoint="a09_logging_monitoring_failures.admin_actions",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/admin_actions.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "High-Value Admin Action With No Audit Trail" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A09{% endblock %}

{% block explanation %}
<p>
  This admin panel has two actions that look equally important: creating
  a user account and deleting one. Only one of them writes to the
  security event log.
</p>
{% endblock %}

{% block detect %}
<p>
  Create a user below and check the
  <a href="{{ url_for('a09_logging_monitoring_failures.security_events') }}">security event log</a>
  -- a new entry appears. Then delete a user and check again.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Delete any user from the list below, then check the
  <a href="{{ url_for('a09_logging_monitoring_failures.security_events') }}">security event log</a>
  again. The deletion succeeded -- the user is gone from the list -- but
  no record of who deleted whom, or when, exists anywhere. A destructive
  action with real consequences left absolutely no audit trail.
</p>
{% endblock %}

{% block vulnerable_code %}if action == "create":
    users.append(username)
    log_security_event("admin_user_created", f"username={username}")
elif action == "delete":
    users.remove(username)
    # no log_security_event() call at all on this branch
{% endblock %}

{% block secure_code %}if action == "create":
    users.append(username)
    log_security_event("admin_user_created", f"username={username}")
elif action == "delete":
    users.remove(username)
    log_security_event("admin_user_deleted", f"username={username}")
{% endblock %}

{% block live_example %}
<p>Current users: {{ users|join(", ") if users else "(none)" }}</p>
<form method="post" class="mb-2">
  <input type="hidden" name="action" value="create">
  <div class="input-group">
    <input class="form-control" type="text" name="username" placeholder="username to create">
    <button type="submit" class="btn btn-primary">Create User</button>
  </div>
</form>
<form method="post">
  <input type="hidden" name="action" value="delete">
  <div class="input-group">
    <input class="form-control" type="text" name="username" placeholder="username to delete">
    <button type="submit" class="btn btn-danger">Delete User</button>
  </div>
</form>
<p class="mt-3">
  <a href="{{ url_for('a09_logging_monitoring_failures.security_events') }}">View security event log</a>
</p>
{% endblock %}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a09_admin_action_no_audit.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all pass (367 baseline + 3 new = 370).

- [ ] **Step 8: Commit**

```bash
git add app/categories/a09_logging_monitoring_failures tests/test_a09_admin_action_no_audit.py
git commit -m "feat(a09): add admin-action-no-audit example"
```

---

## Task 3: Example 3 (Sensitive Data Leaked Into Log Files) + File-Log Helpers

**Files:**
- Modify: `app/categories/a09_logging_monitoring_failures/routes.py`
- Modify: `app/categories/a09_logging_monitoring_failures/__init__.py`
- Modify: `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/security_events.html`
- Create: `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/support_login.html`
- Test: `tests/test_a09_sensitive_data_in_logs.py`

**Interfaces:**
- Consumes: `a09_bp` from Task 1 (unchanged).
- Produces: `LOG_FILE_PATH` (str, absolute path constant) and
  `append_to_app_log(line: str) -> None` /
  `_read_app_log() -> str` (`app.categories.a09_logging_monitoring_failures.routes`)
  — Task 4 imports and reuses all three unchanged, and this task's own test
  file reads `LOG_FILE_PATH` directly for verification. Route endpoint
  `a09_logging_monitoring_failures.support_login` → `GET/POST
  /a09/support-login`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a09_sensitive_data_in_logs.py`:

```python
import os

import pytest

from app.categories.a09_logging_monitoring_failures.routes import LOG_FILE_PATH


@pytest.fixture(autouse=True)
def _clean_log_file():
    # LOG_FILE_PATH is a real file on disk, not wiped by the in-memory test
    # DB -- clean it before and after every test in this file so tests
    # never see another test's leftover content. This fixture is local to
    # this test file, not tests/conftest.py, which stays off-limits.
    if os.path.exists(LOG_FILE_PATH):
        os.remove(LOG_FILE_PATH)
    yield
    if os.path.exists(LOG_FILE_PATH):
        os.remove(LOG_FILE_PATH)


def _read_log_file():
    if not os.path.exists(LOG_FILE_PATH):
        return ""
    with open(LOG_FILE_PATH) as f:
        return f.read()


def test_support_login_succeeds_with_correct_credentials(client):
    response = client.post(
        "/a09/support-login", data={"username": "support", "password": "letmein123"}
    )
    assert response.status_code == 200
    assert b"Invalid username or password" not in response.data


def test_failed_support_login_leaks_plaintext_password_to_log_file(client):
    marker_password = "test-marker-9f3c2b1a-do-not-reuse"
    client.post(
        "/a09/support-login",
        data={"username": "attacker", "password": marker_password},
    )

    log_contents = _read_log_file()
    assert marker_password in log_contents

    response = client.get("/a09/security-events")
    assert marker_password.encode() in response.data


def test_sensitive_data_in_logs_link_appears_in_overview_once_registered(client):
    response = client.get("/a09/")
    assert response.status_code == 200
    assert b"Sensitive Data Leaked Into Log Files" in response.data
    assert b'href="/a09/support-login"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a09_sensitive_data_in_logs.py -v`
Expected: FAIL — `ImportError` (`LOG_FILE_PATH` doesn't exist yet) / 404.

- [ ] **Step 3: Add the file-log helpers and the route**

Modify `app/categories/a09_logging_monitoring_failures/routes.py` — add
`import os` and `from app import BASE_DIR` to the top imports:

```python
import os

from flask import render_template, request, session

from app import BASE_DIR
from app.categories.a09_logging_monitoring_failures import a09_bp
from app.categories.a09_logging_monitoring_failures.models import SecurityEvent
from app.extensions import db
```

Then, after the `DEMO_USERNAME`/`DEMO_PASSWORD` constants, add:

```python
LOG_FILE_PATH = os.path.join(BASE_DIR, "instance", "a09_app.log")

SUPPORT_USERNAME = "support"
SUPPORT_PASSWORD = "letmein123"


def append_to_app_log(line):
    os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
    with open(LOG_FILE_PATH, "a") as f:
        f.write(line + "\n")


def _read_app_log():
    if not os.path.exists(LOG_FILE_PATH):
        return ""
    with open(LOG_FILE_PATH) as f:
        return f.read()
```

Modify the existing `security_events()` route to also read the log file:

```python
@a09_bp.route("/security-events")
def security_events():
    events = SecurityEvent.query.order_by(SecurityEvent.logged_at.desc()).all()
    log_contents = _read_app_log()
    return render_template(
        "a09_logging_monitoring_failures/security_events.html",
        events=events,
        log_contents=log_contents,
    )
```

Then, after the `admin_actions()` route, add:

```python


@a09_bp.route("/support-login", methods=["GET", "POST"])
def support_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == SUPPORT_USERNAME and password == SUPPORT_PASSWORD:
            error = None
        else:
            # VULNERABLE: logs the FULL submitted credentials, including
            # the plaintext password, straight into the app's log file --
            # a textbook CWE-532 sensitive-data-in-logs bug.
            append_to_app_log(
                f"support-login failed: username={username!r} password={password!r}"
            )
            error = "Invalid username or password."
    return render_template("a09_logging_monitoring_failures/support_login.html", error=error)
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a09_logging_monitoring_failures/__init__.py` — in
the `examples=[...]` list, after the `admin-action-no-audit` entry, add:

```python
            ExampleNav(
                id="sensitive-data-in-logs",
                title="Sensitive Data Leaked Into Log Files",
                group="Insecure Log Storage",
                difficulty="Easy",
                endpoint="a09_logging_monitoring_failures.support_login",
            ),
```

- [ ] **Step 5: Update the shared monitoring template**

Modify `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/security_events.html`
— add a new section after the "Security Event Log" section (before the
final `{% endblock %}`):

```html

<section class="mb-4">
  <h2 class="h5">Raw Application Log</h2>
  {% if log_contents %}
  <pre>{{ log_contents }}</pre>
  {% else %}
  <p>No log file yet.</p>
  {% endif %}
</section>
```

- [ ] **Step 6: Create the template**

Create `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/support_login.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Sensitive Data Leaked Into Log Files" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A09{% endblock %}

{% block explanation %}
<p>
  This "support portal" login writes a diagnostic line to the
  application's log file whenever a login attempt fails -- including the
  full submitted form data, exactly as the client sent it.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit any wrong password below, then check the
  <a href="{{ url_for('a09_logging_monitoring_failures.security_events') }}">raw application log</a>
  -- your password is sitting there in plaintext.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Submit any password below -- try something memorable -- then check the
  <a href="{{ url_for('a09_logging_monitoring_failures.security_events') }}">raw application log</a>.
  Whatever you typed appears there in cleartext, in a file meant for
  operational diagnostics, not credential storage -- and this file has no
  access control of its own (the next example proves exactly how little).
</p>
{% endblock %}

{% block vulnerable_code %}else:
    append_to_app_log(
        f"support-login failed: username={username!r} password={password!r}"
    )
    error = "Invalid username or password."
{% endblock %}

{% block secure_code %}else:
    append_to_app_log(f"support-login failed: username={username!r}")
    # never write a password -- not even a failed one -- to a log file
    error = "Invalid username or password."
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Username</label>
    <input class="form-control" type="text" name="username">
  </div>
  <div class="mb-2">
    <label class="form-label">Password</label>
    <input class="form-control" type="password" name="password">
  </div>
  <button type="submit" class="btn btn-primary">Log In</button>
</form>
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
<p class="mt-3">
  <a href="{{ url_for('a09_logging_monitoring_failures.security_events') }}">View raw application log</a>
</p>
{% endblock %}
```

Note: this template's own static teaching prose never states a concrete
password value — only "whatever you typed" — so the test's independently
chosen `marker_password` cannot appear anywhere in this page's static text
regardless of what value the test picks. Do not add a concrete example
password to this template's prose.

- [ ] **Step 7: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a09_sensitive_data_in_logs.py -v`
Expected: PASS (3 passed)

- [ ] **Step 8: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all pass (370 baseline + 3 new = 373).

- [ ] **Step 9: Commit**

```bash
git add app/categories/a09_logging_monitoring_failures tests/test_a09_sensitive_data_in_logs.py
git commit -m "feat(a09): add sensitive-data-in-logs example and file-log helpers"
```

---

## Task 4: Example 4 (Unauthenticated Log File Exposure)

**Files:**
- Modify: `app/categories/a09_logging_monitoring_failures/routes.py`
- Modify: `app/categories/a09_logging_monitoring_failures/__init__.py`
- Create: `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/log_exposure_demo.html`
- Test: `tests/test_a09_log_file_world_readable.py`

**Interfaces:**
- Consumes: `a09_bp`, `append_to_app_log()`, `_read_app_log()`,
  `LOG_FILE_PATH` from Task 3 (unchanged).
- Produces: Route endpoints
  `a09_logging_monitoring_failures.log_exposure_demo` → `GET
  /a09/log-exposure-demo` (the ExampleNav-registered teaching page) and
  `a09_logging_monitoring_failures.download_log` → `GET /a09/download-log`
  (the vulnerable, unauthenticated route the teaching page links to — not
  itself nav-registered, matching A08's `/a08/rce-proof`-style utility
  route convention).

- [ ] **Step 1: Write the failing test**

Create `tests/test_a09_log_file_world_readable.py`:

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


def test_log_exposure_demo_plants_a_secret_in_the_log_file(client):
    response = client.get("/a09/log-exposure-demo")
    assert response.status_code == 200

    with open(LOG_FILE_PATH) as f:
        log_contents = f.read()
    assert "PLANTED-DEMO-SECRET" in log_contents


def test_download_log_route_requires_no_authentication(client):
    client.get("/a09/log-exposure-demo")

    response = client.get("/a09/download-log")
    assert response.status_code == 200
    assert b"PLANTED-DEMO-SECRET" in response.data


def test_log_file_world_readable_link_appears_in_overview_once_registered(client):
    response = client.get("/a09/")
    assert response.status_code == 200
    assert b"Unauthenticated Log File Exposure" in response.data
    assert b'href="/a09/log-exposure-demo"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a09_log_file_world_readable.py -v`
Expected: FAIL — 404 (no routes yet).

- [ ] **Step 3: Add the routes**

Modify `app/categories/a09_logging_monitoring_failures/routes.py` — change
the `flask` import line to also import `Response`:

```python
from flask import Response, render_template, request, session
```

Then, after the `support_login()` route, add:

```python


@a09_bp.route("/log-exposure-demo")
def log_exposure_demo():
    # Plant a secret into the same log file every time this page loads,
    # so this example is self-contained even if example 3 was never
    # visited.
    append_to_app_log(
        "support-login failed: username='demo-visitor' password='PLANTED-DEMO-SECRET'"
    )
    return render_template("a09_logging_monitoring_failures/log_exposure_demo.html")


@a09_bp.route("/download-log")
def download_log():
    # VULNERABLE: the operational log file -- which may contain plaintext
    # credentials logged by the support-login example -- is served to
    # absolutely anyone, no session or role check at all.
    return Response(_read_app_log(), mimetype="text/plain")
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a09_logging_monitoring_failures/__init__.py` — in
the `examples=[...]` list, after the `sensitive-data-in-logs` entry, add:

```python
            ExampleNav(
                id="log-file-world-readable",
                title="Unauthenticated Log File Exposure",
                group="Insecure Log Storage",
                difficulty="Hard",
                endpoint="a09_logging_monitoring_failures.log_exposure_demo",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/log_exposure_demo.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Unauthenticated Log File Exposure" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A09{% endblock %}

{% block explanation %}
<p>
  The "Sensitive Data Leaked Into Log Files" example proved secrets end up
  in a log file. Here's the consequence spelled out: that log file has no
  access control of its own. Anyone who can reach this app can read the
  whole thing, no login required.
</p>
{% endblock %}

{% block detect %}
<p>
  Fetch <a href="{{ url_for('a09_logging_monitoring_failures.download_log') }}">/a09/download-log</a>
  directly, with no prior login, no cookie, nothing -- and the file
  downloads anyway.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Visiting this page just planted one more secret into the shared
  application log file. Now fetch
  <a href="{{ url_for('a09_logging_monitoring_failures.download_log') }}">/a09/download-log</a>
  directly -- no login, no session, nothing -- and the entire raw log
  file downloads, including that secret and anything logged by the
  Sensitive Data Leaked Into Log Files example.
</p>
{% endblock %}

{% block vulnerable_code %}@a09_bp.route("/download-log")
def download_log():
    # no session/role check at all -- anyone can fetch the whole file
    return Response(_read_app_log(), mimetype="text/plain")
{% endblock %}

{% block secure_code %}@a09_bp.route("/download-log")
def download_log():
    if not current_user_is_admin():
        abort(403)
    return Response(_read_app_log(), mimetype="text/plain")
{% endblock %}

{% block live_example %}
<a href="{{ url_for('a09_logging_monitoring_failures.download_log') }}" class="btn btn-primary">
  Download Raw Log File (No Login Required)
</a>
{% endblock %}
```

Note: this template's static prose never states the literal string
`PLANTED-DEMO-SECRET` — it only exists in the Python route code, which is
never rendered as page text (only the `vulnerable_code`/`secure_code`
blocks above show route code, and neither of those shows the
`log_exposure_demo()` function, only `download_log()`). This keeps the
test's assertion on that literal string non-vacuous.

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a09_log_file_world_readable.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all pass (373 baseline + 3 new = 376).

- [ ] **Step 8: Commit**

```bash
git add app/categories/a09_logging_monitoring_failures tests/test_a09_log_file_world_readable.py
git commit -m "feat(a09): add log-file-world-readable example"
```

---

## Task 5: Example 5 (No Alert Threshold for Repeated Failures)

**Files:**
- Modify: `app/categories/a09_logging_monitoring_failures/routes.py`
- Modify: `app/categories/a09_logging_monitoring_failures/__init__.py`
- Create: `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/monitored_login.html`
- Test: `tests/test_a09_no_alert_threshold.py`

**Interfaces:**
- Consumes: `a09_bp`, `log_security_event()`, `DEMO_USERNAME`,
  `DEMO_PASSWORD` from Task 1 (unchanged).
- Produces: Route endpoint `a09_logging_monitoring_failures.monitored_login`
  → `GET/POST /a09/monitored-login`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a09_no_alert_threshold.py`:

```python
def test_monitored_login_success_is_logged(app, client):
    from app.categories.a09_logging_monitoring_failures.models import SecurityEvent

    with app.app_context():
        before = SecurityEvent.query.count()

    response = client.post(
        "/a09/monitored-login", data={"username": "demo", "password": "demo-password"}
    )
    assert response.status_code == 200

    with app.app_context():
        after = SecurityEvent.query.count()
        latest = SecurityEvent.query.order_by(SecurityEvent.id.desc()).first()

    assert after == before + 1
    assert latest.event_type == "monitored_login_success"


def test_monitored_login_logs_every_failed_attempt(app, client):
    from app.categories.a09_logging_monitoring_failures.models import SecurityEvent

    with app.app_context():
        before_total = SecurityEvent.query.count()
        before_failed = SecurityEvent.query.filter_by(
            event_type="monitored_login_failed"
        ).count()

    for _ in range(20):
        response = client.post(
            "/a09/monitored-login", data={"username": "demo", "password": "wrong"}
        )
        assert response.status_code == 200

    with app.app_context():
        after_total = SecurityEvent.query.count()
        after_failed = SecurityEvent.query.filter_by(
            event_type="monitored_login_failed"
        ).count()

    assert after_total == before_total + 20
    assert after_failed == before_failed + 20


def test_no_alert_appears_no_matter_how_many_failures(client):
    for _ in range(20):
        client.post(
            "/a09/monitored-login", data={"username": "demo", "password": "wrong"}
        )

    response = client.get("/a09/security-events")
    assert response.status_code == 200
    assert b"Active Alerts (0)" in response.data


def test_no_alert_threshold_link_appears_in_overview_once_registered(client):
    response = client.get("/a09/")
    assert response.status_code == 200
    assert b"No Alert Threshold for Repeated Failures" in response.data
    assert b'href="/a09/monitored-login"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a09_no_alert_threshold.py -v`
Expected: FAIL — 404 (no route yet) for three of the four tests. The
"Active Alerts (0)" test already passes (the panel is a static, unbacked
string added in Task 1) — that's expected and fine, mirroring the same
already-passing-before-implementation pattern A08's Tasks 5–6 documented.

- [ ] **Step 3: Add the route**

Modify `app/categories/a09_logging_monitoring_failures/routes.py` — after
the `download_log()` route, add:

```python


@a09_bp.route("/monitored-login", methods=["GET", "POST"])
def monitored_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == DEMO_USERNAME and password == DEMO_PASSWORD:
            log_security_event("monitored_login_success", f"user={username}")
        else:
            log_security_event("monitored_login_failed", f"user={username}")
            error = "Invalid username or password."
    return render_template(
        "a09_logging_monitoring_failures/monitored_login.html", error=error
    )
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a09_logging_monitoring_failures/__init__.py` — in
the `examples=[...]` list, after the `log-file-world-readable` entry, add:

```python
            ExampleNav(
                id="no-alert-threshold",
                title="No Alert Threshold for Repeated Failures",
                group="No Detection & Alerting for Active Attacks",
                difficulty="Medium",
                endpoint="a09_logging_monitoring_failures.monitored_login",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/monitored_login.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "No Alert Threshold for Repeated Failures" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A09{% endblock %}

{% block explanation %}
<p>
  Unlike the "Failed Login Attempts Never Logged" example, this login
  form logs every attempt correctly -- success and failure both write a
  real security-event row. The gap here isn't logging; it's that nothing
  ever reacts to what's been logged.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit a few wrong passwords below and check the
  <a href="{{ url_for('a09_logging_monitoring_failures.security_events') }}">security event log</a>
  -- every attempt is genuinely there.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Submit 20 or more consecutive wrong passwords below, then check the
  <a href="{{ url_for('a09_logging_monitoring_failures.security_events') }}">security event log</a>.
  All 20 attempts are logged, correctly, in full detail -- and "Active
  Alerts" is still 0. No lockout, no escalation, no notification, no
  matter how obvious the pattern in the data already is.
</p>
{% endblock %}

{% block vulnerable_code %}if username == DEMO_USERNAME and password == DEMO_PASSWORD:
    log_security_event("monitored_login_success", f"user={username}")
else:
    log_security_event("monitored_login_failed", f"user={username}")
    error = "Invalid username or password."
# every attempt is logged -- but nothing anywhere counts failures per
# user/IP or raises an alert once a threshold is crossed
{% endblock %}

{% block secure_code %}if username == DEMO_USERNAME and password == DEMO_PASSWORD:
    log_security_event("monitored_login_success", f"user={username}")
else:
    log_security_event("monitored_login_failed", f"user={username}")
    if recent_failure_count(username) >= 5:
        raise_alert("repeated_login_failures", username)
    error = "Invalid username or password."
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Username</label>
    <input class="form-control" type="text" name="username">
  </div>
  <div class="mb-2">
    <label class="form-label">Password</label>
    <input class="form-control" type="password" name="password">
  </div>
  <button type="submit" class="btn btn-primary">Log In</button>
</form>
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
<p class="mt-3">
  <a href="{{ url_for('a09_logging_monitoring_failures.security_events') }}">View security event log</a>
</p>
{% endblock %}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a09_no_alert_threshold.py -v`
Expected: PASS (4 passed)

- [ ] **Step 7: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all pass (376 baseline + 4 new = 380).

- [ ] **Step 8: Commit**

```bash
git add app/categories/a09_logging_monitoring_failures tests/test_a09_no_alert_threshold.py
git commit -m "feat(a09): add no-alert-threshold example"
```

---

## Task 6: Example 6 (Attack Signature Logged But Never Flagged)

**Files:**
- Modify: `app/categories/a09_logging_monitoring_failures/routes.py`
- Modify: `app/categories/a09_logging_monitoring_failures/__init__.py`
- Create: `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/product_search.html`
- Test: `tests/test_a09_attack_signature_not_flagged.py`

**Interfaces:**
- Consumes: `a09_bp`, `log_security_event()` from Task 1 (unchanged).
- Produces: Route endpoint `a09_logging_monitoring_failures.product_search`
  → `GET /a09/product-search`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a09_attack_signature_not_flagged.py`:

```python
def test_product_search_with_no_query_does_not_log(app, client):
    from app.categories.a09_logging_monitoring_failures.models import SecurityEvent

    with app.app_context():
        before = SecurityEvent.query.count()

    response = client.get("/a09/product-search")
    assert response.status_code == 200

    with app.app_context():
        after = SecurityEvent.query.count()

    assert after == before


def test_attack_signature_is_logged_verbatim_but_never_flagged(app, client):
    from app.categories.a09_logging_monitoring_failures.models import SecurityEvent

    # Deliberately a query with no HTML-special characters (no quotes,
    # angle brackets, or ampersands) -- Jinja2/MarkupSafe autoescaping
    # would otherwise rewrite a literal "'" to "&#39;" on the rendered
    # page, making a raw-substring check below fail even when the code
    # is correct. The DB-level assertion just below is unaffected either
    # way (SQLAlchemy stores the raw string, untouched by HTML escaping),
    # but the rendered-page check needs a string that survives escaping
    # unchanged, so this test uses a path-traversal probe instead of a
    # SQL-injection probe -- both are illustrated in the template's own
    # teaching prose (see Step 5 below), and either is an equally valid
    # "obvious attack signature" for this lesson.
    attack_query = "../../../../etc/passwd"

    with app.app_context():
        before = SecurityEvent.query.count()

    response = client.get("/a09/product-search", query_string={"q": attack_query})
    assert response.status_code == 200

    with app.app_context():
        after = SecurityEvent.query.count()
        latest = SecurityEvent.query.order_by(SecurityEvent.id.desc()).first()

    assert after == before + 1
    assert latest.detail == f"query={attack_query}"

    events_response = client.get("/a09/security-events")
    assert attack_query.encode() in events_response.data
    assert b"Active Alerts (0)" in events_response.data


def test_reflected_query_is_html_escaped_not_raw(client):
    response = client.get(
        "/a09/product-search", query_string={"q": "<script>alert(1)</script>"}
    )
    assert response.status_code == 200
    assert b"<script>alert(1)</script>" not in response.data
    assert b"&lt;script&gt;" in response.data


def test_attack_signature_not_flagged_link_appears_in_overview_once_registered(client):
    response = client.get("/a09/")
    assert response.status_code == 200
    assert b"Attack Signature Logged But Never Flagged" in response.data
    assert b'href="/a09/product-search"' in response.data
```

Note (flag for reviewer attention, per this session's recurring
vacuous-proof-string lesson): `product_search.html`'s own static
exploitation prose illustrates both a SQL-injection and a path-traversal
attack pattern as examples (see Step 5 below), and this test's
`attack_query` value (`"../../../../etc/passwd"`) happens to match the
path-traversal one shown there. This is **not** a vacuous test: both
load-bearing assertions in `test_attack_signature_is_logged_verbatim_but_
never_flagged` check the `/a09/security-events` page and the `SecurityEvent`
table, neither of which mentions any illustrative payload text anywhere in
their own static content — only `product_search.html` (a different page)
does. Confirm this separation holds when reviewing this task; do not "fix"
it by changing the test's literal to differ from the template's
illustrative example, since the two already never collide. Also confirm
the test's choice of a quote-free, angle-bracket-free string is
deliberate, not incidental: Jinja2/MarkupSafe autoescaping rewrites `'`,
`<`, `>`, `&`, and `"` on render, so a literal SQL-injection string
containing `'` would make the raw-substring check on `events_response.data`
fail even against fully correct code — this is why the test uses the
path-traversal probe instead of the SQL-injection probe for the
rendered-page assertion.

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a09_attack_signature_not_flagged.py -v`
Expected: FAIL — 404 (no route yet).

- [ ] **Step 3: Add the route**

Modify `app/categories/a09_logging_monitoring_failures/routes.py` — after
the `monitored_login()` route, add:

```python


@a09_bp.route("/product-search")
def product_search():
    query = request.args.get("q", "")
    if query:
        log_security_event("product_search", f"query={query}")
    return render_template(
        "a09_logging_monitoring_failures/product_search.html", query=query
    )
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a09_logging_monitoring_failures/__init__.py` — in
the `examples=[...]` list, after the `no-alert-threshold` entry, add:

```python
            ExampleNav(
                id="attack-signature-not-flagged",
                title="Attack Signature Logged But Never Flagged",
                group="No Detection & Alerting for Active Attacks",
                difficulty="Hard",
                endpoint="a09_logging_monitoring_failures.product_search",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a09_logging_monitoring_failures/templates/a09_logging_monitoring_failures/product_search.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Attack Signature Logged But Never Flagged" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A09{% endblock %}

{% block explanation %}
<p>
  This search box logs every query it receives, verbatim, to the security
  event log -- proving the app genuinely captures the evidence. Nothing
  in this app, anywhere, ever inspects that logged content for known
  attack patterns.
</p>
{% endblock %}

{% block detect %}
<p>
  Search for something ordinary, then check the
  <a href="{{ url_for('a09_logging_monitoring_failures.security_events') }}">security event log</a>
  -- your query is there, verbatim.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Search for an unmistakable attack signature -- a SQL injection probe
  like <code>&#39; OR &#39;1&#39;=&#39;1&#39; --</code>, or a
  path-traversal attempt like <code>../../../../etc/passwd</code> -- then
  check the
  <a href="{{ url_for('a09_logging_monitoring_failures.security_events') }}">security event log</a>.
  The exact string is sitting there in plain view, and "Active Alerts" is
  still 0 -- nothing in this app ever pattern-matches logged content
  against known attack signatures, no matter how obvious the signal is.
</p>
{% endblock %}

{% block vulnerable_code %}query = request.args.get("q", "")
if query:
    log_security_event("product_search", f"query={query}")
# logged verbatim -- but nothing anywhere checks logged content against
# any known attack-signature pattern, so this never raises an alert
{% endblock %}

{% block secure_code %}query = request.args.get("q", "")
if query:
    log_security_event("product_search", f"query={query}")
    if matches_known_attack_signature(query):
        raise_alert("suspicious_search_query", query)
{% endblock %}

{% block live_example %}
<form method="get">
  <div class="input-group">
    <input class="form-control" type="text" name="q" value="{{ query }}">
    <button type="submit" class="btn btn-primary">Search</button>
  </div>
</form>
{% if query %}
<p class="mt-3">You searched for: {{ query }}</p>
{% endif %}
<p class="mt-3">
  <a href="{{ url_for('a09_logging_monitoring_failures.security_events') }}">View security event log</a>
</p>
{% endblock %}
```

Note the `&#39;` HTML-entity escapes around the illustrative SQL-injection
example inside the `<code>` tag in the `exploitation` block's static text —
Jinja does not autoescape static block content (only `{{ }}` expressions),
so a literal `'` there is harmless, but the surrounding text is written
this way to keep the illustrative payload visibly inert as plain text
rather than something a template linter might flag; do not change this to
raw unescaped quote characters. The `{{ query }}` in the `live_example`
block, by contrast, is a normal Jinja expression and is autoescaped
automatically — never wrap it in `|safe` or mark it safe some other way.

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a09_attack_signature_not_flagged.py -v`
Expected: PASS (4 passed)

- [ ] **Step 7: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all pass (380 baseline + 4 new = 384).

- [ ] **Step 8: Commit**

```bash
git add app/categories/a09_logging_monitoring_failures tests/test_a09_attack_signature_not_flagged.py
git commit -m "feat(a09): add attack-signature-not-flagged example"
```

---

## Task 7: Final Integration — README and Overview Tests

**Files:**
- Modify: `README.md`
- Test: `tests/test_a09_overview.py`

**Interfaces:**
- Consumes: All six examples and the `CategoryNav` from Tasks 1–6.

- [ ] **Step 1: Write the overview/nav tests**

Create `tests/test_a09_overview.py`:

```python
def test_a09_overview_renders(client):
    response = client.get("/a09/")
    assert response.status_code == 200
    assert b"Security Logging and Monitoring Failures" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a09_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a09 = next(c for c in CATEGORIES if c.id == "a09_logging_monitoring_failures")
    assert a09.short_id == "A09"
    assert [e.difficulty for e in a09.examples] == [
        "Easy",
        "Medium",
        "Easy",
        "Hard",
        "Medium",
        "Hard",
    ]


def test_a09_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a09 = next(c for c in CATEGORIES if c.id == "a09_logging_monitoring_failures")
    grouped = a09.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Missing Audit Logging",
        "Insecure Log Storage",
        "No Detection & Alerting for Active Attacks",
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
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a09_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a09/")
    body = response.data.decode()
    assert "Missing Audit Logging" in body
    assert "Insecure Log Storage" in body
    assert "No Detection &amp; Alerting for Active Attacks" in body
```

Note: the group name "No Detection & Alerting for Active Attacks" contains
a literal `&`, which Jinja2's default autoescaping renders as `&amp;` in
HTML output — assert against the escaped form, matching the exact pattern
A08's group-heading test established for the same reason.

- [ ] **Step 2: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a09_overview.py -v`
Expected: PASS (4 passed)

- [ ] **Step 3: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all tests pass. Baseline before this plan was 363 (post-A08).
This plan's new tests: 4 (Task 1) + 3 (Task 2) + 3 (Task 3) + 3 (Task 4) +
4 (Task 5) + 4 (Task 6) + 4 (Task 7) = 25 new tests → 388 total.

- [ ] **Step 4: Update README.md's intro paragraph**

Modify `README.md` — read the current file fresh before editing (its exact
wrapping/wording may have drifted slightly since this plan was written),
then extend the "Currently implemented" paragraph's list to include A09
after A08, changing the trailing "Remaining categories (A10)" reference (it
currently reads "(A09–A10)" — this becomes just "(A10)"). The A09 clause to
insert, replacing the final "and **A08 ...**). Remaining categories
(A09–A10)..." construction with "..., and **A09 ...**). Remaining
categories (A10)...":

```markdown
, and **A09 Security Logging and Monitoring Failures** (failed login
attempts never logged, high-value admin action with no audit trail,
sensitive data leaked into log files, unauthenticated log file exposure,
no alert threshold for repeated failures, attack signature logged but
never flagged)
```

Insert it as the new final item in the list (after A08's clause, before the
"Remaining categories" sentence), matching the exact conjunction pattern
already used for every prior category in that paragraph (a single "and"
before the final item only — move the "and" that currently precedes A08's
clause so it precedes A09's clause instead, exactly as was done when A08
was added after A07).

- [ ] **Step 5: Update README.md's category summary table**

Modify `README.md` — replace the line:

```
| A09–A10 | Planned | See `docs/superpowers/specs/2026-09-18-owasp-lab-design.md` |
```

with:

```
| A09 Security Logging and Monitoring Failures | Implemented | Failed Login Attempts Never Logged (Easy), High-Value Admin Action With No Audit Trail (Medium), Sensitive Data Leaked Into Log Files (Easy), Unauthenticated Log File Exposure (Hard), No Alert Threshold for Repeated Failures (Medium), Attack Signature Logged But Never Flagged (Hard) |
| A10 | Planned | See `docs/superpowers/specs/2026-09-18-owasp-lab-design.md` |
```

- [ ] **Step 6: Commit**

```bash
git add README.md tests/test_a09_overview.py
git commit -m "docs(a09): update README and add overview/nav tests for A09"
```

No live browser verification step is needed for this category — every A09
example is fully exercisable and provable through the real Flask test
client (SecurityEvent row counts and direct reads of the real on-disk log
file), matching A08's precedent of not needing one.
