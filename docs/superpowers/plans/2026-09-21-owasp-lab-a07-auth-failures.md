# A07 Identification and Authentication Failures Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build A07 (OWASP Top 10 2021: Identification and Authentication
Failures) as a new category with six examples, two per difficulty tier,
covering brute force/credential stuffing, three genuine session-identity
lifecycle failures (URL exposure, no invalidation on logout, full session
fixation), and a bypassable MFA second factor.

**Architecture:** New Flask blueprint `app/categories/a07_auth_failures/`
registered in `app/__init__.py`, following the exact A01–A06 scaffold. A
new, genuinely server-side session mechanism (`AuthSession` model, cookie
`a07_session_id`) is built specifically for this category — Flask's
built-in `session` object (used by the sitewide `switch_user`/`logout`
convenience mechanism) is never touched. A new `A07Account` model holds a
small seeded set of demo accounts, following this app's established
per-category scoped-account convention (A02's `LegacyCredential`, A03's
`InjectionAccount`).

**Tech Stack:** Flask 3.0.3, Flask-SQLAlchemy, `werkzeug.security`
(`generate_password_hash`/`check_password_hash`), Jinja2 templates, pytest.

**Spec:** `docs/superpowers/specs/2026-09-21-owasp-lab-a07-auth-failures-design.md`

## Global Constraints

- Never modify `app/core/views.py`'s `switch_user`/`logout`/`home` or
  anything built on Flask's built-in `session` object — every other
  category depends on it unmodified.
- The session mechanism this plan builds (`AuthSession`, cookie
  `a07_session_id`) is completely separate infrastructure, used only by
  routes under `app/categories/a07_auth_failures/`.
- Session id resolution (`get_or_create_session()` in
  `session_store.py`) is the one deliberately vulnerable chokepoint: it
  reads `request.args.get("sid") or request.cookies.get(SID_COOKIE)` and
  adopts any client-supplied value as a real session — this exact logic
  was live-verified during brainstorming (positive control: full
  three-actor fixation chain works; negative control: ignoring `?sid=`
  and rotating the id on login blocks it completely). Transcribe it
  exactly as specified in each task — do not "improve" it.
- `logout()` clears only the client's cookie
  (`resp.set_cookie(SID_COOKIE, "", expires=0)`) and never deletes the
  corresponding `AuthSession` row — also live-verified. Do not add
  server-side invalidation to it; that is the deliberate vulnerability
  example 4 teaches.
- Passwords are hashed with `werkzeug.security.generate_password_hash`/
  `check_password_hash` (a real, secure hash) — A07's vulnerability is the
  *absence of rate limiting*, not weak hashing (that's A02's territory).
  Do not weaken the hashing to "demonstrate" anything.
- No rate-limiting library or `before_request` throttling hook is added
  anywhere — confirmed absent from `requirements.txt` and the codebase
  during brainstorming; this absence is the Group 1 vulnerability itself.
- `mfa-dashboard` checks only that `AuthSession.username` is set, never
  `AuthSession.mfa_verified` — this omission is the deliberate Hard-tier
  vulnerability; do not add the check.
- Follow the exact A05/A06 category scaffold: `Blueprint(..., template_folder="templates", url_prefix="/a07")`,
  `CATEGORIES.append(CategoryNav(...))` in `__init__.py`, `routes.py`,
  templates under `app/categories/a07_auth_failures/templates/a07_auth_failures/`.

---

## Task 1: Category Scaffold + Models + Session Store + Example 1 (No Rate Limiting Enables Brute Force)

**Files:**
- Create: `app/categories/a07_auth_failures/__init__.py`
- Create: `app/categories/a07_auth_failures/models.py`
- Create: `app/categories/a07_auth_failures/seed.py`
- Create: `app/categories/a07_auth_failures/session_store.py`
- Create: `app/categories/a07_auth_failures/routes.py`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/overview.html`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/account.html`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/brute_force_login.html`
- Modify: `app/__init__.py`
- Test: `tests/test_a07_brute_force_login.py`

**Interfaces:**
- Produces: Blueprint `a07_bp` at `url_prefix="/a07"`. `AuthSession` model
  (`id` [str, primary key], `username` [str, nullable], `mfa_verified`
  [bool], `created_at` [datetime]). `A07Account` model (`id`, `username`
  [unique], `password_hash`). `session_store.get_or_create_session()` →
  returns an `AuthSession` row, creating and committing one if needed.
  `session_store.SID_COOKIE` = `"a07_session_id"`. `routes._render(name,
  session_row, **ctx)` and `routes._redirect(endpoint, session_row,
  **kwargs)` helper functions — every later task's routes use these two
  helpers to guarantee the session cookie is always set on the response.
  `CategoryNav(id="a07_auth_failures", ...)` appended to
  `app.core.nav.CATEGORIES`, `seed_fn=seed_a07_accounts`, with one
  `ExampleNav(id="brute-force-login", ...)` so far.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a07_brute_force_login.py`:

```python
from app.core.seed import seed_database


def test_brute_force_login_rejects_wrong_password(app, client):
    seed_database(app)
    response = client.post(
        "/a07/customer-login", data={"username": "dana", "password": "wrong-guess"}
    )
    assert response.status_code == 200
    assert b"Invalid username or password" in response.data


def test_brute_force_login_accepts_correct_password(app, client):
    seed_database(app)
    response = client.post(
        "/a07/customer-login",
        data={"username": "dana", "password": "welcome1"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Logged in as" in response.data
    assert b"dana" in response.data


def test_brute_force_login_has_no_rate_limiting(app, client):
    seed_database(app)
    # 20 consecutive wrong-password attempts against the same username --
    # every single one must return the normal "invalid" response, never a
    # 429, a lockout message, or any other sign of throttling.
    for _ in range(20):
        response = client.post(
            "/a07/customer-login", data={"username": "dana", "password": "wrong-guess"}
        )
        assert response.status_code == 200
        assert b"Invalid username or password" in response.data
    # immediately after 20 failed attempts, the correct password still
    # works on the very next try -- proving nothing was ever locked out
    response = client.post(
        "/a07/customer-login",
        data={"username": "dana", "password": "welcome1"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Logged in as" in response.data


def test_brute_force_login_link_appears_in_overview_once_registered(client):
    response = client.get("/a07/")
    assert response.status_code == 200
    assert b"No Rate Limiting Enables Brute Force" in response.data
    assert b'href="/a07/customer-login"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a07_brute_force_login.py -v`
Expected: FAIL — 404 (no route/blueprint exists yet).

- [ ] **Step 3: Create the models module**

Create `app/categories/a07_auth_failures/models.py`:

```python
from datetime import datetime

from app.extensions import db


class A07Account(db.Model):
    __tablename__ = "a07_accounts"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class AuthSession(db.Model):
    __tablename__ = "a07_auth_sessions"

    id = db.Column(db.String(32), primary_key=True)
    username = db.Column(db.String(80), nullable=True)
    mfa_verified = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
```

- [ ] **Step 4: Create the seed module**

Create `app/categories/a07_auth_failures/seed.py`:

```python
from werkzeug.security import generate_password_hash

from app.categories.a07_auth_failures.models import A07Account
from app.extensions import db

# "dana" is the single-target account for the brute-force example.
# "morgan"/"priya"/"theo" are the multi-account set for the
# credential-stuffing example (Task 2) -- seeded together here so a
# single seed_fn call sets up every A07 example's account data at once.
SEED_ACCOUNTS = [
    ("dana", "welcome1"),
    ("morgan", "Summer2023!"),
    ("priya", "letmein123"),
    ("theo", "qwerty1!"),
]


def seed_a07_accounts():
    if A07Account.query.count() == 0:
        for username, password in SEED_ACCOUNTS:
            db.session.add(
                A07Account(
                    username=username,
                    password_hash=generate_password_hash(password, method="pbkdf2:sha256"),
                )
            )
        db.session.commit()
```

- [ ] **Step 5: Create the session store module**

Create `app/categories/a07_auth_failures/session_store.py`:

```python
import secrets
from datetime import datetime

from flask import request

from app.categories.a07_auth_failures.models import AuthSession
from app.extensions import db

SID_COOKIE = "a07_session_id"


def get_or_create_session():
    # VULNERABLE: resolves the session id from a URL query parameter as an
    # alternative to the cookie, and ADOPTS any client-supplied value as a
    # real session if it doesn't already exist -- rather than only
    # trusting ids the server itself minted. This exact logic was
    # live-verified during brainstorming: it's what makes both the
    # session-in-url and session-fixation examples genuinely work.
    sid = request.args.get("sid") or request.cookies.get(SID_COOKIE)
    if sid is None:
        sid = secrets.token_hex(16)
    session_row = db.session.get(AuthSession, sid)
    if session_row is None:
        session_row = AuthSession(id=sid, username=None, mfa_verified=False, created_at=datetime.utcnow())
        db.session.add(session_row)
        db.session.commit()
    return session_row
```

- [ ] **Step 6: Create the blueprint package**

Create `app/categories/a07_auth_failures/__init__.py`:

```python
from flask import Blueprint

a07_bp = Blueprint(
    "a07_auth_failures", __name__, template_folder="templates", url_prefix="/a07"
)

from app.categories.a07_auth_failures import routes  # noqa: E402,F401
from app.categories.a07_auth_failures.seed import seed_a07_accounts  # noqa: E402
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a07_auth_failures",
        short_id="A07",
        title="Identification and Authentication Failures",
        blurb="Broken login protections and session-lifecycle handling that let attackers impersonate real users.",
        blueprint_name="a07_auth_failures",
        overview_endpoint="a07_auth_failures.overview",
        examples=[
            ExampleNav(
                id="brute-force-login",
                title="No Rate Limiting Enables Brute Force",
                group="Brute Force & Credential Stuffing",
                difficulty="Easy",
                endpoint="a07_auth_failures.brute_force_login",
            ),
        ],
        seed_fn=seed_a07_accounts,
    )
)
```

- [ ] **Step 7: Create the routes module**

Create `app/categories/a07_auth_failures/routes.py`:

```python
from flask import make_response, redirect, render_template, request, url_for
from werkzeug.security import check_password_hash

from app.categories.a07_auth_failures import a07_bp
from app.categories.a07_auth_failures.models import A07Account
from app.categories.a07_auth_failures.session_store import SID_COOKIE, get_or_create_session
from app.extensions import db


def _render(template_name, session_row, **context):
    resp = make_response(render_template(template_name, session_row=session_row, **context))
    resp.set_cookie(SID_COOKIE, session_row.id)
    return resp


def _redirect(endpoint, session_row, **kwargs):
    resp = make_response(redirect(url_for(endpoint, **kwargs)))
    resp.set_cookie(SID_COOKIE, session_row.id)
    return resp


@a07_bp.route("/")
def overview():
    return render_template("a07_auth_failures/overview.html")


@a07_bp.route("/account")
def account():
    session_row = get_or_create_session()
    return _render("a07_auth_failures/account.html", session_row)


@a07_bp.route("/customer-login", methods=["GET", "POST"])
def brute_force_login():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        account_row = A07Account.query.filter_by(username=username).first()
        # VULNERABLE: no rate limiting, no lockout, no delay -- unlimited
        # login attempts against any username, forever.
        if account_row and check_password_hash(account_row.password_hash, password):
            session_row.username = account_row.username
            db.session.commit()
            return _redirect("a07_auth_failures.account", session_row)
        error = "Invalid username or password."
    return _render("a07_auth_failures/brute_force_login.html", session_row, error=error)
```

- [ ] **Step 8: Create the overview template**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/overview.html`:

```html
{% extends "core/overview_base.html" %}
{% set category_short_id = "A07" %}
{% set category_title = "Identification and Authentication Failures" %}
{% block title %}A07: Identification and Authentication Failures{% endblock %}

{% block what_it_is %}
<p>
  Identification and Authentication Failures cover everything that can go
  wrong in confirming who a user is and keeping that identity attached to
  the right requests afterward — logins with no protection against
  automated guessing, session identifiers that leak or never expire, and
  second-factor checks that can simply be skipped.
</p>
{% endblock %}

{% block why_it_matters %}
<p>
  Authentication is the foundation every other access decision rests on —
  if an attacker can become "you" without your password, every other
  control in the app (access checks, audit logs, authorization) is
  reasoning about the wrong identity from that point forward.
</p>
{% endblock %}

{% block how_exploited %}
<p>
  Attackers script unlimited login attempts when nothing stops them,
  reuse breached username/password pairs across unrelated sites at scale,
  and — once a session identifier itself becomes the weak point — never
  need a password at all: a leaked, reused, or unexpired session id is a
  complete substitute for one.
</p>
{% endblock %}

{% block attack_flow_diagram %}
sequenceDiagram
    participant Attacker
    participant App as Vulnerable App
    participant Victim
    Attacker->>App: Unlimited login attempts, or a planted session id
    Note over App: No rate limiting, no lockout, no session-id rotation on login, no server-side logout
    Victim->>App: Logs in normally (possibly using the attacker's planted id)
    App-->>Attacker: A working session, no password ever required
{% endblock %}

{% block real_world_impact %}
<p>
  Real incidents in this category include large-scale credential-stuffing
  campaigns against sites with no login throttling, and session-fixation
  attacks that hand an attacker a fully authenticated session without ever
  learning the victim's password.
</p>
{% endblock %}

{% block vulnerable_code %}account = Account.query.filter_by(username=username).first()
if account and check_password_hash(account.password_hash, password):
    log_in(account)
# no attempt counter, no lockout, no delay -- runs exactly the same on
# attempt 1 and attempt 10,000
{% endblock %}

{% block secure_code %}# track failed attempts per username/IP, lock out or delay after a
# threshold, and always mint a brand-new session id on successful login
if too_many_recent_failures(username):
    abort(429)
account = Account.query.filter_by(username=username).first()
if account and check_password_hash(account.password_hash, password):
    log_in(account)  # log_in() rotates the session id internally
{% endblock %}
```

- [ ] **Step 9: Create the account utility template**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/account.html`:

```html
{% extends "core/base.html" %}
{% block title %}Account — A07{% endblock %}

{% block content %}
<h1>Account</h1>
{% if session_row.username %}
<p>Logged in as: <strong>{{ session_row.username }}</strong></p>
{% else %}
<p>Not logged in.</p>
{% endif %}
<p>Your current session ID: <code>{{ session_row.id }}</code></p>
<form method="post" action="{{ url_for('a07_auth_failures.logout') }}">
  <button type="submit" class="btn btn-outline-secondary btn-sm">Log out</button>
</form>
{% endblock %}
```

(`logout` doesn't exist yet — this form is added now for the account page's
consistent layout across every task; Task 4 implements the `logout` route
it posts to.)

- [ ] **Step 10: Create the brute-force-login example template**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/brute_force_login.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "No Rate Limiting Enables Brute Force" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A07{% endblock %}

{% block explanation %}
<p>
  This "Customer Login" page checks a submitted username and password
  against a real, securely-hashed account — there's no SQL injection or
  logic flaw here, the check itself is correct. The vulnerability is what's
  <em>missing</em>: no limit on how many times you can guess, no delay
  between attempts, no lockout, no CAPTCHA. A script can try passwords
  exactly as fast as the server can respond.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit a handful of wrong passwords in a row for the same username and
  watch the response: every single attempt gets exactly the same instant
  "Invalid username or password" — no slowdown, no warning, no sign the
  server is tracking failures at all.
</p>
{% endblock %}

{% block exploitation %}
<p>
  The seeded account <code>dana</code> uses a common, weak password. Try
  a short wordlist of common passwords against it:
</p>
<pre><code class="language-text">password
123456
welcome1
qwerty
letmein</code></pre>
<p>
  <code>welcome1</code> succeeds. In a real attack this would be scripted
  — hundreds or thousands of guesses per minute, limited only by network
  speed, because nothing on the server ever says "slow down" or "locked
  out."
</p>
{% endblock %}

{% block vulnerable_code %}account = A07Account.query.filter_by(username=username).first()
if account and check_password_hash(account.password_hash, password):
    session_row.username = account.username
# no attempt counter, no lockout, no delay
{% endblock %}

{% block secure_code %}if too_many_recent_failures(username, request.remote_addr):
    abort(429)  # or a growing delay / CAPTCHA after N failures
account = A07Account.query.filter_by(username=username).first()
if account and check_password_hash(account.password_hash, password):
    session_row.username = account.username
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Username</label>
    <input class="form-control" type="text" name="username" value="dana">
  </div>
  <div class="mb-2">
    <label class="form-label">Password</label>
    <input class="form-control" type="password" name="password">
  </div>
  <button type="submit" class="btn btn-primary">Log in</button>
</form>
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 11: Register the blueprint in `app/__init__.py`**

Modify `app/__init__.py` — after the existing A06 registration block:

```python
    from app.categories.a06_vulnerable_components import a06_bp

    app.register_blueprint(a06_bp)
```

add:

```python

    from app.categories.a07_auth_failures import a07_bp

    app.register_blueprint(a07_bp)
```

(before the `@app.route("/healthz")` block).

- [ ] **Step 12: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_a07_brute_force_login.py -v`
Expected: PASS (4 passed)

- [ ] **Step 13: Commit**

```bash
git add app/categories/a07_auth_failures app/__init__.py tests/test_a07_brute_force_login.py
git commit -m "feat(a07): add category scaffold, AuthSession model, and brute-force-login example"
```

---

## Task 2: Example 2 (Credential Stuffing Across Multiple Accounts)

**Files:**
- Modify: `app/categories/a07_auth_failures/routes.py`
- Modify: `app/categories/a07_auth_failures/__init__.py`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/credential_stuffing.html`
- Test: `tests/test_a07_credential_stuffing.py`

**Interfaces:**
- Consumes: `a07_bp`, `_render`/`_redirect` helpers, `get_or_create_session()`
  from Task 1. The `morgan`/`priya`/`theo` accounts seeded in Task 1's
  `seed.py` (no seed changes needed this task).
- Produces: Route endpoint `a07_auth_failures.credential_stuffing` →
  `GET/POST /a07/loyalty-portal-login`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a07_credential_stuffing.py`:

```python
from app.core.seed import seed_database


def test_credential_stuffing_rejects_wrong_password(app, client):
    seed_database(app)
    response = client.post(
        "/a07/loyalty-portal-login", data={"username": "morgan", "password": "wrong"}
    )
    assert response.status_code == 200
    assert b"Invalid username or password" in response.data


def test_credential_stuffing_accepts_correct_pairs_across_accounts(app, client):
    seed_database(app)
    combo_list = [
        ("morgan", "Summer2023!"),
        ("priya", "letmein123"),
        ("theo", "qwerty1!"),
    ]
    for username, password in combo_list:
        response = client.post(
            "/a07/loyalty-portal-login",
            data={"username": username, "password": password},
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert b"Logged in as" in response.data
        assert username.encode() in response.data


def test_credential_stuffing_has_no_rate_limiting_across_many_attempts(app, client):
    seed_database(app)
    # A stuffing run tries many username:password pairs in a row --
    # simulate 15 wrong guesses across different usernames, then confirm
    # a correct pair still works immediately afterward.
    for i in range(15):
        client.post(
            "/a07/loyalty-portal-login",
            data={"username": f"nonexistent{i}", "password": "guess"},
        )
    response = client.post(
        "/a07/loyalty-portal-login",
        data={"username": "theo", "password": "qwerty1!"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Logged in as" in response.data


def test_credential_stuffing_link_appears_in_overview_once_registered(client):
    response = client.get("/a07/")
    assert response.status_code == 200
    assert b"Credential Stuffing Across Multiple Accounts" in response.data
    assert b'href="/a07/loyalty-portal-login"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a07_credential_stuffing.py -v`
Expected: FAIL — 404 (no route yet).

- [ ] **Step 3: Add the route**

Modify `app/categories/a07_auth_failures/routes.py` — after the
`brute_force_login` route, add:

```python


@a07_bp.route("/loyalty-portal-login", methods=["GET", "POST"])
def credential_stuffing():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        account_row = A07Account.query.filter_by(username=username).first()
        # VULNERABLE: the exact same unprotected check as customer-login,
        # reused against a different set of seeded accounts -- proving
        # the missing protection isn't specific to one login form.
        if account_row and check_password_hash(account_row.password_hash, password):
            session_row.username = account_row.username
            db.session.commit()
            return _redirect("a07_auth_failures.account", session_row)
        error = "Invalid username or password."
    return _render("a07_auth_failures/credential_stuffing.html", session_row, error=error)
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a07_auth_failures/__init__.py` — in the
`examples=[...]` list, after the `brute-force-login` entry, add:

```python
            ExampleNav(
                id="credential-stuffing",
                title="Credential Stuffing Across Multiple Accounts",
                group="Brute Force & Credential Stuffing",
                difficulty="Medium",
                endpoint="a07_auth_failures.credential_stuffing",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/credential_stuffing.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Credential Stuffing Across Multiple Accounts" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A07{% endblock %}

{% block explanation %}
<p>
  This "Loyalty Rewards Portal" login is a different page, a different
  brand, a different set of accounts — but the exact same unprotected
  login check as the "Customer Login" example. Three accounts here each
  reuse a password that's appeared in real public breach dumps. Credential
  stuffing isn't guessing a password from scratch — it's trying pairs of
  <em>already-known, already-breached</em> username/password combinations
  across as many accounts and services as possible, betting on password
  reuse.
</p>
{% endblock %}

{% block detect %}
<p>
  Just like the brute-force example, submit a wrong password and note that
  nothing throttles or blocks you — and that's true no matter which
  username you try it against, one after another.
</p>
{% endblock %}

{% block exploitation %}
<p>Try each of these known username:password pairs in turn:</p>
<pre><code class="language-text">morgan:Summer2023!
priya:letmein123
theo:qwerty1!</code></pre>
<p>
  All three succeed. Real credential-stuffing lists run to millions of
  breached pairs harvested from unrelated sites, tried automatically
  against a target's login form — this is that exact pattern at a
  demonstration scale, against the exact same missing protection as the
  single-account brute-force example.
</p>
{% endblock %}

{% block vulnerable_code %}account = A07Account.query.filter_by(username=username).first()
if account and check_password_hash(account.password_hash, password):
    session_row.username = account.username
# identical unprotected check as the brute-force example -- reused here
# against multiple accounts, which is exactly what makes stuffing viable
{% endblock %}

{% block secure_code %}if too_many_recent_failures(username, request.remote_addr):
    abort(429)
account = A07Account.query.filter_by(username=username).first()
if account and check_password_hash(account.password_hash, password):
    session_row.username = account.username
# rate limiting per-username AND per-IP stops stuffing at volume, not
# just repeated guessing against one account
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
  <button type="submit" class="btn btn-primary">Log in</button>
</form>
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a07_credential_stuffing.py -v`
Expected: PASS (4 passed)

- [ ] **Step 7: Commit**

```bash
git add app/categories/a07_auth_failures tests/test_a07_credential_stuffing.py
git commit -m "feat(a07): add credential-stuffing example"
```

---

## Task 3: Example 3 (Session Identifier Exposed in URL)

**Files:**
- Modify: `app/categories/a07_auth_failures/routes.py`
- Modify: `app/categories/a07_auth_failures/__init__.py`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/session_in_url.html`
- Test: `tests/test_a07_session_in_url.py`

**Interfaces:**
- Consumes: `a07_bp`, `_render`, `get_or_create_session()` from Task 1;
  `account` route from Task 1.
- Produces: Route endpoint `a07_auth_failures.share_session_link` →
  `GET /a07/share-session-link`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a07_session_in_url.py`:

```python
from app.core.seed import seed_database


def test_share_session_link_page_renders(app, client):
    seed_database(app)
    response = client.get("/a07/share-session-link")
    assert response.status_code == 200
    assert b"share_url" not in response.data  # sanity: no raw Jinja leaked
    assert b"sid=" in response.data


def test_session_id_in_url_alone_authenticates_with_no_cookie_at_all(app, client):
    seed_database(app)

    client.post("/a07/customer-login", data={"username": "dana", "password": "welcome1"})
    share_response = client.get("/a07/share-session-link")
    body = share_response.data.decode()
    start = body.index("/a07/account?sid=")
    end = body.index('"', start)
    share_url = body[start:end]
    assert "sid=" in share_url

    # Drop every cookie this client is holding, then visit ONLY the URL --
    # no cookie interaction of any kind, proving the URL parameter alone
    # is a complete, standalone credential.
    client.delete_cookie("a07_session_id")
    response = client.get(share_url)
    assert response.status_code == 200
    assert b"Logged in as" in response.data
    assert b"dana" in response.data


def test_session_in_url_link_appears_in_overview_once_registered(client):
    response = client.get("/a07/")
    assert response.status_code == 200
    assert b"Session Identifier Exposed in URL" in response.data
    assert b'href="/a07/share-session-link"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a07_session_in_url.py -v`
Expected: FAIL — 404 (no route yet).

- [ ] **Step 3: Add the route**

Modify `app/categories/a07_auth_failures/routes.py` — after the
`credential_stuffing` route, add:

```python


@a07_bp.route("/share-session-link")
def share_session_link():
    session_row = get_or_create_session()
    share_url = url_for("a07_auth_failures.account", sid=session_row.id)
    return _render("a07_auth_failures/session_in_url.html", session_row, share_url=share_url)
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a07_auth_failures/__init__.py` — in the
`examples=[...]` list, after the `credential-stuffing` entry, add:

```python
            ExampleNav(
                id="session-in-url",
                title="Session Identifier Exposed in URL",
                group="Session Identity & Lifecycle",
                difficulty="Easy",
                endpoint="a07_auth_failures.share_session_link",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/session_in_url.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Session Identifier Exposed in URL" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A07{% endblock %}

{% block explanation %}
<p>
  This "Get a shareable link" feature is meant to let you continue your
  session on another device — but it does that by putting the live session
  identifier directly into a URL, instead of relying only on the cookie.
  A URL containing an active session id is a complete, standalone
  credential: anyone who ever sees that URL is logged in as you, full
  stop, no cookie required.
</p>
{% endblock %}

{% block detect %}
<p>
  Log in first (via either login example in this category), then visit
  this page and look at the generated link — the session id appears in
  plain sight as a <code>?sid=</code> query parameter.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Log in via <a href="{{ url_for('a07_auth_failures.brute_force_login') }}">Customer Login</a>.</li>
  <li>Return to this page and copy the generated shareable link.</li>
  <li>Open that exact URL in a completely different browser, or with your
      cookies cleared — no login form, no cookie, just the URL alone. You
      land on the account page already authenticated.</li>
</ol>
<p>
  URLs end up in browser history, proxy and server access logs,
  <code>Referer</code> headers sent to any third-party resource linked
  from the page, and screenshots shared for support requests — every one
  of those is now a session-hijacking vector once a valid session id can
  travel as a URL parameter instead of staying confined to a cookie.
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/share-session-link")
def share_session_link():
    session_row = get_or_create_session()
    share_url = url_for("account", sid=session_row.id)
    return render_template("session_in_url.html", share_url=share_url)

# elsewhere: the session id is accepted from a URL query param at all
sid = request.args.get("sid") or request.cookies.get(SID_COOKIE)
{% endblock %}

{% block secure_code %}# never accept a session id from anywhere but the cookie -- no ?sid=
# fallback, no "shareable link" feature built on the raw session id at all
sid = request.cookies.get(SID_COOKIE)
{% endblock %}

{% block live_example %}
<p>Your shareable link (this session's raw identifier, embedded in a URL):</p>
<p><a href="{{ share_url }}" id="share-link">{{ share_url }}</a></p>
<a href="{{ url_for('a07_auth_failures.account') }}" class="btn btn-outline-secondary btn-sm">Go to Account</a>
{% endblock %}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a07_session_in_url.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Commit**

```bash
git add app/categories/a07_auth_failures tests/test_a07_session_in_url.py
git commit -m "feat(a07): add session-identifier-in-url example"
```

---

## Task 4: Example 4 (Session Not Invalidated on Logout)

**Files:**
- Modify: `app/categories/a07_auth_failures/routes.py`
- Modify: `app/categories/a07_auth_failures/__init__.py`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/session_survives_logout.html`
- Test: `tests/test_a07_session_survives_logout.py`

**Interfaces:**
- Consumes: `a07_bp`, `_render`, `SID_COOKIE`, `get_or_create_session()`
  from Task 1.
- Produces: Route endpoint `a07_auth_failures.logout` → `POST
  /a07/logout` (referenced by `account.html`'s logout form since Task 1,
  now implemented). Route endpoint
  `a07_auth_failures.session_survives_logout` → `GET
  /a07/session-survives-logout`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a07_session_survives_logout.py`:

```python
from app.core.seed import seed_database


def test_logout_clears_the_callers_own_cookie(app, client):
    seed_database(app)
    client.post("/a07/customer-login", data={"username": "dana", "password": "welcome1"})
    client.post("/a07/logout")
    response = client.get("/a07/account")
    assert b"Not logged in" in response.data


def test_old_session_id_survives_logout_for_a_separate_holder(app, client):
    seed_database(app)
    client.post("/a07/customer-login", data={"username": "dana", "password": "welcome1"})
    account_response = client.get("/a07/account")
    body = account_response.data.decode()
    start = body.index("<code>") + len("<code>")
    end = body.index("</code>", start)
    old_sid = body[start:end]

    client.post("/a07/logout")
    # The legitimate holder's own client now sees "not logged in" (its
    # cookie was cleared) -- but a SEPARATE request presenting a manually
    # preserved copy of the old id must still work, proving the
    # server-side record was never actually invalidated.
    response = client.get("/a07/account", headers={"Cookie": f"a07_session_id={old_sid}"})
    assert b"Logged in as" in response.data
    assert b"dana" in response.data


def test_session_survives_logout_link_appears_in_overview_once_registered(client):
    response = client.get("/a07/")
    assert response.status_code == 200
    assert b"Session Not Invalidated on Logout" in response.data
    assert b'href="/a07/session-survives-logout"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a07_session_survives_logout.py -v`
Expected: FAIL — `/a07/logout` doesn't exist yet (404).

- [ ] **Step 3: Add the routes**

Modify `app/categories/a07_auth_failures/routes.py` — after the
`share_session_link` route, add:

```python


@a07_bp.route("/logout", methods=["POST"])
def logout():
    # VULNERABLE: only clears the CLIENT's cookie -- the server-side
    # AuthSession row is never deleted, so a separately-held copy of the
    # old id keeps working indefinitely.
    resp = make_response(redirect(url_for("a07_auth_failures.session_survives_logout")))
    resp.set_cookie(SID_COOKIE, "", expires=0)
    return resp


@a07_bp.route("/session-survives-logout")
def session_survives_logout():
    session_row = get_or_create_session()
    return _render("a07_auth_failures/session_survives_logout.html", session_row)
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a07_auth_failures/__init__.py` — in the
`examples=[...]` list, after the `session-in-url` entry, add:

```python
            ExampleNav(
                id="session-survives-logout",
                title="Session Not Invalidated on Logout",
                group="Session Identity & Lifecycle",
                difficulty="Medium",
                endpoint="a07_auth_failures.session_survives_logout",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/session_survives_logout.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Session Not Invalidated on Logout" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A07{% endblock %}

{% block explanation %}
<p>
  Clicking "Log out" clears the session cookie in your own browser — but
  it never touches the corresponding session record on the server. If
  anyone else ever obtained a separate copy of that same session id before
  you logged out (a shared computer, a captured request, the URL-exposure
  bug in this category), your "logout" does absolutely nothing to stop
  them from continuing to use it.
</p>
{% endblock %}

{% block detect %}
<p>
  Log in, note the raw session ID shown on the
  <a href="{{ url_for('a07_auth_failures.account') }}">Account</a> page,
  then log out. Your own browser correctly shows "Not logged in" — but
  that alone doesn't prove the session was actually destroyed server-side,
  only that your cookie was cleared.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Log in via <a href="{{ url_for('a07_auth_failures.brute_force_login') }}">Customer Login</a>.</li>
  <li>Visit <a href="{{ url_for('a07_auth_failures.account') }}">Account</a> and copy the
      "Your current session ID" value.</li>
  <li>Click "Log out" on that page.</li>
  <li>From a terminal, replay a request carrying the <em>old</em>, copied
      session id directly — no login form involved at all:
      <pre><code class="language-bash">curl -b "a07_session_id=&lt;the copied id&gt;" http://127.0.0.1:5001/a07/account</code></pre>
  </li>
</ol>
<p>
  It still returns "Logged in as dana." Logging out protected nothing
  except the one browser tab that clicked the button — the session itself
  was never actually invalidated.
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/logout", methods=["POST"])
def logout():
    resp = redirect(url_for("session_survives_logout"))
    resp.set_cookie(SID_COOKIE, "", expires=0)  # clears the CLIENT's cookie only
    return resp
# the AuthSession row itself is never deleted
{% endblock %}

{% block secure_code %}@app.route("/logout", methods=["POST"])
def logout():
    sid = request.cookies.get(SID_COOKIE)
    session_row = db.session.get(AuthSession, sid)
    if session_row:
        db.session.delete(session_row)  # actually invalidate server-side
        db.session.commit()
    resp = redirect(url_for("session_survives_logout"))
    resp.set_cookie(SID_COOKIE, "", expires=0)
    return resp
{% endblock %}

{% block live_example %}
<p>Try it (see the Exploitation steps above):</p>
<a href="{{ url_for('a07_auth_failures.account') }}" class="btn btn-outline-secondary btn-sm">Go to Account</a>
{% endblock %}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a07_session_survives_logout.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Commit**

```bash
git add app/categories/a07_auth_failures tests/test_a07_session_survives_logout.py
git commit -m "feat(a07): add logout and session-survives-logout example"
```

---

## Task 5: Example 5 (Session Fixation)

**Files:**
- Modify: `app/categories/a07_auth_failures/routes.py`
- Modify: `app/categories/a07_auth_failures/__init__.py`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/session_fixation.html`
- Test: `tests/test_a07_session_fixation.py`

**Interfaces:**
- Consumes: `a07_bp`, `_render`, `get_or_create_session()` from Task 1;
  `brute_force_login`/`account` routes from Task 1.
- Produces: Route endpoint `a07_auth_failures.session_fixation_demo` →
  `GET /a07/session-fixation-demo`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a07_session_fixation.py`:

```python
from app.core.seed import seed_database


def test_session_fixation_demo_page_renders(app, client):
    seed_database(app)
    response = client.get("/a07/session-fixation-demo")
    assert response.status_code == 200
    assert b"sid=attacker-planted-9f8e7d" in response.data


def test_full_session_fixation_chain(app, client):
    seed_database(app)
    planted_sid = "planted-by-attacker-1234"

    # Step 1: attacker visits with a chosen sid, gets it registered as a
    # live (unauthenticated) session.
    client.get(f"/a07/account?sid={planted_sid}")

    # Step 2: victim visits the same URL (adopting the planted id as their
    # own cookie), then logs in -- the id is NOT rotated on login.
    client.get(f"/a07/account?sid={planted_sid}")
    client.post(
        "/a07/customer-login",
        data={"username": "dana", "password": "welcome1"},
        headers={"Cookie": f"a07_session_id={planted_sid}"},
    )

    # Step 3: attacker, who never submitted any credentials, presents the
    # SAME planted sid directly and is authenticated as the victim.
    response = client.get("/a07/account", headers={"Cookie": f"a07_session_id={planted_sid}"})
    assert response.status_code == 200
    assert b"Logged in as" in response.data
    assert b"dana" in response.data


def test_session_fixation_link_appears_in_overview_once_registered(client):
    response = client.get("/a07/")
    assert response.status_code == 200
    assert b"Session Fixation" in response.data
    assert b'href="/a07/session-fixation-demo"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a07_session_fixation.py -v`
Expected: `test_session_fixation_demo_page_renders` and the overview-link
test FAIL with 404 (no route yet).
`test_full_session_fixation_chain` already PASSes — the underlying
`get_or_create_session()`/`brute_force_login`/`account` mechanics from
Task 1 already make the exploit chain itself work; this task only adds the
dedicated teaching page. That's expected and fine.

- [ ] **Step 3: Add the route**

Modify `app/categories/a07_auth_failures/routes.py` — after the
`session_survives_logout` route, add:

```python


@a07_bp.route("/session-fixation-demo")
def session_fixation_demo():
    session_row = get_or_create_session()
    return _render("a07_auth_failures/session_fixation.html", session_row)
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a07_auth_failures/__init__.py` — in the
`examples=[...]` list, after the `session-survives-logout` entry, add:

```python
            ExampleNav(
                id="session-fixation",
                title="Session Fixation",
                group="Session Identity & Lifecycle",
                difficulty="Hard",
                endpoint="a07_auth_failures.session_fixation_demo",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/session_fixation.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Session Fixation" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A07{% endblock %}

{% block explanation %}
<p>
  This is the most severe consequence of the two bugs already shown
  elsewhere in this category — accepting a session id from a URL, and
  never rotating it on login — chained into a full attack. An attacker
  doesn't need to steal a password, or even observe network traffic. They
  only need to get you to open a link <em>before</em> you log in.
</p>
{% endblock %}

{% block detect %}
<p>
  Watch what happens to the session id across a login: visit
  <a href="{{ url_for('a07_auth_failures.account') }}">Account</a>, note
  the session ID shown, then log in and check the ID again. A secure app
  would show a completely different ID after authenticating — here, it's
  identical.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Play both roles yourself to see the full chain:
</p>
<ol>
  <li><strong>As the attacker:</strong> open this link (it plants a fixed,
      attacker-chosen session id) — <a
      href="{{ url_for('a07_auth_failures.account', sid='attacker-planted-9f8e7d') }}">/a07/account?sid=attacker-planted-9f8e7d</a>.
      This is exactly the kind of link an attacker would email, message,
      or embed anywhere a victim might click it.</li>
  <li><strong>As the victim:</strong> having just opened that link (so
      your browser's cookie is now that exact planted value), log in
      normally via <a href="{{ url_for('a07_auth_failures.brute_force_login') }}">Customer Login</a>.</li>
  <li><strong>As the attacker again:</strong> from a terminal — no browser,
      no cookies, nothing but the id the attacker chose in step 1 — replay:
      <pre><code class="language-bash">curl -b "a07_session_id=attacker-planted-9f8e7d" http://127.0.0.1:5001/a07/account</code></pre>
  </li>
</ol>
<p>
  It returns "Logged in as dana." The attacker is now fully authenticated
  as the victim, having never seen a password, a cookie theft, or any
  network interception at all — only a single link click by the victim,
  before they ever logged in.
</p>
{% endblock %}

{% block vulnerable_code %}sid = request.args.get("sid") or request.cookies.get(SID_COOKIE)
if sid is None:
    sid = secrets.token_hex(16)
session_row = AuthSession.query.get(sid) or AuthSession(id=sid)  # ADOPTS any id
# ...later, on successful login...
session_row.username = account.username  # same id, never rotated
{% endblock %}

{% block secure_code %}# never accept a session id from a URL at all
sid = request.cookies.get(SID_COOKIE)
# ...on successful login, always mint a brand new id, discarding
# whatever pre-auth id (fixed or not) was previously in use...
if old_session_row:
    db.session.delete(old_session_row)
new_sid = secrets.token_hex(16)
new_session = AuthSession(id=new_sid, username=account.username)
db.session.add(new_session)
resp.set_cookie(SID_COOKIE, new_sid)
{% endblock %}

{% block live_example %}
<p>Follow the three Exploitation steps above using this browser tab and a terminal.</p>
<a href="{{ url_for('a07_auth_failures.account') }}" class="btn btn-outline-secondary btn-sm">Go to Account</a>
{% endblock %}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a07_session_fixation.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Commit**

```bash
git add app/categories/a07_auth_failures tests/test_a07_session_fixation.py
git commit -m "feat(a07): add session-fixation example"
```

---

## Task 6: Example 6 (Bypassable Multi-Factor Authentication)

**Files:**
- Modify: `app/categories/a07_auth_failures/routes.py`
- Modify: `app/categories/a07_auth_failures/__init__.py`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_login.html`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_verify.html`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_dashboard.html`
- Test: `tests/test_a07_mfa_bypass.py`

**Interfaces:**
- Consumes: `a07_bp`, `_render`, `_redirect`, `get_or_create_session()`
  from Task 1; the seeded `A07Account` rows.
- Produces: Route endpoints `a07_auth_failures.mfa_login` → `GET/POST
  /a07/mfa-login`; `a07_auth_failures.mfa_verify` → `GET/POST
  /a07/mfa-verify`; `a07_auth_failures.mfa_dashboard` → `GET
  /a07/mfa-dashboard`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a07_mfa_bypass.py`:

```python
from app.core.seed import seed_database


def test_mfa_login_step_one_does_not_grant_dashboard_access_without_step_two(app, client):
    seed_database(app)
    client.post("/a07/mfa-login", data={"username": "dana", "password": "welcome1"})
    # Deliberately skip /a07/mfa-verify entirely.
    response = client.get("/a07/mfa-dashboard")
    # VULNERABLE by omission: this assertion documents the bug -- the
    # dashboard is reachable even though mfa_verify was never called.
    assert response.status_code == 200
    assert b"Welcome, dana" in response.data


def test_mfa_verify_with_correct_code_also_reaches_dashboard(app, client):
    seed_database(app)
    client.post("/a07/mfa-login", data={"username": "dana", "password": "welcome1"})
    verify_response = client.post("/a07/mfa-verify", data={"code": "482913"}, follow_redirects=True)
    assert verify_response.status_code == 200
    assert b"Welcome, dana" in verify_response.data


def test_mfa_verify_rejects_wrong_code(app, client):
    seed_database(app)
    client.post("/a07/mfa-login", data={"username": "dana", "password": "welcome1"})
    response = client.post("/a07/mfa-verify", data={"code": "000000"})
    assert response.status_code == 200
    assert b"Incorrect code" in response.data


def test_mfa_dashboard_redirects_when_never_logged_in_at_all(client):
    response = client.get("/a07/mfa-dashboard", follow_redirects=True)
    assert response.status_code == 200
    assert b"Log in" in response.data or b"Username" in response.data


def test_mfa_bypass_link_appears_in_overview_once_registered(client):
    response = client.get("/a07/")
    assert response.status_code == 200
    assert b"Bypassable Multi-Factor Authentication" in response.data
    assert b'href="/a07/mfa-login"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a07_mfa_bypass.py -v`
Expected: FAIL — 404 (no routes yet).

- [ ] **Step 3: Add the routes**

Modify `app/categories/a07_auth_failures/routes.py` — after the
`session_fixation_demo` route, add:

```python


MFA_DEMO_CODE = "482913"


@a07_bp.route("/mfa-login", methods=["GET", "POST"])
def mfa_login():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        account_row = A07Account.query.filter_by(username=username).first()
        if account_row and check_password_hash(account_row.password_hash, password):
            session_row.username = account_row.username
            session_row.mfa_verified = False
            db.session.commit()
            return _redirect("a07_auth_failures.mfa_verify", session_row)
        error = "Invalid username or password."
    return _render("a07_auth_failures/mfa_login.html", session_row, error=error)


@a07_bp.route("/mfa-verify", methods=["GET", "POST"])
def mfa_verify():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        code = request.form.get("code", "")
        if code == MFA_DEMO_CODE:
            session_row.mfa_verified = True
            db.session.commit()
            return _redirect("a07_auth_failures.mfa_dashboard", session_row)
        error = "Incorrect code."
    return _render("a07_auth_failures/mfa_verify.html", session_row, error=error, demo_code=MFA_DEMO_CODE)


@a07_bp.route("/mfa-dashboard")
def mfa_dashboard():
    session_row = get_or_create_session()
    if not session_row.username:
        return _redirect("a07_auth_failures.mfa_login", session_row)
    # VULNERABLE: only checks that a username is set on the session --
    # never checks session_row.mfa_verified, so step 2 (the code) can be
    # skipped entirely and this destination reached right after step 1.
    return _render("a07_auth_failures/mfa_dashboard.html", session_row)
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a07_auth_failures/__init__.py` — in the
`examples=[...]` list, after the `session-fixation` entry, add:

```python
            ExampleNav(
                id="mfa-bypass",
                title="Bypassable Multi-Factor Authentication",
                group="Multi-Factor Authentication Bypass",
                difficulty="Hard",
                endpoint="a07_auth_failures.mfa_login",
            ),
```

- [ ] **Step 5: Create the three templates**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_login.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Bypassable Multi-Factor Authentication" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A07{% endblock %}

{% block explanation %}
<p>
  This login has a real second factor — after your password, you're sent
  to a verification-code page before reaching the dashboard. The bug isn't
  in the password check or the code check themselves; both work correctly.
  It's that the <em>destination</em> page never actually confirms the
  second factor was completed — it only checks that step one succeeded.
</p>
{% endblock %}

{% block detect %}
<p>
  Log in with a correct password and you'll be sent to a code-entry page
  as expected — so far, so normal. The bug only becomes visible if you
  try skipping that page entirely.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Submit the correct username/password below (<code>dana</code> /
      <code>welcome1</code>).</li>
  <li>You land on the verification-code page — <strong>do not enter a
      code</strong>.</li>
  <li>Instead, navigate directly to
      <a href="{{ url_for('a07_auth_failures.mfa_dashboard') }}">the dashboard URL</a>.</li>
</ol>
<p>
  It loads anyway. The second factor was never actually enforced — the
  dashboard route only checks that a username is attached to your
  session, exactly the same check a single-factor login would use. The
  code-entry page is a real UI step with no corresponding server-side gate
  behind it.
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/mfa-dashboard")
def mfa_dashboard():
    session_row = get_or_create_session()
    if not session_row.username:
        return redirect(url_for("mfa_login"))
    # missing: `if not session_row.mfa_verified: return redirect(...)`
    return render_template("mfa_dashboard.html")
{% endblock %}

{% block secure_code %}@app.route("/mfa-dashboard")
def mfa_dashboard():
    session_row = get_or_create_session()
    if not session_row.username or not session_row.mfa_verified:
        return redirect(url_for("mfa_login"))
    return render_template("mfa_dashboard.html")
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Username</label>
    <input class="form-control" type="text" name="username" value="dana">
  </div>
  <div class="mb-2">
    <label class="form-label">Password</label>
    <input class="form-control" type="password" name="password">
  </div>
  <button type="submit" class="btn btn-primary">Log in</button>
</form>
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_verify.html`:

```html
{% extends "core/base.html" %}
{% block title %}Enter Verification Code — A07{% endblock %}

{% block content %}
<h1>Enter Verification Code</h1>
<p>
  Your code is <strong>{{ demo_code }}</strong> — shown here since this
  lab doesn't send real SMS/email.
</p>
<form method="post">
  <div class="mb-2">
    <label class="form-label">6-digit code</label>
    <input class="form-control" type="text" name="code">
  </div>
  <button type="submit" class="btn btn-primary">Verify</button>
</form>
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_dashboard.html`:

```html
{% extends "core/base.html" %}
{% block title %}Dashboard — A07{% endblock %}

{% block content %}
<h1>Dashboard</h1>
<p>Welcome, {{ session_row.username }}.</p>
<p>MFA verified on this session: <strong>{{ session_row.mfa_verified }}</strong></p>
{% endblock %}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a07_mfa_bypass.py -v`
Expected: PASS (5 passed)

- [ ] **Step 7: Commit**

```bash
git add app/categories/a07_auth_failures tests/test_a07_mfa_bypass.py
git commit -m "feat(a07): add bypassable-MFA example"
```

---

## Task 7: Final Integration — README and Overview Tests

**Files:**
- Modify: `README.md`
- Test: `tests/test_a07_overview.py`

**Interfaces:**
- Consumes: All six examples and the `CategoryNav` from Tasks 1–6.

- [ ] **Step 1: Write the overview/nav tests**

Create `tests/test_a07_overview.py`:

```python
def test_a07_overview_renders(client):
    response = client.get("/a07/")
    assert response.status_code == 200
    assert b"Identification and Authentication Failures" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a07_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a07 = next(c for c in CATEGORIES if c.id == "a07_auth_failures")
    assert a07.short_id == "A07"
    assert [e.difficulty for e in a07.examples] == [
        "Easy",
        "Medium",
        "Easy",
        "Medium",
        "Hard",
        "Hard",
    ]


def test_a07_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a07 = next(c for c in CATEGORIES if c.id == "a07_auth_failures")
    grouped = a07.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Brute Force & Credential Stuffing",
        "Session Identity & Lifecycle",
        "Multi-Factor Authentication Bypass",
    ]
    assert [e.id for e in grouped[0][1]] == ["brute-force-login", "credential-stuffing"]
    assert [e.id for e in grouped[1][1]] == [
        "session-in-url",
        "session-survives-logout",
        "session-fixation",
    ]
    assert [e.id for e in grouped[2][1]] == ["mfa-bypass"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a07_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a07/")
    body = response.data.decode()
    assert "Brute Force &amp; Credential Stuffing" in body
    assert "Session Identity &amp; Lifecycle" in body
    assert "Multi-Factor Authentication Bypass" in body
```

Note: the group names "Brute Force & Credential Stuffing" and "Session
Identity & Lifecycle" contain a literal `&`, which Jinja2's default
autoescaping renders as `&amp;` in HTML output — assert against the
escaped form, matching the exact pattern A05's group-heading test
established for the same reason.

- [ ] **Step 2: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a07_overview.py -v`
Expected: PASS (4 passed)

- [ ] **Step 3: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all tests pass. Baseline before this plan was 308 (post-A06,
post-UI-changes). This plan's new tests: 4 (Task 1) + 4 (Task 2) + 3
(Task 3) + 3 (Task 4) + 3 (Task 5) + 5 (Task 6) + 4 (Task 7) = 26 new
tests → 334 total.

- [ ] **Step 4: Update README.md's intro paragraph**

Modify `README.md` — replace the "Currently implemented" paragraph
(currently ending "...and **A06 Vulnerable and Outdated Components**
(component version disclosure, outdated JS library detection, jQuery DOM
XSS via a real CVE, jQuery XSS chained to session-token theft, Lodash
prototype pollution via a real CVE, prototype pollution bypassing a
client-side access check). Remaining categories (A07–A10) are tracked
separately and follow the same pattern.") with the same text up through
A06, followed by:

```markdown
, and **A07 Identification and Authentication Failures** (no rate limiting
enables brute force, credential stuffing across multiple accounts, session
identifier exposed in a URL, session not invalidated on logout, full
session fixation, bypassable multi-factor authentication). Remaining
categories (A08–A10) are tracked separately and follow the same pattern.
```

- [ ] **Step 5: Update README.md's category summary table**

Modify `README.md` — replace the line:

```
| A07–A10 | Planned | See `docs/superpowers/specs/2026-09-18-owasp-lab-design.md` |
```

with:

```
| A07 Identification and Authentication Failures | Implemented | No Rate Limiting Enables Brute Force (Easy), Credential Stuffing Across Multiple Accounts (Medium), Session Identifier Exposed in URL (Easy), Session Not Invalidated on Logout (Medium), Session Fixation (Hard), Bypassable Multi-Factor Authentication (Hard) |
| A08–A10 | Planned | See `docs/superpowers/specs/2026-09-18-owasp-lab-design.md` |
```

- [ ] **Step 6: Commit**

```bash
git add README.md tests/test_a07_overview.py
git commit -m "docs(a07): update README and add overview/nav tests for A07"
```

No live browser verification step is needed for this category (unlike
A05's Werkzeug-debugger/CORS mechanisms and A06's vendored-library CVEs) —
every A07 example is fully exercisable and provable through the real
Flask test client (multi-request sequences with explicit `Cookie` headers
across separate logical actors), which is exactly how every test in this
plan already proves each vulnerability. The core session mechanics
(fixation, URL-exposure, logout-non-invalidation) were live-verified
during brainstorming against a standalone spike server before this plan
was written; the plan's own tests re-prove the same mechanics against the
real integrated app.
