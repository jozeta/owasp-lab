# A03 LDAP Injection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add LDAP injection as a new vulnerability sub-type under A03, with two graduated examples (Easy password-wildcard auth bypass, Hard blind boolean data exfiltration) backed by a real LDAP server, in the established four-part content structure.

**Architecture:** A new `ldap` service (`osixia/openldap:1.5.0`) is added to `docker-compose.yml`, alongside a new pure-Python `ldap3==2.9.1` client dependency. Both examples live on the existing `a03_bp` blueprint as new routes. A small `app/categories/a03_injection/ldap_client.py` module centralizes connection creation behind one function (`get_ldap_connection()`) so tests can substitute an in-memory mock connection (mirroring how this project already substitutes SQLite for Postgres in tests) without touching route code. LDAP directory seeding is wired directly into `wsgi.py` (production-only), deliberately NOT into the existing `CategoryNav.seed_fn` mechanism — that mechanism runs during any test that calls `seed_database()` (e.g. via the `login` fixture used across A01/A02/A03 tests), and bundling a real LDAP bind attempt into it would break those existing, currently-passing tests in an unrelated part of the suite.

**Tech Stack:** Flask 3.0.3, `ldap3==2.9.1` (new dependency), `osixia/openldap:1.5.0` (new Docker service), pytest.

**Spec:** docs/superpowers/specs/2026-09-20-owasp-lab-a03-ldap-design.md

## Global Constraints

- No changes to any existing A01/A02/A04/existing-A03 route, model, or template.
- No changes to the existing `postgres` service or `DATABASE_URL` configuration — the new `ldap` service and its config are purely additive.
- The vulnerable pattern is exactly raw f-string interpolation into an LDAP filter string, in both examples — verified live (not assumed) against a real running `osixia/openldap:1.5.0` instance during the design phase, and re-verified live against the real container again in this plan's Task 3.
- `userPassword` genuinely has no substring-matching support (LDAP's `octetStringMatch` equality rule) — the Hard example's blind extraction targets the `description` attribute for this reason, not `userPassword`. Do not "simplify" this to extract `userPassword` instead — verified live that doing so would not work against a real server.
- Unit tests use `ldap3`'s `MOCK_SYNC` in-memory strategy via a `mock_ldap` pytest fixture (mirroring this project's existing SQLite-for-Postgres precedent) — no real LDAP server needed for `pytest`. `MOCK_SYNC` does NOT replicate the real server's `userPassword` no-substring-matching restriction (confirmed live to diverge) — no task in this plan writes a unit test relying on that restriction; only Task 3's Docker verification proves it against the real server.
- All Vulnerable-vs-Secure code panels use `language-python` (the shared base template's default via `code_language|default('python')`) — matching the precedent set by the SSTI sub-project for illustrative non-Python payload snippets (there is no `language-ldap` highlighter available and no established alternative in this codebase). No `{% set code_language = ... %}` override is needed anywhere in this plan.
- No HTML-entity escaping or `{% raw %}` Jinja-wrapping is needed anywhere in this plan's templates — LDAP filter metacharacters (`(`, `)`, `*`, `\`) contain no `<`, `>`, `{{`, or `{%`, so neither of this project's two standing escaping constraints apply here. Every payload in this plan's template text has been checked against both.

---

### Task 1: Infrastructure + Easy — Password-Wildcard Authentication Bypass

**Files:**
- Modify: `docker-compose.yml`
- Modify: `requirements.txt`
- Modify: `wsgi.py`
- Modify: `tests/conftest.py`
- Modify: `app/categories/a03_injection/routes.py`
- Modify: `app/categories/a03_injection/__init__.py`
- Create: `app/categories/a03_injection/ldap_client.py`
- Create: `app/categories/a03_injection/ldap_seed.py`
- Create: `app/categories/a03_injection/templates/a03_injection/directory_login.html`
- Create: `tests/test_a03_directory_login.py`
- Modify: `tests/test_a03_overview.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `ldap_client.get_ldap_connection()` (no-arg, returns a bound `ldap3.Connection`), `ldap_client.LDAP_BASE_DN`/`LDAP_ADMIN_DN`/`LDAP_ADMIN_PASSWORD` constants, the `mock_ldap` pytest fixture, and the `directory_login` route/endpoint (`a03_injection.directory_login`) — all consumed by Task 2.

- [ ] **Step 1: Add the `ldap3` dependency and the new Docker service**

In `requirements.txt`, add a new line:

```
ldap3==2.9.1
```

In `docker-compose.yml`, the current file reads:

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: lab
      POSTGRES_PASSWORD: lab
      POSTGRES_DB: owasp_lab
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U lab -d owasp_lab"]
      interval: 5s
      timeout: 5s
      retries: 10

  app:
    build: .
    env_file:
      - .env
    environment:
      DATABASE_URL: postgresql+psycopg://lab:lab@postgres:5432/owasp_lab
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "127.0.0.1:5001:5000"

volumes:
  pgdata:
```

Change it to:

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: lab
      POSTGRES_PASSWORD: lab
      POSTGRES_DB: owasp_lab
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U lab -d owasp_lab"]
      interval: 5s
      timeout: 5s
      retries: 10

  ldap:
    image: osixia/openldap:1.5.0
    environment:
      LDAP_ORGANISATION: "OWASP Lab"
      LDAP_DOMAIN: "owasp-lab.local"
      LDAP_ADMIN_PASSWORD: "admin123"
      LDAP_TLS: "false"
    healthcheck:
      test: ["CMD", "ldapwhoami", "-x", "-D", "cn=admin,dc=owasp-lab,dc=local", "-w", "admin123", "-H", "ldap://localhost:389"]
      interval: 5s
      timeout: 5s
      retries: 10
    ports:
      - "127.0.0.1:3890:389"

  app:
    build: .
    env_file:
      - .env
    environment:
      DATABASE_URL: postgresql+psycopg://lab:lab@postgres:5432/owasp_lab
      LDAP_URL: ldap://ldap:389
      LDAP_BASE_DN: dc=owasp-lab,dc=local
      LDAP_ADMIN_DN: cn=admin,dc=owasp-lab,dc=local
      LDAP_ADMIN_PASSWORD: admin123
    depends_on:
      postgres:
        condition: service_healthy
      ldap:
        condition: service_healthy
    ports:
      - "127.0.0.1:5001:5000"

volumes:
  pgdata:
```

(`LDAP_TLS: "false"` skips certificate-generation overhead at container startup — this is a local training lab, plain LDAP on localhost is appropriate, matching the app's own "never expose to an untrusted network" banner. The healthcheck uses `ldapwhoami`, verified present and working in this exact image before this plan was written.)

Install the dependency in this worktree's venv: `.venv/bin/pip install ldap3==2.9.1`

- [ ] **Step 2: Create the LDAP client module**

Create `app/categories/a03_injection/ldap_client.py`:

```python
import os

from ldap3 import Connection, Server

LDAP_URL = os.environ.get("LDAP_URL", "ldap://localhost:3890")
LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN", "dc=owasp-lab,dc=local")
LDAP_ADMIN_DN = os.environ.get("LDAP_ADMIN_DN", "cn=admin,dc=owasp-lab,dc=local")
LDAP_ADMIN_PASSWORD = os.environ.get("LDAP_ADMIN_PASSWORD", "admin123")


def get_ldap_connection():
    """Returns a fresh, bound LDAP connection. Tests monkeypatch this
    function (see the `mock_ldap` fixture in tests/conftest.py) to return
    an in-memory mock connection instead of binding to a real server."""
    server = Server(LDAP_URL)
    return Connection(server, LDAP_ADMIN_DN, LDAP_ADMIN_PASSWORD, auto_bind=True)
```

(The `LDAP_URL` default of `ldap://localhost:3890` matches this plan's Docker port mapping, for convenience when running the app outside Docker against a manually-started container during development — production always sets `LDAP_URL` via `docker-compose.yml`'s `app.environment` block, added in Step 1.)

- [ ] **Step 3: Create the LDAP seed module**

Create `app/categories/a03_injection/ldap_seed.py`:

```python
from ldap3 import BASE

from app.categories.a03_injection import ldap_client


def seed_ldap_data():
    """Idempotently seeds the LDAP directory with two accounts. Checked via
    a BASE-scope existence search on the marker entry (uid=alice) before
    creating anything, so re-running this (e.g. at every app startup) is
    safe and does not error on an already-seeded directory."""
    conn = ldap_client.get_ldap_connection()
    try:
        base_dn = ldap_client.LDAP_BASE_DN
        alice_dn = f"uid=alice,ou=people,{base_dn}"
        exists = conn.search(alice_dn, "(objectClass=*)", BASE)
        if exists and conn.entries:
            return

        conn.add(f"ou=people,{base_dn}", ["organizationalUnit"])

        conn.add(
            alice_dn,
            ["inetOrgPerson", "organizationalPerson", "person", "top"],
            {
                "cn": "Alice Example",
                "sn": "Example",
                "uid": "alice",
                "userPassword": "alice123",
                "mail": "alice@owasp-lab.local",
            },
        )

        conn.add(
            f"uid=root_admin,ou=people,{base_dn}",
            ["inetOrgPerson", "organizationalPerson", "person", "top"],
            {
                "cn": "Root Administrator",
                "sn": "Administrator",
                "uid": "root_admin",
                "userPassword": "sup3r-s3cret-ldap-admin-pw",
                "mail": "root_admin@owasp-lab.local",
                "description": "recovery-code-x7k2p9",
            },
        )
    finally:
        conn.unbind()
```

- [ ] **Step 4: Wire LDAP seeding into `wsgi.py`**

`wsgi.py` currently reads:

```python
from app import create_app
from app.core.seed import seed_database

app = create_app()
seed_database(app)
```

Change it to:

```python
from app import create_app
from app.categories.a03_injection.ldap_seed import seed_ldap_data
from app.core.seed import seed_database

app = create_app()
seed_database(app)
seed_ldap_data()
```

Do NOT wire `seed_ldap_data` into `CategoryNav.seed_fn` (A03's `seed_fn` stays exactly `seed_injection_data`, unchanged) — `seed_fn` runs during `seed_database()`, which several existing tests trigger indirectly via the `login` fixture (`tests/conftest.py`) using `TestConfig`'s in-memory SQLite. If LDAP seeding were wired into that same path, every one of those existing tests would attempt a real LDAP bind and fail — this is a deliberate design decision, not an oversight; do not "simplify" by merging the two seed paths.

- [ ] **Step 5: Add the `mock_ldap` pytest fixture**

`tests/conftest.py` currently reads:

```python
import pytest

from app import create_app
from app.config import TestConfig
from app.extensions import db


@pytest.fixture
def app():
    flask_app = create_app(TestConfig)
    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def login(app, client):
    def _login(username):
        from app.core.models import User
        from app.core.seed import seed_database

        seed_database(app)
        with app.app_context():
            user = User.query.filter_by(username=username).first()
            user_id = user.id
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
        return user_id

    return _login
```

Add this fixture at the end of the file:

```python


@pytest.fixture
def mock_ldap(monkeypatch):
    """Monkeypatches ldap_client.get_ldap_connection to return a fresh,
    pre-seeded ldap3 MOCK_SYNC in-memory connection on every call -- no
    real LDAP server needed. A fresh connection is built each call (not a
    shared/reused one) because a real Connection object cannot be
    searched again after unbind(), and each route call does its own
    bind-search-unbind cycle, matching real usage."""
    from ldap3 import MOCK_SYNC, Connection, Server

    from app.categories.a03_injection import ldap_client

    def _make_connection():
        server = Server("mock-ldap-server")
        conn = Connection(server, client_strategy=MOCK_SYNC)
        conn.strategy.add_entry(
            ldap_client.LDAP_ADMIN_DN, {"userPassword": ldap_client.LDAP_ADMIN_PASSWORD}
        )
        conn.strategy.add_entry(
            f"uid=alice,ou=people,{ldap_client.LDAP_BASE_DN}",
            {
                "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
                "cn": "Alice Example",
                "sn": "Example",
                "uid": "alice",
                "userPassword": "alice123",
                "mail": "alice@owasp-lab.local",
            },
        )
        conn.strategy.add_entry(
            f"uid=root_admin,ou=people,{ldap_client.LDAP_BASE_DN}",
            {
                "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
                "cn": "Root Administrator",
                "sn": "Administrator",
                "uid": "root_admin",
                "userPassword": "sup3r-s3cret-ldap-admin-pw",
                "mail": "root_admin@owasp-lab.local",
                "description": "recovery-code-x7k2p9",
            },
        )
        conn.bind()
        return conn

    monkeypatch.setattr(ldap_client, "get_ldap_connection", _make_connection)
```

- [ ] **Step 6: Write the failing tests**

Create `tests/test_a03_directory_login.py`:

```python
def test_directory_login_succeeds_with_correct_credentials(client, mock_ldap):
    response = client.post(
        "/a03/directory-login", data={"username": "alice", "password": "alice123"}
    )
    assert response.status_code == 200
    assert b"Alice Example" in response.data


def test_directory_login_fails_with_wrong_password(client, mock_ldap):
    response = client.post(
        "/a03/directory-login", data={"username": "alice", "password": "wrongpass"}
    )
    assert response.status_code == 200
    assert b"Invalid username or password" in response.data


def test_directory_login_wildcard_password_bypasses_authentication(client, mock_ldap):
    response = client.post(
        "/a03/directory-login", data={"username": "root_admin", "password": "*"}
    )
    assert response.status_code == 200
    assert b"Root Administrator" in response.data


def test_directory_login_secure_pattern_neutralizes_wildcard_bypass(mock_ldap):
    from ldap3 import SUBTREE
    from ldap3.utils.conv import escape_filter_chars

    from app.categories.a03_injection import ldap_client

    safe_password = escape_filter_chars("*")
    filt = f"(&(uid=root_admin)(userPassword={safe_password}))"
    conn = ldap_client.get_ldap_connection()
    conn.search(ldap_client.LDAP_BASE_DN, filt, SUBTREE, attributes=["cn"])
    entries = list(conn.entries)
    conn.unbind()
    assert entries == []


def test_directory_login_still_works_with_teaching_text_hidden(app, client, mock_ldap):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post(
        "/a03/directory-login", data={"username": "alice", "password": "alice123"}
    )
    assert response.status_code == 200
    assert b"Alice Example" in response.data
    assert b"Vulnerable vs. Secure" in response.data
    assert b"Detect" not in response.data


def test_directory_login_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"LDAP Injection" in response.data
    assert b'href="/a03/directory-login"' in response.data
```

- [ ] **Step 7: Run tests to verify they fail**

Run: `pytest tests/test_a03_directory_login.py -v`
Expected: the tests exercising `/a03/directory-login` FAIL (404 — the route doesn't exist yet). `test_directory_login_secure_pattern_neutralizes_wildcard_bypass` PASSES already (it only exercises `ldap_client`/`mock_ldap`, not the route).

- [ ] **Step 8: Add the route**

In `app/categories/a03_injection/routes.py`, the current top of the file reads:

```python
import os
import subprocess
import urllib.request

from flask import redirect, render_template, render_template_string, request, session, url_for
from lxml import etree
from sqlalchemy import text

from app.categories.a03_injection import a03_bp
from app.categories.a03_injection.models import Comment, InjectionAccount
from app.extensions import db

XXE_SECRET_PATH = os.path.join(os.path.dirname(__file__), "xxe_secret.txt")
```

Change it to:

```python
import os
import subprocess
import urllib.request

from flask import redirect, render_template, render_template_string, request, session, url_for
from ldap3 import SUBTREE
from lxml import etree
from sqlalchemy import text

from app.categories.a03_injection import a03_bp, ldap_client
from app.categories.a03_injection.models import Comment, InjectionAccount
from app.extensions import db

XXE_SECRET_PATH = os.path.join(os.path.dirname(__file__), "xxe_secret.txt")
```

Then append this route at the end of the file (after the existing `bio_preview()` route):

```python


@a03_bp.route("/directory-login", methods=["GET", "POST"])
def directory_login():
    username = ""
    result = None
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = ldap_client.get_ldap_connection()
        try:
            # VULNERABLE: raw f-string interpolation into an LDAP filter, no escaping
            filt = f"(&(uid={username})(userPassword={password}))"
            conn.search(ldap_client.LDAP_BASE_DN, filt, SUBTREE, attributes=["cn"])
            if conn.entries:
                cn = str(conn.entries[0].cn)
                result = f"Welcome, {cn}!"
            else:
                error = "Invalid username or password."
        finally:
            conn.unbind()
    return render_template(
        "a03_injection/directory_login.html", username=username, result=result, error=error
    )
```

- [ ] **Step 9: Register the nav entry**

In `app/categories/a03_injection/__init__.py`, the `examples=[...]` list currently ends with the `ssti-blacklist-bypass` entry and closes like this:

```python
            ExampleNav(
                id="ssti-blacklist-bypass",
                title="SSTI Blacklist Bypass via Profile Bio Preview",
                group="Server-Side Template Injection (SSTI)",
                difficulty="Hard",
                endpoint="a03_injection.bio_preview",
            ),
        ],
        seed_fn=seed_injection_data,
    )
)
```

Add a new entry immediately after `ssti-blacklist-bypass`, before the closing `],`:

```python
            ExampleNav(
                id="ssti-blacklist-bypass",
                title="SSTI Blacklist Bypass via Profile Bio Preview",
                group="Server-Side Template Injection (SSTI)",
                difficulty="Hard",
                endpoint="a03_injection.bio_preview",
            ),
            ExampleNav(
                id="ldap-directory-login",
                title="LDAP Auth Bypass via Company Directory Login",
                group="LDAP Injection",
                difficulty="Easy",
                endpoint="a03_injection.directory_login",
            ),
        ],
        seed_fn=seed_injection_data,
    )
)
```

- [ ] **Step 10: Create the template**

Create `app/categories/a03_injection/templates/a03_injection/directory_login.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "LDAP Auth Bypass via Company Directory Login" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This "company directory login" feature authenticates against an LDAP
  directory (the same kind of system that backs corporate single sign-on
  in many real organizations) by building a search filter directly from
  your submitted username and password with plain string interpolation:
  <code>(&(uid=USERNAME)(userPassword=PASSWORD))</code>. If the search
  returns any matching entry, the login is treated as successful. Because
  neither field is escaped, LDAP filter metacharacters you submit —
  parentheses, the wildcard <code>*</code>, and others — become part of
  the filter's actual logic instead of being treated as literal text to
  match against.
</p>
{% endblock %}

{% block detect %}
<p>
  Log in with a username you know exists (<code>alice</code>) and a
  single asterisk as the password:
</p>
<pre><code class="language-python">username: alice
password: *</code></pre>
<p>
  In LDAP filter syntax, <code>*</code> alone means "any non-empty
  value" — a presence match, not a literal asterisk character. If this
  logs you in as Alice without her real password, you've confirmed the
  filter is being built from unescaped input.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Log in with:
      <pre><code class="language-python">username: root_admin
password: *</code></pre>
  </li>
  <li>You're logged in as the Root Administrator account — a privileged
      account whose real password you never supplied or even guessed.
      The filter the server actually evaluates is
      <code>(&(uid=root_admin)(userPassword=*))</code>: "match any entry
      with uid root_admin that has <em>some</em> password set" — which
      root_admin, like every real account, does.</li>
</ol>
<p>
  LDAP injection auth bypass is a well-documented real-world class of
  vulnerability, historically affecting any application that
  authenticates against Active Directory or another LDAP-backed
  directory by building filters through string concatenation — this
  exact pattern (a wildcard password bypassing a naive
  <code>(&(uid=X)(userPassword=Y))</code> check) has shown up repeatedly
  in enterprise login forms, VPN portals, and internal admin tools that
  delegate authentication to a corporate directory without escaping user
  input first.
</p>
{% endblock %}

{% block vulnerable_code %}filt = f"(&(uid={username})(userPassword={password}))"
conn.search(base_dn, filt, SUBTREE, attributes=["cn"])
{% endblock %}

{% block secure_code %}from ldap3.utils.conv import escape_filter_chars

safe_username = escape_filter_chars(username)
safe_password = escape_filter_chars(password)
filt = f"(&(uid={safe_username})(userPassword={safe_password}))"
conn.search(base_dn, filt, SUBTREE, attributes=["cn"])
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Username</label>
    <input type="text" class="form-control" name="username" value="{{ username }}">
  </div>
  <div class="mb-2">
    <label class="form-label">Password</label>
    <input type="text" class="form-control" name="password">
  </div>
  <button type="submit" class="btn btn-primary">Log in</button>
</form>
{% if result %}
<p class="mt-3">{{ result }}</p>
{% endif %}
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 11: Run the tests to verify they pass**

Run: `pytest tests/test_a03_directory_login.py -v`
Expected: all 6 PASS.

- [ ] **Step 12: Update the hardcoded nav-list tests**

Registering the new `ldap-directory-login` entry breaks two pre-existing tests in `tests/test_a03_overview.py` that hardcode the full A03 nav-entry/group lists — the same pattern XXE's and SSTI's implementations hit and fixed. Open `tests/test_a03_overview.py` and make these two changes:

In `test_a03_registered_in_nav`, change:

```python
    assert [e.difficulty for e in a03.examples] == [
        "Easy",
        "Medium",
        "Hard",
        "Medium",
        "Hard",
        "Hard",
        "Easy",
        "Hard",
        "Easy",
        "Hard",
    ]
```

to:

```python
    assert [e.difficulty for e in a03.examples] == [
        "Easy",
        "Medium",
        "Hard",
        "Medium",
        "Hard",
        "Hard",
        "Easy",
        "Hard",
        "Easy",
        "Hard",
        "Easy",
    ]
```

In `test_a03_examples_grouped_by_vulnerability_subtype`, change:

```python
    assert [name for name, _ in grouped] == [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "OS Command Injection",
        "XML External Entity Injection (XXE)",
        "Server-Side Template Injection (SSTI)",
    ]
    assert [e.id for e in grouped[0][1]] == ["sqli-login", "union-exfiltration", "blind-sqli"]
    assert [e.id for e in grouped[1][1]] == ["reflected-xss", "stored-xss"]
    assert [e.id for e in grouped[2][1]] == ["command-injection"]
    assert [e.id for e in grouped[3][1]] == ["xml-import", "xxe-ssrf"]
    assert [e.id for e in grouped[4][1]] == ["ssti-email-preview", "ssti-blacklist-bypass"]
```

to:

```python
    assert [name for name, _ in grouped] == [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "OS Command Injection",
        "XML External Entity Injection (XXE)",
        "Server-Side Template Injection (SSTI)",
        "LDAP Injection",
    ]
    assert [e.id for e in grouped[0][1]] == ["sqli-login", "union-exfiltration", "blind-sqli"]
    assert [e.id for e in grouped[1][1]] == ["reflected-xss", "stored-xss"]
    assert [e.id for e in grouped[2][1]] == ["command-injection"]
    assert [e.id for e in grouped[3][1]] == ["xml-import", "xxe-ssrf"]
    assert [e.id for e in grouped[4][1]] == ["ssti-email-preview", "ssti-blacklist-bypass"]
    assert [e.id for e in grouped[5][1]] == ["ldap-directory-login"]
```

- [ ] **Step 13: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (184 existing + 6 new = 190)

- [ ] **Step 14: Commit**

```bash
git add docker-compose.yml requirements.txt wsgi.py tests/conftest.py \
  app/categories/a03_injection/ldap_client.py app/categories/a03_injection/ldap_seed.py \
  app/categories/a03_injection/routes.py app/categories/a03_injection/__init__.py \
  app/categories/a03_injection/templates/a03_injection/directory_login.html \
  tests/test_a03_directory_login.py tests/test_a03_overview.py
git commit -m "feat: add A03 LDAP injection infrastructure and auth-bypass example (Easy)"
```

---

### Task 2: Hard — Blind Boolean Data Exfiltration via Directory Search

**Files:**
- Modify: `app/categories/a03_injection/routes.py`
- Modify: `app/categories/a03_injection/__init__.py`
- Create: `app/categories/a03_injection/templates/a03_injection/directory_search.html`
- Create: `tests/test_a03_directory_search.py`
- Modify: `tests/test_a03_overview.py`

**Interfaces:**
- Consumes: `ldap_client.get_ldap_connection()`/`LDAP_BASE_DN` (already added in Task 1), the `mock_ldap` fixture (already added in Task 1), the `SUBTREE` import (already added to `routes.py` in Task 1).
- Produces: nothing consumed by later tasks — this is the last functional change in this plan.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a03_directory_search.py`:

```python
import string


def test_directory_search_reports_match_for_existing_prefix(client, mock_ldap):
    response = client.post(
        "/a03/directory-search", data={"target": "root_admin", "query": "r"}
    )
    assert response.status_code == 200
    assert b"Match found" in response.data


def test_directory_search_reports_no_match_for_wrong_prefix(client, mock_ldap):
    response = client.post(
        "/a03/directory-search", data={"target": "root_admin", "query": "z"}
    )
    assert response.status_code == 200
    assert b"No match" in response.data


def test_directory_search_blind_extraction_recovers_full_secret(client, mock_ldap):
    alphabet = string.ascii_lowercase + string.digits + "-"
    extracted = ""
    for _ in range(40):
        found_char = None
        for ch in alphabet:
            response = client.post(
                "/a03/directory-search",
                data={"target": "root_admin", "query": extracted + ch},
            )
            if b"Match found" in response.data:
                found_char = ch
                break
        if found_char is None:
            break
        extracted += found_char
    assert extracted == "recovery-code-x7k2p9"


def test_directory_search_secure_pattern_rejects_injection_attempt(mock_ldap):
    from ldap3 import SUBTREE
    from ldap3.utils.conv import escape_filter_chars

    from app.categories.a03_injection import ldap_client

    injected = escape_filter_chars(")(uid=*")
    filt = f"(&(uid=root_admin)(description={injected}*))"
    conn = ldap_client.get_ldap_connection()
    conn.search(ldap_client.LDAP_BASE_DN, filt, SUBTREE, attributes=["uid"])
    entries = list(conn.entries)
    conn.unbind()
    assert entries == []


def test_directory_search_still_works_with_teaching_text_hidden(app, client, mock_ldap):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post(
        "/a03/directory-search", data={"target": "root_admin", "query": "r"}
    )
    assert response.status_code == 200
    assert b"Match found" in response.data
    assert b"Vulnerable vs. Secure" in response.data
    assert b"Detect" not in response.data


def test_directory_search_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Blind" in response.data
    assert b'href="/a03/directory-search"' in response.data
```

Note: `test_directory_search_blind_extraction_recovers_full_secret` runs the
FULL extraction loop through the real Flask test client (dozens of actual
HTTP-level requests to the route, exactly like a real attacker script would
do), not a shortcut against `ldap3` directly — proving the entire
route+mock stack genuinely leaks the secret one character at a time via
only the boolean "Match found"/"No match" response, matching the "prove it
for real" discipline used during this plan's design-phase live
verification.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_a03_directory_search.py -v`
Expected: the tests exercising `/a03/directory-search` FAIL (404 — the route doesn't exist yet). `test_directory_search_secure_pattern_rejects_injection_attempt` PASSES already (it only exercises `ldap_client`/`mock_ldap`, not the route).

- [ ] **Step 3: Add the route**

In `app/categories/a03_injection/routes.py`, append this route at the end of the file (after the `directory_login()` route added in Task 1):

```python


@a03_bp.route("/directory-search", methods=["GET", "POST"])
def directory_search():
    target = ""
    query = ""
    result = None
    if request.method == "POST":
        target = request.form.get("target", "")
        query = request.form.get("query", "")
        conn = ldap_client.get_ldap_connection()
        try:
            # VULNERABLE: same raw f-string interpolation flaw as directory_login(),
            # reused in a different feature -- here the response is BLIND (only
            # found/not-found is shown), not the matched value itself, which is
            # exactly what makes boolean-based blind injection extraction possible.
            filt = f"(&(uid={target})(description={query}*))"
            conn.search(ldap_client.LDAP_BASE_DN, filt, SUBTREE, attributes=["uid"])
            result = "Match found" if conn.entries else "No match"
        finally:
            conn.unbind()
    return render_template(
        "a03_injection/directory_search.html", target=target, query=query, result=result
    )
```

- [ ] **Step 4: Register the nav entry**

In `app/categories/a03_injection/__init__.py`, the `examples=[...]` list now ends with the `ldap-directory-login` entry added in Task 1, closing like this:

```python
            ExampleNav(
                id="ldap-directory-login",
                title="LDAP Auth Bypass via Company Directory Login",
                group="LDAP Injection",
                difficulty="Easy",
                endpoint="a03_injection.directory_login",
            ),
        ],
        seed_fn=seed_injection_data,
    )
)
```

Add the new entry immediately after `ldap-directory-login`, in the same group, before the closing `],`:

```python
            ExampleNav(
                id="ldap-directory-login",
                title="LDAP Auth Bypass via Company Directory Login",
                group="LDAP Injection",
                difficulty="Easy",
                endpoint="a03_injection.directory_login",
            ),
            ExampleNav(
                id="ldap-directory-search",
                title="Blind LDAP Injection via Employee Directory Search",
                group="LDAP Injection",
                difficulty="Hard",
                endpoint="a03_injection.directory_search",
            ),
        ],
        seed_fn=seed_injection_data,
    )
)
```

- [ ] **Step 5: Create the template**

Create `app/categories/a03_injection/templates/a03_injection/directory_search.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Blind LDAP Injection via Employee Directory Search" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This "employee directory search" feature has the exact same underlying
  flaw as the company directory login example — it builds an LDAP filter
  directly from your input with no escaping:
  <code>(&(uid=TARGET)(description=QUERY*))</code>. Unlike the login
  example, though, this feature never shows you the matched value —
  only whether a match was found at all ("Match found" / "No match").
  That single bit of information, repeated many times with different
  inputs, is enough to extract data you were never shown: this is
  <strong>blind</strong> LDAP injection.
</p>
{% endblock %}

{% block detect %}
<p>
  Search for the <code>root_admin</code> account with a single-letter
  query:
</p>
<pre><code class="language-python">target: root_admin
query: r</code></pre>
<p>
  If this reports "Match found," the server is treating your query as a
  filter fragment (a prefix match against the account's
  <code>description</code> field) rather than literal search text — the
  next step turns that single true/false bit into a way to read data you
  can't see directly.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Search with <code>target=root_admin</code> and
      <code>query=r</code> — "Match found" (the hidden
      <code>description</code> value starts with "r").</li>
  <li>Try <code>query=re</code> — still "Match found". Try
      <code>query=rf</code> — "No match". Keep extending the query by one
      character at a time, trying every letter/digit until one matches,
      then moving to the next position.</li>
  <li>Repeating this character by character recovers the entire hidden
      <code>description</code> value — a secret recovery code — without
      ever being shown it directly, purely from the found/not-found
      responses.</li>
</ol>
<p>
  Blind boolean-based injection is what an attacker reaches for whenever
  an application is vulnerable but doesn't echo back the injected data
  directly — the same technique this lab's Blind Time-Based SQL
  Injection example demonstrates for SQL. It's slower than a direct
  data leak (each character can take dozens of guesses), but it's fully
  automatable: a real attack script tries every character position in a
  loop exactly like this, typically recovering secrets in seconds. This
  matters because "the app never displays the sensitive field" is often
  mistaken for a mitigation — it isn't, if the underlying query is still
  injectable.
</p>
{% endblock %}

{% block vulnerable_code %}filt = f"(&(uid={target})(description={query}*))"
conn.search(base_dn, filt, SUBTREE, attributes=["uid"])
result = "Match found" if conn.entries else "No match"
{% endblock %}

{% block secure_code %}from ldap3.utils.conv import escape_filter_chars

safe_target = escape_filter_chars(target)
safe_query = escape_filter_chars(query)
filt = f"(&(uid={safe_target})(description={safe_query}*))"
conn.search(base_dn, filt, SUBTREE, attributes=["uid"])
result = "Match found" if conn.entries else "No match"
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Target username</label>
    <input type="text" class="form-control" name="target" value="{{ target }}">
  </div>
  <div class="mb-2">
    <label class="form-label">Search query</label>
    <input type="text" class="form-control" name="query" value="{{ query }}">
  </div>
  <button type="submit" class="btn btn-primary">Search</button>
</form>
{% if result %}
<p class="mt-3">{{ result }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `pytest tests/test_a03_directory_search.py -v`
Expected: all 6 PASS.

- [ ] **Step 7: Update the hardcoded nav-list tests**

Registering the new `ldap-directory-search` entry breaks the same two tests in `tests/test_a03_overview.py` again — apply the same additive pattern as Task 1's Step 12.

In `test_a03_registered_in_nav`, change:

```python
    assert [e.difficulty for e in a03.examples] == [
        "Easy",
        "Medium",
        "Hard",
        "Medium",
        "Hard",
        "Hard",
        "Easy",
        "Hard",
        "Easy",
        "Hard",
        "Easy",
    ]
```

to:

```python
    assert [e.difficulty for e in a03.examples] == [
        "Easy",
        "Medium",
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
    ]
```

In `test_a03_examples_grouped_by_vulnerability_subtype`, change:

```python
    assert [e.id for e in grouped[5][1]] == ["ldap-directory-login"]
```

to:

```python
    assert [e.id for e in grouped[5][1]] == ["ldap-directory-login", "ldap-directory-search"]
```

(The group *names* list itself doesn't change in this step, since both LDAP examples share the group added in Task 1.)

- [ ] **Step 8: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (190 + 6 = 196)

- [ ] **Step 9: Commit**

```bash
git add app/categories/a03_injection/routes.py app/categories/a03_injection/__init__.py \
  app/categories/a03_injection/templates/a03_injection/directory_search.html \
  tests/test_a03_directory_search.py tests/test_a03_overview.py
git commit -m "feat: add A03 LDAP blind injection example (Hard)"
```

---

### Task 3: Full regression + Docker verification

**Files:**
- None (verification-only task; no code changes expected).

**Interfaces:**
- Consumes: nothing new (verifies Tasks 1–2's combined output).
- Produces: nothing — this is the final task.

- [ ] **Step 1: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (196 tests)

- [ ] **Step 2: Docker end-to-end verification**

```bash
docker compose up --build -d
```

Confirm `ldap3` installed correctly in the `app` container's build logs
(no pip errors), and confirm the new `ldap` service reaches "healthy"
status (`docker compose ps` — its healthcheck uses `ldapwhoami`, added in
Task 1). This is a NEW pip package AND a new Docker service in this plan —
both need to be confirmed working for real, not just assumed from the
design-phase live testing.

Confirm seed data loaded into the REAL directory (not the mock used by
unit tests):

```bash
docker compose exec ldap ldapsearch -x -D "cn=admin,dc=owasp-lab,dc=local" -w admin123 -H ldap://localhost:389 -b "dc=owasp-lab,dc=local" "(uid=root_admin)"
```

Expected: returns the `root_admin` entry with `description: recovery-code-x7k2p9`.

Then, via curl against the live app container (`http://127.0.0.1:5001`):

- `/a03/` returns 200 and contains `LDAP Injection`, the new group heading.
- `/a03/directory-login` returns 200. POST
  `username=root_admin&password=*` and confirm the response contains
  `Root Administrator` — this is the first time this exact payload is
  verified against the real LDAP service, not just the design-phase test
  or the unit tests' mock.
- **Re-confirm the `userPassword` vs. `description` matching-rule
  divergence against the REAL server** (this is exactly the kind of
  assumption a prior sub-project's SSRF example got wrong before Docker
  verification caught it — confirm it here too, don't just trust the
  spec's brainstorming-phase claim):
  ```bash
  docker compose exec ldap ldapsearch -x -D "cn=admin,dc=owasp-lab,dc=local" -w admin123 -H ldap://localhost:389 -b "dc=owasp-lab,dc=local" "(&(uid=root_admin)(userPassword=s*))"
  docker compose exec ldap ldapsearch -x -D "cn=admin,dc=owasp-lab,dc=local" -w admin123 -H ldap://localhost:389 -b "dc=owasp-lab,dc=local" "(&(uid=root_admin)(description=r*))"
  ```
  Expected: the first search returns NO entries (confirming `userPassword`
  genuinely rejects substring matching on the real server); the second
  returns the `root_admin` entry (confirming `description` genuinely
  supports it). If either result differs from this expectation, STOP —
  this is a load-bearing assumption behind the Hard example's entire
  design and must be root-caused, not papered over, exactly like the
  XXE sub-project's SSRF assumption had to be when Docker verification
  caught it wrong.
- `/a03/directory-search` returns 200. POST
  `target=root_admin&query=z` and confirm the response contains
  `No match`. Then run the FULL blind extraction live against the real
  container — write a short throwaway script (bash loop with curl, or a
  short Python script using `requests`) that POSTs successive
  single-character-longer `query` values against `target=root_admin` and
  checks each response for "Match found", extending the extracted string
  one character at a time (alphabet: lowercase letters, digits, `-`).
  Confirm the fully-extracted string equals `recovery-code-x7k2p9`,
  matching the real seeded value — this is the live proof that the blind
  extraction genuinely works against the real directory server end to
  end, not just the mock.
- `/force-reset` still works cleanly with the new examples in place.
  Confirm the LDAP directory data is unaffected by `/force-reset` (it
  should be — `/force-reset` only drops/recreates the SQL database, never
  touches the LDAP directory) by re-running the `root_admin` login bypass
  once more after triggering `/force-reset`.

If you have a browser tool available, additionally visit both new example
pages and confirm the Detect/Exploitation/Vulnerable-vs-Secure sections
render correctly with proper syntax highlighting. If no browser tool is
available, note that as a known gap in your report rather than skipping
the curl-based checks above.

Tear down cleanly afterward:

```bash
docker compose down
```

- [ ] **Step 3: Commit**

No code changes are expected from this task. If the Docker/curl
verification finds nothing to fix, there is nothing to commit — report
DONE with the verification evidence in your report file rather than an
empty commit.
