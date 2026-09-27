# Second-Order SQL Injection & Insecure File Upload Additions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 3 new intentionally-vulnerable examples to the OWASP Top 10 Training Lab — a second-order SQL injection example in A03, a path-traversal-via-upload example in A01, and a stored-XSS-via-SVG-upload example in A03 — bringing the app from 100 to 103 examples and max score from 2140 to 2220.

**Architecture:** All three examples reuse existing SQLAlchemy models (`Employee`, `InjectionAccount`) or are filesystem-only (new `instance/` subdirectories), following this app's established pattern for upload/document features. No new SQLAlchemy models anywhere in this round.

**Tech Stack:** Flask, Jinja2, Werkzeug's `FileStorage`/`send_from_directory`, pytest with Flask's test client (no mocking).

**Spec:** `docs/superpowers/specs/2026-09-27-owasp-lab-second-order-sqli-avatar-upload-additions-design.md`

## Global Constraints

- No new SQLAlchemy models — Example 1 reuses the existing `Employee` and `InjectionAccount` models (`app/categories/a03_injection/models.py`); Examples 2 and 3 are filesystem-only, following the existing `DOCUMENTS_DIR` pattern in A01.
- Every `ExampleNav.hints` list has 3-5 entries, each non-empty, no duplicates within the list.
- Within each category's `grouped_examples()` output, every group's examples must be sorted Easy → Medium → Hard.
- Hints render through Jinja's autoescaped `{{ hint }}` expression — write raw, unescaped `<`/`>`/`&` in hint text (Jinja escapes it automatically at render time). The six static template blocks (`explanation`/`detect`/`exploitation`/`tasks`/`vulnerable_code`/`secure_code`/`live_example`) are rendered UNESCAPED (raw HTML written directly in the template source) — any literal `<`/`>`/`&` that must appear as visible TEXT (not real markup) inside those blocks must be manually entity-encoded (`&lt;`/`&gt;`/`&amp;`).
- **The vulnerabilities ARE the deliverable.** Never add sanitization, escaping, validation, authentication, or restriction to any new vulnerable code path.
  - The `add_employee()` write must stay genuinely safe (fully parameterized via the ORM) — that is not the bug. The `department_report()` read must keep using raw f-string interpolation into `text(query)` — never parameterized, never validated/allowlisted against already-stored values.
  - The avatar-upload route must never call `secure_filename()` and must never validate that the resolved save path stays inside `AVATARS_DIR`.
  - The attachment-upload route must never restrict file extensions or verify content against a declared type; `view_attachment()` must never force `Content-Disposition: attachment` and must never override Flask's default extension-based MIME-type guessing.
- New routes follow each category's existing plain `render_template()`/`redirect()`/`jsonify()` convention — no new abstraction layers.
- Every `ExampleNav.endpoint` must point at a route that renders an HTML explanation page (extending `core/example_page_base.html`, with the "mark as done" UI) — never directly at a raw action/download/upload-serving route. (This is why `view_attachment()` — which must serve a raw, unwrapped SVG for the exploit to work at all — is NOT itself an `ExampleNav` entry; `upload_attachment()` is, mirroring this app's existing `css_exfil_demo()`/`css_exfil_collector()` split.)

---

### Task 1: A03 Second-Order SQL Injection via Department Report

**Files:**
- Modify: `app/categories/a03_injection/routes.py` (append two new routes at the end of the file)
- Modify: `app/categories/a03_injection/__init__.py` (append new `ExampleNav` at the very end of the existing "SQL Injection" group, i.e. immediately after `sqli-to-rce` and before `reflected-xss`)
- Create: `app/categories/a03_injection/templates/a03_injection/department_report.html`
- Create: `tests/test_a03_second_order_sqli.py`
- Modify: `tests/test_a03_hints_sqli_group.py`
- Modify: `tests/test_a03_overview.py`

**Interfaces:**
- Consumes: the existing `Employee` model (`name`, `email`, `department`, `salary`) and `InjectionAccount` model (`username`, `password`) — both already imported in `routes.py`. Existing seeded employees span departments `Engineering`, `Finance`, `Support`, `Executive` (`app/categories/a03_injection/seed.py`); the seeded `InjectionAccount` rows are `alice`/`alice123` and `admin`/`sup3r-s3cret-admin-pw`.
- Produces: routes `a03_injection.add_employee` (POST) and `a03_injection.department_report` (GET). `ExampleNav` id `second-order-sqli-department-report`, appended as the 8th (final) member of the existing "SQL Injection" group.

## Orchestration Note (read before starting Task 1 — this note also covers Task 3)

Tasks 1 and 3 BOTH modify `app/categories/a03_injection/routes.py`, `__init__.py`, and `tests/test_a03_overview.py`, sequentially, in that order (Task 1 → Task 3; Task 2 is fully independent — it only touches A01 files and can run in any order relative to 1/3). Their insertion points do not physically overlap:

- Task 1's `ExampleNav` entry goes at the END of the FIRST group ("SQL Injection"), near the TOP of A03's overall list.
- Task 3's `ExampleNav` entry forms a brand-new "Insecure File Upload" group, appended at the very END of A03's list (after the existing `file-inclusion-lfi-ssti` entry) — this is AFTER Task 1's insertion point in list order, so no collision.
- Task 1 and Task 3 use DIFFERENT hints test files: Task 1's example joins the existing "SQL Injection" group, so its hints go in `tests/test_a03_hints_sqli_group.py`. Task 3's example creates a brand-new group, so its hints go in `tests/test_a03_hints_remaining_groups.py`. These two files never conflict.

Both tasks append their new ROUTES to the end of `routes.py`, in task order (Task 1's two routes, then — after Task 1 has landed — Task 3's two routes), matching every prior round's convention.

**Re-read `app/categories/a03_injection/routes.py`, `__init__.py`, and `tests/test_a03_overview.py` fresh before starting Task 3** — don't assume line numbers from this plan still match exactly, since Task 1 will have already appended its own routes and inserted its own `ExampleNav` entry.

**The fully-composed final A03 difficulty list (26 entries), after Tasks 1 and 3 have both landed:**

```
Easy, Medium, Medium, Medium, Hard, Hard, Hard,
Hard,                                              # second-order-sqli-department-report (Task 1, NEW)
Medium, Hard, Hard, Hard,                          # XSS group (unchanged, shifted down by 1)
Medium, Hard, Hard, Hard,                          # OS Command Injection group (shifted)
Easy, Hard,                                        # XXE group (shifted)
Easy, Hard,                                        # SSTI group (shifted)
Easy, Hard,                                        # LDAP group (shifted)
Hard,                                              # CSS Injection (shifted)
Medium,                                            # CSV Injection (shifted)
Hard,                                               # file-inclusion-lfi-ssti (shifted)
Hard,                                               # svg-upload-stored-xss (Task 3, NEW, final entry)
```

Written out as the literal 26-entry list Task 3's own Step 8 writes:
```python
    assert [e.difficulty for e in a03.examples] == [
        "Easy", "Medium", "Medium", "Medium", "Hard", "Hard", "Hard",
        "Hard",
        "Medium", "Hard", "Hard", "Hard",
        "Medium", "Hard", "Hard", "Hard",
        "Easy", "Hard",
        "Easy", "Hard",
        "Easy", "Hard",
        "Hard",
        "Medium",
        "Hard",
        "Hard",
    ]
```

Task 1's own Step 8 writes only the 25-entry INTERMEDIATE state (identical to the above with the final `"Hard"` — Task 3's `svg-upload-stored-xss` — removed entirely, since Task 3 hasn't landed yet):
```python
    assert [e.difficulty for e in a03.examples] == [
        "Easy", "Medium", "Medium", "Medium", "Hard", "Hard", "Hard",
        "Hard",
        "Medium", "Hard", "Hard", "Hard",
        "Medium", "Hard", "Hard", "Hard",
        "Easy", "Hard",
        "Easy", "Hard",
        "Easy", "Hard",
        "Hard",
        "Medium",
        "Hard",
    ]
```

**Groups:** Task 1 does NOT create a new group — `second-order-sqli-department-report` joins the existing "SQL Injection" group as its 8th member, so `test_a03_examples_grouped_by_vulnerability_subtype`'s group-NAME list (9 entries) is unchanged by Task 1; only `grouped[0][1]` (the SQL Injection group's own id list) gains one more id at the end. Task 3 DOES create a new 10th group, "Insecure File Upload", appended at the very end of the group-name list, with `grouped[9][1] == ["svg-upload-stored-xss"]`.

This table is what each task's own Step 8 writes into `tests/test_a03_overview.py` — Task 1 to its own 25-entry intermediate state (never jumping ahead to Task 3's not-yet-landed final state, a mistake caught and fixed during a prior round's plan self-review), Task 3 to the full 26-entry final state above.

- [ ] **Step 1: Read A03's current routes.py, __init__.py, models.py, and seed.py fresh**

Read `app/categories/a03_injection/routes.py` in full, `app/categories/a03_injection/__init__.py` in full, `app/categories/a03_injection/models.py` in full, and `app/categories/a03_injection/seed.py` in full. If anything has changed from what's shown below, adapt accordingly — this plan is accurate as of repo tip `1b00c0d`.

- [ ] **Step 2: Write the failing tests**

Create `tests/test_a03_second_order_sqli.py`:

```python
from app.core.seed import seed_database


SECOND_ORDER_PAYLOAD = "NoSuchDept' UNION SELECT username, password, 0 FROM injection_accounts--"


def test_add_employee_stores_payload_safely(app, client):
    seed_database(app)
    response = client.post(
        "/a03/roster/add-employee",
        data={
            "name": "Mallory",
            "email": "mallory@example.com",
            "department": SECOND_ORDER_PAYLOAD,
            "salary": "1",
        },
    )
    assert response.status_code == 302


def test_department_report_leaks_credentials_via_second_order_injection(app, client):
    seed_database(app)
    client.post(
        "/a03/roster/add-employee",
        data={
            "name": "Mallory",
            "email": "mallory@example.com",
            "department": SECOND_ORDER_PAYLOAD,
            "salary": "1",
        },
    )
    response = client.get("/a03/roster/department-report")
    assert response.status_code == 200
    assert b"sup3r-s3cret-admin-pw" in response.data


def test_department_report_shows_normal_departments_unaffected(app, client):
    seed_database(app)
    response = client.get("/a03/roster/department-report")
    assert response.status_code == 200
    assert b"Engineering" in response.data
    assert b"Alice Chen" in response.data
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_a03_second_order_sqli.py -v`
Expected: FAIL — `404 NOT FOUND` for both `/a03/roster/add-employee` and `/a03/roster/department-report` (neither route exists yet).

- [ ] **Step 4: Add the two new routes**

Append these two routes to the end of `app/categories/a03_injection/routes.py` (after the current last function, `render_snippet()`):

```python
@a03_bp.route("/roster/department-report")
def department_report():
    departments = [
        row[0]
        for row in db.session.execute(text("SELECT DISTINCT department FROM a03_employees")).all()
    ]
    report = {}
    for department in departments:
        # VULNERABLE: `department` was already sitting safely in the
        # database -- inserted through add_employee()'s fully
        # parameterized INSERT below -- but this SEPARATE, later query
        # re-interpolates that already-stored value into a brand new raw
        # SQL string with zero parameterization. The safe write earlier
        # provides no protection at all against this unsafe read: this
        # is second-order SQL injection.
        query = f"SELECT name, email, salary FROM a03_employees WHERE department = '{department}'"
        report[department] = db.session.execute(text(query)).all()
    return render_template("a03_injection/department_report.html", report=report)


@a03_bp.route("/roster/add-employee", methods=["POST"])
def add_employee():
    name = request.form.get("name", "")
    email = request.form.get("email", "")
    department = request.form.get("department", "")
    salary = request.form.get("salary", "0")
    try:
        salary_value = int(salary)
    except ValueError:
        salary_value = 0
    # Genuinely safe: a real parameterized INSERT via the ORM. The
    # `department` value is stored VERBATIM, whatever it is -- this
    # write is not the vulnerability; what happens to this value LATER,
    # in department_report() above, is.
    db.session.add(
        Employee(name=name, email=email, department=department, salary=salary_value)
    )
    db.session.commit()
    return redirect(url_for("a03_injection.department_report"))
```

No new imports are needed — `Employee`, `db`, `text`, `request`, `redirect`, `render_template`, `url_for` are already imported at the top of this file.

- [ ] **Step 5: Create the template**

Create `app/categories/a03_injection/templates/a03_injection/department_report.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Second-Order SQL Injection via Department Report" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This "add employee to roster" form stores a new employee's department
  through a completely safe, parameterized database write -- there is no
  SQL injection risk at the moment of writing. The bug lives somewhere
  else entirely: a SEPARATE "department report" feature later reads
  every stored department value back and re-inserts it into a BRAND NEW
  raw SQL query, built with plain string interpolation instead of bound
  parameters.
</p>
<p>
  This is <strong>second-order SQL injection</strong>: the malicious
  payload is stored safely, sits inert in the database, and only fires
  when a completely different, unrelated feature reads it back and
  trusts it as if it were already-safe data.
</p>
{% endblock %}

{% block detect %}
<p>
  Add a new employee with an ordinary department name like
  <code>Marketing</code> and confirm it shows up correctly in the report
  below. Then think about what happens if the department VALUE itself
  contains SQL syntax.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Add a new employee using the form below with the Department field set
  to exactly:
</p>
<pre>NoSuchDept' UNION SELECT username, password, 0 FROM injection_accounts--</pre>
<p>
  The employee is added successfully -- this write is genuinely safe,
  parameterized, and never touches raw SQL. Now look at the department
  report further down this page: the report route builds a fresh query
  for EVERY distinct department already in the table, including the one
  you just added, by directly interpolating that stored string into
  <code>SELECT name, email, salary FROM a03_employees WHERE department =
  '&lt;value&gt;'</code>. Your stored payload breaks out of that new
  query's string literal and UNION-selects every row of
  <code>injection_accounts</code> instead -- real usernames and
  plaintext passwords appear in the report, disguised as one
  department's employee list.
</p>
<p>
  The lesson: parameterizing the WRITE gives you zero protection if a
  LATER, unrelated feature re-interpolates the already-stored value into
  a new query of its own. Every consumer of stored data needs its own
  parameterization -- safety doesn't travel with the data.
</p>
{% endblock %}

{% block vulnerable_code %}# Safe write -- this is NOT the bug:
db.session.add(Employee(name=name, email=email, department=department, salary=salary))
db.session.commit()

# Unsafe read, in a completely different route, run later:
for department in distinct_departments:
    query = f"SELECT name, email, salary FROM a03_employees WHERE department = '{department}'"
    report[department] = db.session.execute(text(query)).all()
{% endblock %}

{% block secure_code %}# Parameterize the READ too, not just the write:
for department in distinct_departments:
    query = text("SELECT name, email, salary FROM a03_employees WHERE department = :department")
    report[department] = db.session.execute(query, {"department": department}).all()
{% endblock %}

{% block live_example %}
<h3 class="h6 mt-3">Add an employee</h3>
<form method="post" action="{{ url_for('a03_injection.add_employee') }}" class="mb-4">
  <div class="row g-2">
    <div class="col"><input type="text" class="form-control" name="name" placeholder="Name" required></div>
    <div class="col"><input type="email" class="form-control" name="email" placeholder="Email" required></div>
    <div class="col"><input type="text" class="form-control" name="department" placeholder="Department" required></div>
    <div class="col"><input type="number" class="form-control" name="salary" placeholder="Salary" required></div>
    <div class="col-auto"><button type="submit" class="btn btn-primary">Add employee</button></div>
  </div>
</form>

<h3 class="h6 mt-3">Department report</h3>
{% for department, rows in report.items() %}
<h4 class="h6 mt-2">{{ department }}</h4>
<table class="table table-sm">
  <thead><tr><th>Name</th><th>Email</th><th>Salary</th></tr></thead>
  <tbody>
    {% for row in rows %}
    <tr><td>{{ row[0] }}</td><td>{{ row[1] }}</td><td>{{ row[2] }}</td></tr>
    {% endfor %}
  </tbody>
</table>
{% endfor %}
{% endblock %}
```

- [ ] **Step 6: Register the ExampleNav entry**

In `app/categories/a03_injection/__init__.py`, insert this new `ExampleNav` immediately after the `sqli-to-rce` entry's closing `),` and before the `reflected-xss` entry (i.e. as the LAST member of the "SQL Injection" group, before the "Cross-Site Scripting (XSS)" group begins):

```python
            ExampleNav(
                id="second-order-sqli-department-report",
                title="Second-Order SQL Injection via Department Report",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.department_report",
                hints=[
                    "This form safely adds a new employee to the roster -- the write itself uses the ORM and is fully parameterized. Look instead at what happens to a stored department value LATER, in a completely different feature.",
                    "The department report loops over every distinct department already in the database and builds a NEW SQL query for each one via plain f-string interpolation -- request.form was never involved in that query at all, only data that already sat safely in the table.",
                    "Add a new employee with the department field set to: NoSuchDept' UNION SELECT username, password, 0 FROM injection_accounts-- . The write succeeds without any error -- this step is completely safe.",
                    "Now view the department report. The report route reads your stored department value back and interpolates it into a fresh query -- your payload breaks out of that query's string literal and the UNION SELECT fires, leaking every row of injection_accounts (real usernames and plaintext passwords) disguised as an employee list for a department that doesn't exist.",
                    "This is second-order SQL injection: parameterizing the WRITE (as this app correctly does here) provides zero protection against an unrelated, later feature that re-interpolates the same stored value into a brand new, unparameterized query.",
                ],
            ),
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_a03_second_order_sqli.py -v`
Expected: PASS (all 3 tests).

- [ ] **Step 8: Update A03's cross-cutting test files (intermediate state)**

In `tests/test_a03_hints_sqli_group.py`, append `"second-order-sqli-department-report"` to the end of the `SQLI_GROUP_IDS` list (after `"sqli-to-rce"`).

In `tests/test_a03_overview.py`:

In `test_a03_registered_in_nav`, replace the existing 24-entry `assert [e.difficulty for e in a03.examples] == [...]` with the 25-entry INTERMEDIATE list given in the Orchestration Note above.

In `test_a03_examples_grouped_by_vulnerability_subtype`, the group-NAME list (`assert [name for name, _ in grouped] == [...]`, 9 entries) is UNCHANGED by this task. Update only `assert [e.id for e in grouped[0][1]] == [...]` (the SQL Injection group's own id list) by appending `"second-order-sqli-department-report"` at the end:
```python
    assert [e.id for e in grouped[0][1]] == [
        "sqli-login",
        "union-exfiltration",
        "roster-sort",
        "error-based-sqli",
        "blind-sqli",
        "roster-lookup",
        "sqli-to-rce",
        "second-order-sqli-department-report",
    ]
```

- [ ] **Step 9: Run the full A03 test surface**

Run: `pytest tests/test_a03_second_order_sqli.py tests/test_a03_hints_sqli_group.py tests/test_a03_hints_remaining_groups.py tests/test_a03_overview.py tests/test_a03_login.py tests/test_a03_search.py tests/test_a03_roster.py tests/test_a03_roster_lookup.py tests/test_a03_inventory_lookup.py tests/test_a03_product_lookup.py tests/test_a03_check_username.py -v`
Expected: PASS (all tests, no regressions).

- [ ] **Step 10: Commit**

```bash
git add app/categories/a03_injection/routes.py \
        app/categories/a03_injection/__init__.py \
        app/categories/a03_injection/templates/a03_injection/department_report.html \
        tests/test_a03_second_order_sqli.py \
        tests/test_a03_hints_sqli_group.py \
        tests/test_a03_overview.py
git commit -m "feat(a03): add Second-Order SQL Injection via Department Report example"
```

---

### Task 2: A01 Path Traversal via Unsanitized Avatar-Upload Filename

**Files:**
- Modify: `app/categories/a01_access_control/routes.py` (add `AVATARS_DIR` constant near `DOCUMENTS_DIR`; append one new route at the end of the file)
- Modify: `app/categories/a01_access_control/__init__.py` (insert new `ExampleNav` immediately after the existing `arbitrary-file-read` entry — inside the existing "Path Traversal" group, before `path-traversal-filter-bypass`)
- Create: `app/categories/a01_access_control/templates/a01_access_control/avatar_upload.html`
- Create: `tests/test_a01_avatar_upload_traversal.py`
- Modify: `tests/test_a01_hints.py`
- Modify: `tests/test_a01_overview.py`

**Interfaces:**
- Consumes: `get_current_user()`, `os`, `BASE_DIR` (already imported/available). Uses Werkzeug's `FileStorage.save()` (via `request.files`).
- Produces: route `a01_access_control.avatar_upload` (GET/POST). `ExampleNav` id `avatar-upload-path-traversal`, inserted as the 2nd member of the existing "Path Traversal" group (between `arbitrary-file-read` and `path-traversal-filter-bypass`).

This task is entirely independent of Tasks 1 and 3 — it touches only A01's files, which neither of those tasks modifies. It can be run at any point relative to them.

**Test-design note (read before Step 2):** the exploit proves impact by writing OUTSIDE `AVATARS_DIR` via `../` traversal into the EXISTING `a01_documents` folder — but the test must NOT overwrite the real, shared `welcome.txt` seed file there (that file is a real file on disk, not reset between test runs the way the in-memory test database is, and other A01 tests may depend on its exact seeded content). Instead, the traversal targets a fresh, dedicated sentinel filename (`pwned_by_avatar_upload.txt`) that no other test reads or asserts on — this proves the identical "write lands in `a01_documents/` instead of `a01_avatars/`" primitive without touching any shared fixture state.

- [ ] **Step 1: Read A01's current routes.py, __init__.py, and download_document.html fresh**

Read `app/categories/a01_access_control/routes.py` in full and `app/categories/a01_access_control/__init__.py` in full. If anything has changed from what's shown below, adapt accordingly — this plan is accurate as of repo tip `1b00c0d`.

- [ ] **Step 2: Write the failing tests**

Create `tests/test_a01_avatar_upload_traversal.py`:

```python
import io
import os

from app import BASE_DIR
from app.core.models import User
from app.core.seed import seed_database


def _login_as(client, app, username):
    with app.app_context():
        seed_database(app)
        user = User.query.filter_by(username=username).first()
        user_id = user.id
    with client.session_transaction() as sess:
        sess["user_id"] = user_id
    return user_id


def test_avatar_upload_traversal_writes_outside_avatars_dir(app, client):
    _login_as(client, app, "alice")
    # Ensure a01_documents/ already exists on disk before the exploit
    # tries to write into it via traversal (mirrors _ensure_seed_document()
    # already running once via a normal document-center visit).
    client.get("/a01/download-document")

    malicious_content = b"OVERWRITTEN BY AVATAR UPLOAD TRAVERSAL\n"
    data = {
        "avatar": (io.BytesIO(malicious_content), "../a01_documents/pwned_by_avatar_upload.txt"),
    }
    response = client.post("/a01/avatar-upload", data=data, content_type="multipart/form-data")
    assert response.status_code == 200

    # Prove the write landed in a01_documents/, NOT a01_avatars/, using
    # this app's own EXISTING, unrelated document-download feature.
    proof_response = client.get("/a01/download-document?name=pwned_by_avatar_upload.txt")
    assert proof_response.status_code == 200
    assert malicious_content.decode() in proof_response.data.decode()

    documents_dir = os.path.join(BASE_DIR, "instance", "a01_documents")
    avatars_dir = os.path.join(BASE_DIR, "instance", "a01_avatars")
    assert os.path.exists(os.path.join(documents_dir, "pwned_by_avatar_upload.txt"))
    assert not os.path.exists(os.path.join(avatars_dir, "pwned_by_avatar_upload.txt"))


def test_avatar_upload_normal_filename_saves_inside_avatars_dir(app, client):
    _login_as(client, app, "bob")
    data = {"avatar": (io.BytesIO(b"fake image bytes"), "myavatar.png")}
    response = client.post("/a01/avatar-upload", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    assert b"myavatar.png" in response.data

    avatars_dir = os.path.join(BASE_DIR, "instance", "a01_avatars")
    assert os.path.exists(os.path.join(avatars_dir, "myavatar.png"))
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_a01_avatar_upload_traversal.py -v`
Expected: FAIL — `404 NOT FOUND` for `/a01/avatar-upload` (route doesn't exist yet).

- [ ] **Step 4: Add the AVATARS_DIR constant and the vulnerable route**

In `app/categories/a01_access_control/routes.py`, change:

```python
DOCUMENTS_DIR = os.path.join(BASE_DIR, "instance", "a01_documents")
```

to:

```python
DOCUMENTS_DIR = os.path.join(BASE_DIR, "instance", "a01_documents")
AVATARS_DIR = os.path.join(BASE_DIR, "instance", "a01_avatars")
```

Append this route to the end of the file (after the current last function, `update_preferences()`):

```python
@a01_bp.route("/avatar-upload", methods=["GET", "POST"])
def avatar_upload():
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=request.path))
    uploaded_name = None
    error = None
    if request.method == "POST":
        os.makedirs(AVATARS_DIR, exist_ok=True)
        avatar = request.files.get("avatar")
        if avatar and avatar.filename:
            # VULNERABLE: the client-supplied filename is used exactly as
            # submitted -- no secure_filename(), no traversal check, no
            # restriction to AVATARS_DIR at all. A filename containing
            # "../" climbs straight out of this directory, the same
            # os.path.join() behavior this lab's other Path Traversal
            # examples already demonstrate on the READ side -- here it's
            # a WRITE.
            path = os.path.join(AVATARS_DIR, avatar.filename)
            try:
                avatar.save(path)
                uploaded_name = avatar.filename
            except Exception as e:
                error = str(e)
    return render_template(
        "a01_access_control/avatar_upload.html",
        viewer=viewer,
        uploaded_name=uploaded_name,
        error=error,
    )
```

No new imports are needed — `os`, `get_current_user`, `redirect`, `render_template`, `request`, `url_for` are already imported at the top of this file.

- [ ] **Step 5: Create the template**

Create `app/categories/a01_access_control/templates/a01_access_control/avatar_upload.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Path Traversal via Unsanitized Avatar-Upload Filename" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A01{% endblock %}

{% block explanation %}
<p>
  This "upload an avatar" feature saves whatever file you submit using
  the filename YOU supplied in the upload, exactly as given -- no
  <code>secure_filename()</code>, no check that the resolved path stays
  inside the avatars folder, nothing at all.
</p>
{% endblock %}

{% block detect %}
<p>
  Upload a normal image with an ordinary filename first and confirm it's
  accepted. Then think about what a filename containing <code>../</code>
  would do once it's joined onto the avatars folder's path.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Upload any file, but set its filename to
  <code>../a01_documents/pwned_by_avatar_upload.txt</code> with whatever
  content you like. The upload succeeds -- but the file doesn't land in
  the avatars folder at all. It lands in this lab's own document-center
  folder instead, one directory up and back down into
  <code>a01_documents/</code>.
</p>
<p>
  Prove it: visit
  <code>/a01/download-document?name=pwned_by_avatar_upload.txt</code>
  (this lab's EXISTING document-download feature, completely unrelated
  to avatar upload) -- it serves back exactly the content you just
  uploaded as an "avatar," proving a write in one feature reached a
  completely different feature's storage.
</p>
{% endblock %}

{% block vulnerable_code %}path = os.path.join(AVATARS_DIR, avatar.filename)
avatar.save(path)
{% endblock %}

{% block secure_code %}from werkzeug.utils import secure_filename

safe_name = secure_filename(avatar.filename)
path = os.path.join(AVATARS_DIR, safe_name)
avatar.save(path)
{% endblock %}

{% block live_example %}
<form method="post" enctype="multipart/form-data">
  <div class="mb-2">
    <label class="form-label">Avatar file</label>
    <input type="file" class="form-control" name="avatar" required>
  </div>
  <button type="submit" class="btn btn-primary">Upload avatar</button>
</form>
{% if uploaded_name %}
<div class="alert alert-success mt-3">Uploaded as: {{ uploaded_name }}</div>
{% endif %}
{% if error %}
<div class="alert alert-danger mt-3">{{ error }}</div>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Register the ExampleNav entry**

In `app/categories/a01_access_control/__init__.py`, insert this new `ExampleNav` immediately after the `arbitrary-file-read` entry's closing `),` and before the `path-traversal-filter-bypass` entry:

```python
            ExampleNav(
                id="avatar-upload-path-traversal",
                title="Path Traversal via Unsanitized Avatar-Upload Filename",
                group="Path Traversal",
                difficulty="Medium",
                endpoint="a01_access_control.avatar_upload",
                hints=[
                    "This 'upload an avatar' feature saves your file using the filename YOU provide in the upload -- not a server-generated one. Check whether there's any validation on what that filename can contain.",
                    "The server builds the save path with os.path.join(AVATARS_DIR, avatar.filename) and saves directly there -- the exact same unguarded os.path.join() pattern this lab's Path Traversal READ examples use, just on the WRITE side this time.",
                    "Upload any file, but set its filename to ../a01_documents/pwned_by_avatar_upload.txt -- the upload is accepted with no error, but the file writes one directory up and back into this lab's document-center folder instead of the avatars folder.",
                    "Prove the write landed somewhere else entirely: visit /a01/download-document?name=pwned_by_avatar_upload.txt (a completely different, already-existing feature) -- it serves back exactly the content you uploaded as an 'avatar,' proving arbitrary file write reached outside the intended directory.",
                ],
            ),
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_a01_avatar_upload_traversal.py -v`
Expected: PASS (both tests).

- [ ] **Step 8: Update A01's cross-cutting test files**

In `tests/test_a01_hints.py`, change the example-count assertion from `12` to `13`.

In `tests/test_a01_overview.py`:

In `test_a01_registered_in_nav`, update the difficulty list to insert `"Medium"` between the existing `"Medium"` (for `arbitrary-file-read`, currently the 8th entry) and `"Hard"` (for `path-traversal-filter-bypass`, currently the 9th entry):

```python
    assert [e.difficulty for e in a01.examples] == [
        "Easy",
        "Medium",
        "Medium",
        "Medium",
        "Hard",
        "Medium",
        "Medium",
        "Medium",
        "Medium",
        "Hard",
        "Medium",
        "Hard",
        "Hard",
    ]
```

The group-name list and group-heading test in this file need NO changes from this task — `avatar-upload-path-traversal` joins the existing "Path Traversal" group, it doesn't create a new one.

- [ ] **Step 9: Run the full A01 test surface**

Run: `pytest tests/test_a01_avatar_upload_traversal.py tests/test_a01_hints.py tests/test_a01_overview.py tests/test_a01_account_update.py tests/test_a01_admin_users.py tests/test_a01_csrf_broken_token.py tests/test_a01_csrf_email_change.py tests/test_a01_directory_traversal.py tests/test_a01_idor.py tests/test_a01_idor_wildcard.py tests/test_a01_open_redirect.py tests/test_a01_http_parameter_pollution.py tests/test_a01_password_change_idor.py -v`
Expected: PASS (all tests, no regressions).

- [ ] **Step 10: Commit**

```bash
git add app/categories/a01_access_control/routes.py \
        app/categories/a01_access_control/__init__.py \
        app/categories/a01_access_control/templates/a01_access_control/avatar_upload.html \
        tests/test_a01_avatar_upload_traversal.py \
        tests/test_a01_hints.py \
        tests/test_a01_overview.py
git commit -m "feat(a01): add Path Traversal via Unsanitized Avatar-Upload Filename example"
```

---

### Task 3: A03 Stored XSS via Untrusted SVG Upload (new "Insecure File Upload" group)

**Files:**
- Modify: `app/categories/a03_injection/routes.py` (add `send_from_directory` to the flask import line; append two new routes at the end of the file, after Task 1's `add_employee()`)
- Modify: `app/categories/a03_injection/__init__.py` (append new `ExampleNav` at the very end of the examples list — after the existing `file-inclusion-lfi-ssti` entry)
- Create: `app/categories/a03_injection/templates/a03_injection/upload_attachment.html`
- Create: `tests/test_a03_svg_upload_xss.py`
- Modify: `tests/test_a03_hints_remaining_groups.py`
- Modify: `tests/test_a03_overview.py`

**Interfaces:**
- Consumes: `os`, `BASE_DIR`, `redirect`, `render_template`, `request`, `url_for` (already imported).
- Produces: routes `a03_injection.upload_attachment` (GET/POST) and `a03_injection.view_attachment` (GET, NOT an `ExampleNav` entry — see Global Constraints). `ExampleNav` id `svg-upload-stored-xss`, forming a brand-new `"Insecure File Upload"` group.

See the Orchestration Note under Task 1 for this task's exact insertion points and the fully-composed final order — this task's Step 8 writes the FINAL, complete 26-entry difficulty list and 10-group name list for all of A03.

- [ ] **Step 1: Read A03's current routes.py and __init__.py fresh (after Task 1 has landed)**

Read both files in full to confirm Task 1's changes are present and locate the exact end of each (this task's insertion points).

- [ ] **Step 2: Write the failing tests**

Create `tests/test_a03_svg_upload_xss.py`:

```python
import io


SVG_PAYLOAD = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)"></svg>'


def test_upload_attachment_page_renders(client):
    response = client.get("/a03/upload-attachment")
    assert response.status_code == 200


def test_upload_and_view_svg_executes_as_svg_document(client):
    data = {"attachment": (io.BytesIO(SVG_PAYLOAD), "poc.svg")}
    response = client.post("/a03/upload-attachment", data=data, content_type="multipart/form-data")
    assert response.status_code == 302

    view_response = client.get("/a03/attachments/poc.svg")
    assert view_response.status_code == 200
    assert view_response.headers["Content-Type"].startswith("image/svg+xml")
    assert "attachment" not in view_response.headers.get("Content-Disposition", "").lower()
    assert b'onload="alert(document.cookie)"' in view_response.data


def test_uploaded_attachment_listed_on_page(client):
    data = {"attachment": (io.BytesIO(SVG_PAYLOAD), "poc.svg")}
    client.post("/a03/upload-attachment", data=data, content_type="multipart/form-data")
    response = client.get("/a03/upload-attachment")
    assert response.status_code == 200
    assert b"poc.svg" in response.data
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_a03_svg_upload_xss.py -v`
Expected: FAIL — `404 NOT FOUND` for both `/a03/upload-attachment` and `/a03/attachments/poc.svg` (neither route exists yet).

- [ ] **Step 4: Add the ATTACHMENTS_DIR constant and the two vulnerable routes**

At the top of `app/categories/a03_injection/routes.py`, change:

```python
from flask import Response, redirect, render_template, render_template_string, request, session, url_for
```

to:

```python
from flask import (
    Response,
    redirect,
    render_template,
    render_template_string,
    request,
    send_from_directory,
    session,
    url_for,
)
```

Near the other directory constants (e.g. next to `SNIPPETS_DIR`), add:

```python
ATTACHMENTS_DIR = os.path.join(BASE_DIR, "instance", "a03_attachments")
```

Append these two routes to the end of the file (after Task 1's `add_employee()`):

```python
@a03_bp.route("/upload-attachment", methods=["GET", "POST"])
def upload_attachment():
    if request.method == "POST":
        os.makedirs(ATTACHMENTS_DIR, exist_ok=True)
        attachment = request.files.get("attachment")
        if attachment and attachment.filename:
            # VULNERABLE: no extension allowlist, no content-type check,
            # no content verification of any kind -- whatever the client
            # uploads is saved and later served back with no override of
            # Flask's default extension-based MIME-type guessing.
            path = os.path.join(ATTACHMENTS_DIR, attachment.filename)
            attachment.save(path)
        return redirect(url_for("a03_injection.upload_attachment"))
    uploaded_files = []
    if os.path.isdir(ATTACHMENTS_DIR):
        uploaded_files = sorted(os.listdir(ATTACHMENTS_DIR))
    return render_template("a03_injection/upload_attachment.html", uploaded_files=uploaded_files)


@a03_bp.route("/attachments/<path:filename>")
def view_attachment(filename):
    # VULNERABLE: serves the uploaded file back via Flask's default
    # extension-based MIME-type guessing, with no forced
    # Content-Disposition: attachment -- an uploaded .svg is served as
    # image/svg+xml, inline, and a direct navigation to this URL renders
    # it as a top-level document, executing any embedded script/onload
    # handler.
    return send_from_directory(ATTACHMENTS_DIR, filename)
```

- [ ] **Step 5: Create the template**

Create `app/categories/a03_injection/templates/a03_injection/upload_attachment.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Stored XSS via Untrusted SVG Upload" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This "upload an attachment" feature saves whatever file you submit
  with no restriction on extension or content, and later serves it back
  by filename with no override of Flask's default behavior: the file's
  own extension decides its Content-Type, and it's served
  <code>inline</code>, not forced to download.
</p>
{% endblock %}

{% block detect %}
<p>
  Upload a plain text file first and open it back -- it's served as
  <code>text/plain</code>, harmless. Now think about what happens if the
  uploaded file's extension is one a browser knows how to RENDER, not
  just display as text.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Upload a file named <code>poc.svg</code> containing:
</p>
<pre>&lt;svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)"&gt;&lt;/svg&gt;</pre>
<p>
  Then click the uploaded file's link, opening it as a top-level page
  (not embedded in an <code>&lt;img&gt;</code> tag -- browsers don't
  execute scripts inside image-context SVGs, but a direct navigation
  renders the SVG as its own document). The server serves this file with
  <code>Content-Type: image/svg+xml</code> and no forced attachment
  disposition, so the browser renders it as a real SVG document and the
  <code>onload</code> handler fires -- genuine, persistent stored XSS:
  this exact file executes for every visitor who opens the link, for as
  long as it stays uploaded.
</p>
{% endblock %}

{% block vulnerable_code %}path = os.path.join(ATTACHMENTS_DIR, attachment.filename)
attachment.save(path)
...
return send_from_directory(ATTACHMENTS_DIR, filename)
{% endblock %}

{% block secure_code %}ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf", "txt"}

ext = attachment.filename.rsplit(".", 1)[-1].lower()
if ext not in ALLOWED_EXTENSIONS:
    abort(400)
path = os.path.join(ATTACHMENTS_DIR, secure_filename(attachment.filename))
attachment.save(path)
...
return send_from_directory(
    ATTACHMENTS_DIR, filename, as_attachment=True, mimetype="application/octet-stream"
)
{% endblock %}

{% block live_example %}
<form method="post" enctype="multipart/form-data" class="mb-3">
  <div class="mb-2">
    <label class="form-label">Attachment file</label>
    <input type="file" class="form-control" name="attachment" required>
  </div>
  <button type="submit" class="btn btn-primary">Upload attachment</button>
</form>
{% if uploaded_files %}
<ul>
  {% for name in uploaded_files %}
  <li><a href="{{ url_for('a03_injection.view_attachment', filename=name) }}" target="_blank">{{ name }}</a></li>
  {% endfor %}
</ul>
{% else %}
<p class="text-muted">No attachments uploaded yet.</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Register the ExampleNav entry**

In `app/categories/a03_injection/__init__.py`, append this new `ExampleNav` at the very end of the examples list (after the `file-inclusion-lfi-ssti` entry, before the list's closing `],`):

```python
            ExampleNav(
                id="svg-upload-stored-xss",
                title="Stored XSS via Untrusted SVG Upload",
                group="Insecure File Upload",
                difficulty="Hard",
                endpoint="a03_injection.upload_attachment",
                hints=[
                    "This 'upload an attachment' feature accepts any file at all -- check whether there's any restriction on file extension or content before it's saved.",
                    "Uploaded files are served back later via Flask's send_from_directory() with no override at all -- the file's own extension decides its Content-Type, exactly like any static file on the web.",
                    "Upload a file named poc.svg containing <svg onload=\"alert(document.cookie)\"></svg>. It's accepted with zero validation.",
                    "Open the uploaded file's link directly (as its own page, not embedded in an <img> tag). The server serves it as image/svg+xml with no forced download -- your browser renders it as a real SVG document and the onload handler fires immediately.",
                    "This is persistent stored XSS with no template-escaping bug anywhere in sight: the vulnerability is entirely in trusting an uploaded file's own extension to decide how the browser interprets it, rather than in any HTML-rendering code path.",
                ],
            ),
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_a03_svg_upload_xss.py -v`
Expected: PASS (all 3 tests).

- [ ] **Step 8: Update A03's cross-cutting test files (final state)**

In `tests/test_a03_hints_remaining_groups.py`, append `"svg-upload-stored-xss"` to the end of the `REMAINING_GROUP_IDS` list.

In `tests/test_a03_overview.py`:

In `test_a03_registered_in_nav`, replace the difficulty list with the FULL 26-entry final state given in the Orchestration Note above.

In `test_a03_examples_grouped_by_vulnerability_subtype`, append `"Insecure File Upload"` to the group-name list (10th entry) and add:
```python
    assert [e.id for e in grouped[9][1]] == ["svg-upload-stored-xss"]
```

`test_a03_overview_shows_vulnerability_subtype_group_headings` needs NO changes — it only asserts 3 of A03's group headings (SQL Injection, XSS, OS Command Injection), not all of them, and none of those 3 are affected by this task.

- [ ] **Step 9: Run the full A03 test surface**

Run: `pytest tests/test_a03_svg_upload_xss.py tests/test_a03_second_order_sqli.py tests/test_a03_hints_sqli_group.py tests/test_a03_hints_remaining_groups.py tests/test_a03_overview.py tests/test_a03_file_inclusion.py tests/test_a03_comments.py -v`
Expected: PASS (all tests, no regressions).

- [ ] **Step 10: Commit**

```bash
git add app/categories/a03_injection/routes.py \
        app/categories/a03_injection/__init__.py \
        app/categories/a03_injection/templates/a03_injection/upload_attachment.html \
        tests/test_a03_svg_upload_xss.py \
        tests/test_a03_hints_remaining_groups.py \
        tests/test_a03_overview.py
git commit -m "feat(a03): add Stored XSS via Untrusted SVG Upload example"
```

---

### Task 4: Final Integration

**Files:**
- Modify: `tests/test_all_examples_have_hints.py`
- Modify: `tests/test_hints.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: the final state of A01 and A03 after Tasks 1-3 — 103 total examples across all categories, max score 2220.
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

Expected: `total examples: 103` (100 + Task 1's 1 + Task 2's 1 + Task 3's 1). If this doesn't read 103, stop and investigate before proceeding.

- [ ] **Step 2: Update the cross-cutting count assertion**

In `tests/test_all_examples_have_hints.py`, change `assert total == 100` to `assert total == 103`.

- [ ] **Step 3: Update the max-score assertions**

In `tests/test_hints.py`, change both `2140` occurrences to `2220`:

```python
    assert "Score: 10 / 2220 points" in body
```
and:
```python
    assert b"Score: 10 / 2220" in response.data
```

- [ ] **Step 4: Update README.md's intro paragraph**

Find the A01 parenthetical, currently ending:
```
absolute path, IDOR via a wildcard pattern-matched lookup, an unvalidated open
redirect, an open-redirect allowlist bypass via domain suffix, and HTTP
parameter pollution enabling role escalation), **A02 Cryptographic Failures**
```
and change it to:
```
absolute path, IDOR via a wildcard pattern-matched lookup, an unvalidated open
redirect, an open-redirect allowlist bypass via domain suffix, HTTP
parameter pollution enabling role escalation, and path traversal via an
unsanitized avatar-upload filename), **A02 Cryptographic Failures**
```

Find the A03 Injection intro text, currently (verified fresh against the real file — this is `README.md` lines 27-32):
```
**A03 Injection** (SQL injection auth bypass, UNION-based exfiltration, reflected XSS,
blind time-based SQLi, error-based SQLi, OS command injection, SQL injection escalating
to remote code execution, stored XSS, XXE file disclosure, XXE SSRF, CSS
attribute-selector data exfiltration via a profile theme, argument injection via an
unsanitized tar export, CSV formula injection via comment export, Unicode
normalization filter bypass, and LFI-to-SSTI via an unsanitized snippet include),
```
change the final clause to:
```
**A03 Injection** (SQL injection auth bypass, UNION-based exfiltration, reflected XSS,
blind time-based SQLi, error-based SQLi, OS command injection, SQL injection escalating
to remote code execution, stored XSS, XXE file disclosure, XXE SSRF, CSS
attribute-selector data exfiltration via a profile theme, argument injection via an
unsanitized tar export, CSV formula injection via comment export, Unicode
normalization filter bypass, LFI-to-SSTI via an unsanitized snippet include,
second-order SQL injection via a stored department value, and stored XSS via an
untrusted SVG upload),
```

- [ ] **Step 5: Update README.md's category summary table**

Change the A01 row, currently (verified fresh against the real file — `README.md` line 133; note this table uses SHORTER abbreviated titles than the full `ExampleNav.title` strings, e.g. "SQLi Auth Bypass" not "Authentication Bypass via SQL Injection" — match that abbreviated style, don't paste the full titles verbatim):
```
| A01 Broken Access Control | Implemented | IDOR (Easy), IDOR on Password-Change API (Medium), Hidden Admin Panel (Medium), Mass Assignment Role Escalation (Hard), Account Takeover via CSRF (Email Change) (Medium), CSRF via Token Presence-Only Validation (Medium), Arbitrary File Read via Document Download (Medium), Path Traversal Filter Bypass via Absolute Path (Hard), IDOR via Wildcard Pattern-Matched Lookup (Medium), Unvalidated Open Redirect (Medium), Open Redirect Allowlist Bypass via Domain Suffix (Hard), HTTP Parameter Pollution Role Escalation (Hard) |
```
to:
```
| A01 Broken Access Control | Implemented | IDOR (Easy), IDOR on Password-Change API (Medium), Hidden Admin Panel (Medium), Mass Assignment Role Escalation (Hard), Account Takeover via CSRF (Email Change) (Medium), CSRF via Token Presence-Only Validation (Medium), Arbitrary File Read via Document Download (Medium), Path Traversal Filter Bypass via Absolute Path (Hard), IDOR via Wildcard Pattern-Matched Lookup (Medium), Unvalidated Open Redirect (Medium), Open Redirect Allowlist Bypass via Domain Suffix (Hard), HTTP Parameter Pollution Role Escalation (Hard), Avatar-Upload Path Traversal (Medium) |
```

Change the A03 row, currently (verified fresh against the real file — `README.md` line 135):
```
| A03 Injection | Implemented | SQLi Auth Bypass (Easy), UNION SQLi Exfiltration (Medium), Error-Based SQLi (Medium), Reflected XSS (Medium), Blind Time-Based SQLi (Hard), OS Command Injection (Hard), SQLi to RCE (Hard), Stored XSS (Hard), XXE File Disclosure (Easy), XXE SSRF (Hard), CSS Attribute-Selector Data Exfiltration (Hard), Argument Injection via tar Export (Hard), CSV Formula Injection (Medium), Unicode Normalization Filter Bypass (Hard), LFI-to-SSTI via Snippet Include (Hard) |
```
to:
```
| A03 Injection | Implemented | SQLi Auth Bypass (Easy), UNION SQLi Exfiltration (Medium), Error-Based SQLi (Medium), Reflected XSS (Medium), Blind Time-Based SQLi (Hard), OS Command Injection (Hard), SQLi to RCE (Hard), Stored XSS (Hard), XXE File Disclosure (Easy), XXE SSRF (Hard), CSS Attribute-Selector Data Exfiltration (Hard), Argument Injection via tar Export (Hard), CSV Formula Injection (Medium), Unicode Normalization Filter Bypass (Hard), LFI-to-SSTI via Snippet Include (Hard), Second-Order SQLi via Department Report (Hard), Stored XSS via SVG Upload (Hard) |
```

- [ ] **Step 6: Run the full test suite**

Run: `pytest -q`
Expected: green, zero failures. Compute the exact expected pass count from the actual new-test counts across Tasks 1-3 (3 + 2 + 3 = 8 new tests) plus the prior baseline (579 passed + 1 skipped, from the previous round's final state) — expect approximately `587 passed, 1 skipped`, but **verify this arithmetic against the actual observed new-test counts from each task's own Step 7/9 runs rather than trusting this estimate blindly** (this plan's own practice from every prior round: never trust a predicted count over an actually-observed one).

- [ ] **Step 7: Commit**

```bash
git add tests/test_all_examples_have_hints.py tests/test_hints.py README.md
git commit -m "test(nav): update total/max-score assertions and README for 3 new examples"
```

---

## Self-Review Notes (for the plan author, not an execution step)

**Spec coverage:** all 3 examples from the spec are fully covered by Tasks 1-3, including the exact route names, the empirically-verified second-order UNION store-then-read-back sequence, the empirically-verified path-traversal resolution depth (`../a01_documents/`), and the empirically-verified Flask `send_from_directory()` default SVG-serving headers (`image/svg+xml`, `inline`).

**Placeholder scan:** no TBD/TODO; every step has literal, complete code.

**Type/naming consistency:** every new route name matches its `ExampleNav.endpoint` value and every `url_for()` call across all three tasks' templates and tests. `view_attachment` deliberately has NO `ExampleNav` entry of its own (per the Global Constraints section) — its ONLY reference is via `url_for()` inside `upload_attachment.html`'s `live_example` block and inside the test file, both confirmed consistent.

**Deviation from the design spec, caught during plan-writing:** the spec's Example 2 narrative describes overwriting the EXISTING seeded `welcome.txt`. During planning, this was refined to target a fresh sentinel filename (`pwned_by_avatar_upload.txt`) instead, to avoid a test corrupting shared, non-test-isolated filesystem fixture state (`instance/a01_documents/welcome.txt` is a real file on disk that persists across test runs, unlike the in-memory test database). The underlying vulnerability, mechanism, and "prove it via the existing download-document route" claim are all unchanged — only the specific target filename changed, and this is called out explicitly in Task 2's own "Test-design note."

**The Orchestration Note's fully-composed order:** independently derived from A03's actual current 24-entry `__init__.py` (read fresh during plan-writing) plus Tasks 1 and 3's own stated insertion points, and cross-checked against each task's own Step 8 test-file edits at every intermediate stage (25-entry after Task 1, 26-entry final after Task 3) — consistent throughout, avoiding the exact "asserts a later task's final state too early" class of bug a prior round's plan self-review caught and fixed.

**Task 4's final assertions:** the 100→103 and 2140→2220 changes are arithmetically exact (Task 1: +1 Hard = +30; Task 2: +1 Medium = +20; Task 3: +1 Hard = +30; total +80). Task 4 Step 1 has the implementer verify the actual total before touching any assertion, rather than trusting this arithmetic blindly, matching this plan's own Global Constraints spirit and the practice established in every prior round's final task.

**README.md's exact current text, verified fresh during self-review (not left as "read fresh" placeholders):** both the A01/A03 intro-paragraph wording and the A01/A03 category-table rows were read directly from the real file during plan-writing and are quoted verbatim in Task 4 Steps 4-5, including the table's abbreviated-title convention (confirmed distinct from the full `ExampleNav.title` strings) — this closes the exact class of gap a prior round's self-review caught (an unverified guess at a table row's wording that turned out to be wrong).
