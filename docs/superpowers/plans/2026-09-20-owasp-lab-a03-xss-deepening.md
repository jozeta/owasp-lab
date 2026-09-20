# A03 XSS Deepening (Filter Bypass Challenge) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one new Hard XSS example, "Filter Bypass Challenge," to A03's
existing Cross-Site Scripting (XSS) nav group — three independently naive
server-side filters (level 1/2/3), each with a genuine bypass, taught via
the existing multi-task "Show solution" pattern.

**Architecture:** One new route (`GET /a03/filter-challenge`) in the
existing `app/categories/a03_injection/routes.py`, selecting one of three
small vulnerable filter functions via a `level` query param and reflecting
the filtered result with `|safe` — matching this project's established
build-raw-HTML-then-`|safe` vulnerable pattern. One new template reusing
the existing `{% block tasks %}` section from `example_page_base.html`
as-is. One new nav entry inserted into the existing XSS group. No new
model, no new seed data, no new dependency, no base-template changes.

**Tech Stack:** Flask, Jinja2, Bootstrap 5 (`collapse` component, already
vendored), pytest + Flask test client.

**Spec:** `docs/superpowers/specs/2026-09-20-owasp-lab-a03-xss-deepening-design.md`

## Global Constraints

- No change to the existing XSS examples (`reflected-xss`/`stored-xss`) or
  their routes/templates/tests.
- No change to the shared `{% block tasks %}` base-template mechanism in
  `app/core/templates/core/example_page_base.html` — reuse it exactly as
  built in the SQLi-deepening sub-project.
- DOM-based XSS is explicitly out of scope — do not add it anywhere.
- No Docker/browser verification task in this plan. This is an
  **intentional deviation** from every prior A03 sub-project's plan: every
  technique here is a pure server-side string-transformation bug, fully
  provable through the Flask test client alone (confirmed in the spec's
  Testing section) — this is not an oversight.
- No new pip dependency, no new docker-compose service, no new model, no
  new migration.
- The three filter functions and their exact bypass payloads are
  specified below verbatim from the spec — do not invent different ones.

---

### Task 1: Filter Bypass Challenge — route, template, nav, and tests

**Files:**
- Modify: `app/categories/a03_injection/routes.py` (add `import re`, three
  filter functions, the `filter_challenge()` route)
- Modify: `app/categories/a03_injection/__init__.py` (new `ExampleNav`
  entry in the existing "Cross-Site Scripting (XSS)" group)
- Create: `app/categories/a03_injection/templates/a03_injection/filter_challenge.html`
- Create: `tests/test_a03_filter_challenge.py`
- Modify: `tests/test_a03_overview.py` (update the two nav-list assertions
  for the 15th entry)

**Interfaces:**
- Produces: route `a03_injection.filter_challenge` at `GET /a03/filter-challenge`,
  accepting query params `level` (`"1"`/`"2"`/`"3"`, default/fallback `"1"`)
  and `payload` (default `""`); template context `level: str`,
  `payload: str`, `filtered: str`.
- Consumes: nothing from earlier A03 sub-projects — this task is fully
  self-contained (no new model, no seed data).

---

- [ ] **Step 1: Write the failing route-level tests**

Create `tests/test_a03_filter_challenge.py`:

```python
def test_filter_challenge_level1_legitimate_input_passes_through(client):
    response = client.get(
        "/a03/filter-challenge", query_string={"level": "1", "payload": "hello"}
    )
    assert response.status_code == 200
    assert b'<div id="output" class="border rounded p-2">hello</div>' in response.data


def test_filter_challenge_level1_blocks_naive_script_tag(client):
    # Assert the full live-output wrapper, not a bare substring match --
    # "[blocked: script tag detected]" also appears, unconditionally, in
    # this page's own static vulnerable_code sample (rendered on every
    # page load regardless of what payload was submitted), so a bare
    # substring assertion would pass vacuously even if the filter were
    # broken or removed entirely.
    response = client.get(
        "/a03/filter-challenge",
        query_string={"level": "1", "payload": "<script>alert(1)</script>"},
    )
    assert response.status_code == 200
    assert (
        b'<div id="output" class="border rounded p-2">'
        b"[blocked: script tag detected]</div>"
    ) in response.data
    assert b"<script>alert(1)</script>" not in response.data


def test_filter_challenge_level1_bypass_executes(client):
    payload = "<img src=x onerror=console.log('LEVEL-1-BYPASS')>"
    response = client.get(
        "/a03/filter-challenge", query_string={"level": "1", "payload": payload}
    )
    assert response.status_code == 200
    assert (
        b'<div id="output" class="border rounded p-2">'
        b"<img src=x onerror=console.log('LEVEL-1-BYPASS')></div>"
    ) in response.data


def test_filter_challenge_level2_legitimate_input_passes_through(client):
    response = client.get(
        "/a03/filter-challenge", query_string={"level": "2", "payload": "hello"}
    )
    assert response.status_code == 200
    assert b'<div id="output" class="border rounded p-2">hello</div>' in response.data


def test_filter_challenge_level2_strips_naive_script_tag(client):
    response = client.get(
        "/a03/filter-challenge",
        query_string={"level": "2", "payload": "<script>alert(1)</script>"},
    )
    assert response.status_code == 200
    assert (
        b'<div id="output" class="border rounded p-2">alert(1)</div>' in response.data
    )
    assert b"<script>alert(1)</script>" not in response.data


def test_filter_challenge_level2_bypass_reconstructs_script_tag(client):
    # After the filter strips "<script>" and "</script>" as two separate,
    # non-recursive passes, the leftover fragments recombine into a real
    # <script> tag the filter never gets to re-scan.
    payload = "<scr<script>ipt>console.log('LEVEL-2-BYPASS')</scr</script>ipt>"
    response = client.get(
        "/a03/filter-challenge", query_string={"level": "2", "payload": payload}
    )
    assert response.status_code == 200
    assert (
        b'<div id="output" class="border rounded p-2">'
        b"<script>console.log('LEVEL-2-BYPASS')</script></div>"
    ) in response.data


def test_filter_challenge_level3_legitimate_input_passes_through(client):
    response = client.get(
        "/a03/filter-challenge", query_string={"level": "3", "payload": "hello"}
    )
    assert response.status_code == 200
    assert (
        b'<input type="text" class="form-control" value="hello" '
        b'placeholder="Your name" readonly>'
    ) in response.data


def test_filter_challenge_level3_escapes_naive_script_tag(client):
    response = client.get(
        "/a03/filter-challenge",
        query_string={"level": "3", "payload": "<script>alert(1)</script>"},
    )
    assert response.status_code == 200
    assert (
        b'<input type="text" class="form-control" '
        b'value="&lt;script&gt;alert(1)&lt;/script&gt;" '
        b'placeholder="Your name" readonly>'
    ) in response.data
    assert b"<script>alert(1)</script>" not in response.data


def test_filter_challenge_level3_bypass_breaks_out_of_attribute(client):
    # The filter's replace() calls only ever touch "<" and ">" -- a lone
    # double-quote sails through untouched and closes the value="..."
    # attribute early, turning the rest of the payload into two brand-new
    # attributes (autofocus + onfocus) on the same <input> tag.
    payload = "\" autofocus onfocus=\"console.log('LEVEL-3-BYPASS')"
    response = client.get(
        "/a03/filter-challenge", query_string={"level": "3", "payload": payload}
    )
    assert response.status_code == 200
    assert (
        b'<input type="text" class="form-control" value="" autofocus '
        b"onfocus=\"console.log('LEVEL-3-BYPASS')\" "
        b'placeholder="Your name" readonly>'
    ) in response.data


def test_filter_challenge_invalid_level_defaults_to_level_1(client):
    response = client.get(
        "/a03/filter-challenge", query_string={"level": "9", "payload": "hello"}
    )
    assert response.status_code == 200
    assert b'<div id="output" class="border rounded p-2">hello</div>' in response.data


def test_filter_challenge_tasks_hidden_when_exploit_instructions_off(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get("/a03/filter-challenge")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"Detect" not in response.data
    assert b"Tasks" not in response.data


def test_filter_challenge_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Filter Bypass Challenge" in response.data
    assert b'href="/a03/filter-challenge"' in response.data
```

The `app` and `client` fixtures come from the project's existing
`conftest.py` (same fixtures every other A03 test file uses — no new
fixture is needed here since this feature has no model/seed data).

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `pytest tests/test_a03_filter_challenge.py -v`
Expected: every test fails with a 404 (route `/a03/filter-challenge`
doesn't exist yet) or an import/collection error if the route module
doesn't define it at all.

- [ ] **Step 3: Add the vulnerable filter functions and route**

In `app/categories/a03_injection/routes.py`, add `import re` to the
top-of-file imports (alphabetically between `import os` and
`import subprocess`):

```python
import os
import re
import subprocess
import urllib.request
```

Then add the following at the end of the file, after the existing
`roster_lookup()` route:

```python
def filter_level_1(payload: str) -> str:
    # VULNERABLE: blocks only the literal substring "<script", nothing else
    if "<script" in payload.lower():
        return "[blocked: script tag detected]"
    return payload


def filter_level_2(payload: str) -> str:
    # VULNERABLE: strips "<script>" and "</script>" as two SEPARATE passes --
    # doesn't re-scan its own output, so nested/interleaved tags reconstruct
    # a real <script> tag from the leftover fragments
    payload = re.sub(r"<script>", "", payload, flags=re.IGNORECASE)
    payload = re.sub(r"</script>", "", payload, flags=re.IGNORECASE)
    return payload


def filter_level_3(payload: str) -> str:
    # VULNERABLE: escapes only angle brackets -- safe in a tag context, but
    # this value is reflected inside an HTML attribute, where an unescaped
    # quote is what actually needs escaping
    return payload.replace("<", "&lt;").replace(">", "&gt;")


@a03_bp.route("/filter-challenge")
def filter_challenge():
    level = request.args.get("level", "1")
    payload = request.args.get("payload", "")
    if level == "2":
        filtered = filter_level_2(payload)
    elif level == "3":
        filtered = filter_level_3(payload)
    else:
        level = "1"
        filtered = filter_level_1(payload)
    return render_template(
        "a03_injection/filter_challenge.html",
        level=level,
        payload=payload,
        filtered=filtered,
    )
```

- [ ] **Step 4: Create the template**

Create `app/categories/a03_injection/templates/a03_injection/filter_challenge.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Filter Bypass Challenge" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This page runs three independent, deliberately naive filters against
  your input, selected with the <code>level</code> parameter below. Each
  filter is meant to neutralize script injection on its own — there's no
  framework-level escaping backing any of them up, since the filtered
  result is rendered with <code>|safe</code>, which disables Jinja's
  automatic escaping entirely. All three filters are real code that
  genuinely block the naive payload they were written against — the
  question for each level is what case they didn't think of.
</p>
{% endblock %}

{% block detect %}
<p>
  Try each level with an ordinary word like <code>hello</code> — it
  passes through unchanged everywhere. Then try
  <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> at each level: Level 1
  replaces it with a block message, Level 2 strips the tags out entirely
  (leaving inert leftover text), and Level 3 turns the angle brackets into
  harmless entities. Every filter visibly does something — confirming a
  bypass means finding the one input shape each filter's author didn't
  anticipate.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Each level's filter has a real gap once you look at it closely — a
  choice of tag it doesn't check for, a stripping pass that doesn't
  re-scan its own output, or a character class it doesn't escape in the
  context it's actually used in. Work through the three graduated Tasks
  below, from a simple tag swap to a fully filter-defeating nested tag to
  an attribute-context break-out that needs no angle brackets at all.
</p>
{% endblock %}

{% block tasks %}
<ol class="list-unstyled">
  <li class="mb-4">
    <strong>Task 1 (Easy): Bypass the Level 1 filter, which blocks only
    the literal substring <code>&lt;script</code>.</strong>
    <p>Set the level selector to <strong>Level 1</strong> and find a
    payload that runs JavaScript without ever containing that
    substring.</p>
    <button class="btn btn-sm btn-outline-secondary" type="button"
            data-bs-toggle="collapse" data-bs-target="#task1-solution">
      Show solution
    </button>
    <div class="collapse mt-2" id="task1-solution">
      <div class="card card-body">
        <p>Submit
        <code>&lt;img src=x onerror=console.log('LEVEL-1-BYPASS')&gt;</code>.
        The filter only ever checks for the substring
        <code>&lt;script</code> — an <code>&lt;img&gt;</code> tag with a
        broken <code>src</code> and an <code>onerror</code> handler never
        contains it, so it sails through untouched and fires the moment
        the browser fails to load the image.</p>
      </div>
    </div>
  </li>
  <li class="mb-4">
    <strong>Task 2 (Medium): Bypass the Level 2 filter, which strips
    <code>&lt;script&gt;</code> and <code>&lt;/script&gt;</code> as two
    separate, one-shot passes.</strong>
    <p>Set the level selector to <strong>Level 2</strong>. The filter
    removes both substrings, but it never re-scans its own output after
    removing them.</p>
    <button class="btn btn-sm btn-outline-secondary" type="button"
            data-bs-toggle="collapse" data-bs-target="#task2-solution">
      Show solution
    </button>
    <div class="collapse mt-2" id="task2-solution">
      <div class="card card-body">
        <p>Submit
        <code>&lt;scr&lt;script&gt;ipt&gt;console.log('LEVEL-2-BYPASS')&lt;/scr&lt;/script&gt;ipt&gt;</code>.
        The filter's first pass removes the inner
        <code>&lt;script&gt;</code>, and its second pass removes the inner
        <code>&lt;/script&gt;</code> — but doing so leaves the surrounding
        fragments <code>&lt;scr</code> + <code>ipt&gt;</code> and
        <code>&lt;/scr</code> + <code>ipt&gt;</code> sitting right next to
        each other, which recombine into a real
        <code>&lt;script&gt;console.log('LEVEL-2-BYPASS')&lt;/script&gt;</code>
        tag that the filter never gets a chance to see.</p>
      </div>
    </div>
  </li>
  <li class="mb-4">
    <strong>Task 3 (Hard): Bypass the Level 3 filter, which escapes only
    <code>&lt;</code> and <code>&gt;</code> — safe against a tag
    injection, but this value is reflected inside an HTML
    attribute.</strong>
    <p>Set the level selector to <strong>Level 3</strong>. You don't need
    a single angle bracket to break out of an attribute value — you need
    a quote.</p>
    <button class="btn btn-sm btn-outline-secondary" type="button"
            data-bs-toggle="collapse" data-bs-target="#task3-solution">
      Show solution
    </button>
    <div class="collapse mt-2" id="task3-solution">
      <div class="card card-body">
        <p>Submit
        <code>" autofocus onfocus="console.log('LEVEL-3-BYPASS')</code>.
        The filter's <code>replace()</code> calls only ever touch
        <code>&lt;</code> and <code>&gt;</code>, so a lone double-quote
        sails through untouched. Since this value is reflected inside
        <code>value="..."</code>, that quote closes the attribute early,
        and everything after it — <code>autofocus
        onfocus="console.log(...)"</code> — becomes two brand-new
        attributes on the same tag. <code>autofocus</code> makes the
        browser focus the field the instant the page loads, which fires
        <code>onfocus</code> immediately, with no click or angle bracket
        required.</p>
      </div>
    </div>
  </li>
</ol>
{% endblock %}

{% block vulnerable_code %}def filter_level_1(payload):
    if "&lt;script" in payload.lower():
        return "[blocked: script tag detected]"
    return payload

def filter_level_2(payload):
    payload = re.sub(r"&lt;script&gt;", "", payload, flags=re.IGNORECASE)
    payload = re.sub(r"&lt;/script&gt;", "", payload, flags=re.IGNORECASE)
    return payload

def filter_level_3(payload):
    return payload.replace("&lt;", "&amp;lt;").replace("&gt;", "&amp;gt;")
# all three rendered with {% raw %}{{ filtered|safe }}{% endraw %} -- bypasses
# Jinja's own escaping entirely, so the filter function is the ONLY defense
{% endblock %}

{% block secure_code %}# Don't hand-roll a blacklist/allowlist filter -- let Jinja's automatic
# escaping handle every context correctly (tag AND attribute):
return render_template("filter_challenge.html", payload=payload)
# template: value="{% raw %}{{ payload }}{% endraw %}"  (no |safe -- Jinja
# escapes &lt;, &gt;, &amp;, ', " for you, in whatever context it's used)
{% endblock %}

{% block live_example %}
<form method="get" class="mb-3">
  <div class="row g-2 align-items-end">
    <div class="col-auto">
      <label class="form-label" for="filter-level">Level</label>
      <select class="form-select" id="filter-level" name="level">
        <option value="1" {% if level == "1" %}selected{% endif %}>Level 1</option>
        <option value="2" {% if level == "2" %}selected{% endif %}>Level 2</option>
        <option value="3" {% if level == "3" %}selected{% endif %}>Level 3</option>
      </select>
    </div>
    <div class="col">
      <label class="form-label" for="filter-payload">Payload</label>
      <input type="text" class="form-control" id="filter-payload" name="payload" value="{{ payload }}">
    </div>
    <div class="col-auto">
      <button type="submit" class="btn btn-primary">Submit</button>
    </div>
  </div>
</form>
{% if level == "3" %}
<p class="mb-1">Reflected inside an HTML attribute:</p>
<input type="text" class="form-control" value="{{ filtered|safe }}" placeholder="Your name" readonly>
{% else %}
<p class="mb-1">Reflected inside the page body:</p>
<div id="output" class="border rounded p-2">{{ filtered|safe }}</div>
{% endif %}
{% endblock %}
```

- [ ] **Step 5: Run the new tests to verify they pass**

Run: `pytest tests/test_a03_filter_challenge.py -v`
Expected: all tests PASS except the two overview/registration tests, which
still fail until Step 6 registers the nav entry.

- [ ] **Step 6: Register the nav entry**

In `app/categories/a03_injection/__init__.py`, insert a new `ExampleNav`
immediately after the existing `stored-xss` entry and before the
`command-injection` entry:

```python
            ExampleNav(
                id="stored-xss",
                title="Stored XSS in Comments",
                group="Cross-Site Scripting (XSS)",
                difficulty="Hard",
                endpoint="a03_injection.comments",
            ),
            ExampleNav(
                id="filter-challenge",
                title="Filter Bypass Challenge",
                group="Cross-Site Scripting (XSS)",
                difficulty="Hard",
                endpoint="a03_injection.filter_challenge",
            ),
            ExampleNav(
                id="command-injection",
                title="OS Command Injection in Host Lookup Tool",
                group="OS Command Injection",
                difficulty="Hard",
                endpoint="a03_injection.host_lookup",
            ),
```

(The `stored-xss` and `command-injection` entries already exist —
only the `filter-challenge` block between them is new.)

- [ ] **Step 7: Update `tests/test_a03_overview.py`'s nav-list assertions**

Replace the `test_a03_registered_in_nav` function's difficulty-list
assertion with the updated 15-entry list (a new `"Hard"` inserted at
position 7, for the new `filter-challenge` entry landing between
`stored-xss` and `command-injection`):

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
function's XSS-group assertion (the rest of the function is unchanged):

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
    assert [e.id for e in grouped[2][1]] == ["command-injection"]
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
Expected: all tests PASS, including every test added in Step 1 and every
existing A01/A02/A04/A03 test (none of which this task touches except the
two `test_a03_overview.py` assertions updated in Step 7).

- [ ] **Step 9: Commit**

```bash
git add app/categories/a03_injection/routes.py \
        app/categories/a03_injection/__init__.py \
        app/categories/a03_injection/templates/a03_injection/filter_challenge.html \
        tests/test_a03_filter_challenge.py \
        tests/test_a03_overview.py
git commit -m "feat: add A03 Filter Bypass Challenge XSS example with three graduated bypass tasks (Hard)"
```

---

## Notes for the executor

- **No Docker/browser verification task follows this one.** Per the spec's
  Testing section, every technique here (substring blacklist, naive
  tag-stripping, angle-bracket-only escaping) is a pure Python
  string-transformation bug with no database, no external service, and no
  client-side JavaScript execution involved — the Flask test client's
  assertions on raw response bytes are a complete, sufficient proof for
  all three bypasses. Do not add a Docker verification step; its absence
  here is intentional, not an oversight carried over from the SQLi/LDAP/
  XXE/SSTI plan template.
- **Escaping discipline.** Every illustrative bypass payload or filter
  code snippet shown as *readable text* in the template (Explanation,
  Detect, Exploitation, Task descriptions, `vulnerable_code`/`secure_code`
  blocks) must have its literal `<`, `>`, and `&` characters written as
  `&lt;`, `&gt;`, `&amp;` — Jinja does **not** autoescape literal block
  content, only `{{ }}` expressions, so an un-escaped `<script>` typed
  directly into template text would render as a real tag. This plan's
  template code above already does this throughout; double-check any
  further edits preserve it.
- **Vacuous-test guard, already designed in:** the `LEVEL-1-BYPASS`,
  `LEVEL-2-BYPASS`, and `LEVEL-3-BYPASS` proof tokens appear in the Tasks
  section's solution text too (as teaching content), but always inside
  properly-escaped `&lt;`/`&gt;` markup or, for Level 3, as a bare payload
  string with no surrounding `value="..."` context. Every test assertion
  above matches the *fully reconstructed, exact* live-reflection output
  (e.g. the complete `<div id="output" class="border rounded p-2">...`
  wrapper, or the complete `value="" autofocus onfocus="..."` attribute
  sequence) — a byte sequence that only the real filter/reflection code
  path can produce, not a substring that could also appear in the static
  solution prose. Preserve this precision if the template or tests change
  during implementation; do not loosen an assertion to a bare
  `b"LEVEL-1-BYPASS" in response.data`-style check.
