# HTTP Parameter Pollution, IDOR, Insecure Randomness & Open Redirect Additions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 5 new intentionally-vulnerable examples to the OWASP Top 10 Training Lab — an IDOR-via-wildcard-lookup example, two Open Redirect examples, and an HTTP Parameter Pollution example in A01, plus a time-seeded-PRNG example in A02 — bringing the app from 95 to 100 examples and max score from 2010 to 2140.

**Architecture:** All five examples are self-contained additions to their category's existing `routes.py`/`__init__.py`/`templates/`. No new SQLAlchemy models anywhere — the IDOR example queries the existing `User` model with a different operator, the HPP example writes to the existing `User.role` column, and the Open Redirect/PRNG examples need no persistent state at all.

**Tech Stack:** Flask, Jinja2, Python's `random`/`time`/`urllib.parse` standard-library modules, pytest with Flask's test client (no mocking — the PRNG test must genuinely re-derive the same key via `random.seed()`, not a stand-in).

**Spec:** `docs/superpowers/specs/2026-09-27-owasp-lab-hpp-idor-randomness-redirect-additions-design.md`

## Global Constraints

- No new SQLAlchemy models — the IDOR example reuses the existing `User` model (queried via `.like()` instead of `==`); the HPP example writes to the existing `User.role` column; the two Open Redirect examples and the PRNG example need no model at all.
- Every `ExampleNav.hints` list has 3-5 entries, each non-empty, no duplicates within the list.
- Within each category's `grouped_examples()` output, every group's examples must be sorted Easy → Medium → Hard.
- Hints render through Jinja's autoescaped `{{ hint }}` expression — write raw, unescaped `<`/`>`/`&` in hint text (Jinja escapes it automatically at render time). The six static template blocks (`explanation`/`detect`/`exploitation`/`tasks`/`vulnerable_code`/`secure_code`/`live_example`) are rendered UNESCAPED (raw HTML written directly in the template source) — any literal `<`/`>`/`&` that must appear as visible TEXT (not real markup) inside those blocks must be manually entity-encoded (`&lt;`/`&gt;`/`&amp;`).
- **The vulnerabilities ARE the deliverable.** Never add sanitization, escaping, validation, authentication, or restriction to any new vulnerable code path. The IDOR lookup must never switch from `.like()` to `==`. Neither Open Redirect route may validate/parse the `next` URL's actual host (the filtered one's check must remain exactly the narrow substring test specified). The HPP route's authorization check and its write must keep reading DIFFERENT occurrences of the `role` field (`.get()` vs `.getlist()[-1]`) — never unified to read the same one. The PRNG route must keep seeding `random` with `int(time.time())` — never switch to `secrets.token_hex()` or any other secure source.
- New routes follow each category's existing plain `render_template()`/`redirect()`/`jsonify()` convention — no new abstraction layers.
- Every `ExampleNav.endpoint` must point at a route that renders an HTML explanation page (extending `core/example_page_base.html`, with the "mark as done" UI) — never directly at a raw action/download route.

---

### Task 1: A01 IDOR via Wildcard Pattern-Matched Lookup

**Files:**
- Modify: `app/categories/a01_access_control/routes.py` (append one new route at the end of the file)
- Modify: `app/categories/a01_access_control/__init__.py` (insert new `ExampleNav` immediately after the existing `password-change-idor` entry — inside the "Insecure Direct Object References (IDOR)" group)
- Create: `app/categories/a01_access_control/templates/a01_access_control/lookup_account.html`
- Create: `tests/test_a01_idor_wildcard.py`
- Modify: `tests/test_a01_hints.py`
- Modify: `tests/test_a01_overview.py`

**Interfaces:**
- Consumes: the existing `User` model (`username`, `email`, `display_name`, `role` fields — already imported in `routes.py`).
- Produces: route `a01_access_control.lookup_account` (GET/POST). `ExampleNav` id `idor-wildcard-lookup`, inserted as the 3rd member of the EXISTING "Insecure Direct Object References (IDOR)" group.

## Orchestration Note (read before starting Task 1 — this note also covers Tasks 2 and 3)

Tasks 1, 2, and 3 ALL modify `app/categories/a01_access_control/routes.py`, `__init__.py`, `tests/test_a01_hints.py`, and `tests/test_a01_overview.py`, sequentially, in that order (Task 1 → Task 2 → Task 3). Their insertion points do not physically overlap:
- Task 1's `ExampleNav` entry goes in the MIDDLE of the list (inside the existing IDOR group, near the top).
- Task 2's two `ExampleNav` entries form a brand-new "Open Redirect" group, appended at the very END of the list (after Task 1 has already landed, so after its own IDOR insertion — but since Task 1's insertion is near the top and Task 2's is at the end, they don't collide).
- Task 3's one `ExampleNav` entry forms a brand-new "HTTP Parameter Pollution" group, appended at the very END of the list, AFTER Task 2's Open Redirect group.

All three tasks append their new ROUTES to the end of `routes.py` in the same order (Task 1's route, then Task 2's two routes, then Task 3's route) — routes in this file are always appended in registration order, matching every prior round's convention.

**Re-read all four shared files fresh before starting each of Tasks 1, 2, and 3** — don't assume line numbers from this plan still match exactly, since each task changes what immediately precedes the next task's insertion point.

**The fully-composed final A01 example order, after Tasks 1, 2, and 3 have all landed:**

| # | id | group | difficulty |
|---|---|---|---|
| 1 | idor | Insecure Direct Object References (IDOR) | Easy |
| 2 | password-change-idor | Insecure Direct Object References (IDOR) | Medium |
| 3 | **idor-wildcard-lookup** (Task 1) | Insecure Direct Object References (IDOR) | **Medium** |
| 4 | admin-users | Missing Function-Level Access Control | Medium |
| 5 | mass-assignment | Mass Assignment | Hard |
| 6 | csrf-email-change | Cross-Site Request Forgery | Medium |
| 7 | csrf-token-presence-only | Cross-Site Request Forgery | Medium |
| 8 | arbitrary-file-read | Path Traversal | Medium |
| 9 | path-traversal-filter-bypass | Path Traversal | Hard |
| 10 | **unvalidated-open-redirect** (Task 2) | Open Redirect | **Medium** |
| 11 | **open-redirect-allowlist-bypass** (Task 2) | Open Redirect | **Hard** |
| 12 | **hpp-role-escalation** (Task 3) | HTTP Parameter Pollution | **Hard** |

Final groups (7 total, first-occurrence order): Insecure Direct Object References (IDOR) (now 3 members), Missing Function-Level Access Control, Mass Assignment, Cross-Site Request Forgery, Path Traversal, Open Redirect (2 members), HTTP Parameter Pollution (1 member).

Full difficulty list (12 entries): `Easy, Medium, Medium, Medium, Hard, Medium, Medium, Medium, Hard, Medium, Hard, Hard`

This table is what Task 3's own Step 8 (the final step in this A01 sequence) writes into `tests/test_a01_overview.py` in full. Task 1's own Step 8 writes only the 9-entry intermediate state (through `idor-wildcard-lookup`), and Task 2's Step 8 writes the 11-entry intermediate state (through `open-redirect-allowlist-bypass`) — each task updates the file to its own correct intermediate point, never jumping ahead to a later task's state (a mistake caught and fixed during a prior round's plan self-review).

- [ ] **Step 1: Read A01's current routes.py, __init__.py, and idor.html fresh**

Read `app/categories/a01_access_control/routes.py` in full, `app/categories/a01_access_control/__init__.py` in full, and `app/categories/a01_access_control/templates/a01_access_control/idor.html` (for tone/style reference — the sibling IDOR example). If anything has changed from what's shown below, adapt accordingly — this plan is accurate as of repo tip `92192cd`.

- [ ] **Step 2: Write the failing tests**

Create `tests/test_a01_idor_wildcard.py`:

```python
from app.core.seed import seed_database


def test_lookup_account_exact_match_returns_one_user(app, client):
    with app.app_context():
        seed_database(app)

    response = client.post("/a01/lookup-account", data={"username": "alice"})
    assert response.status_code == 200
    assert b"alice" in response.data
    assert b"bob" not in response.data


def test_lookup_account_wildcard_returns_every_user(app, client):
    with app.app_context():
        seed_database(app)

    response = client.post("/a01/lookup-account", data={"username": "%"})
    assert response.status_code == 200
    assert b"alice" in response.data
    assert b"bob" in response.data
    assert b"carol" in response.data
    assert b"admin" in response.data
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_a01_idor_wildcard.py -v`
Expected: FAIL — `404 NOT FOUND` for `/a01/lookup-account` (route doesn't exist yet).

- [ ] **Step 4: Add the vulnerable route**

Append this route to the end of `app/categories/a01_access_control/routes.py` (after the current last function, `download_document_filtered()`):

```python
@a01_bp.route("/lookup-account", methods=["GET", "POST"])
def lookup_account():
    username = ""
    results = []
    if request.method == "POST":
        username = request.form.get("username", "")
        # VULNERABLE: uses SQL LIKE-style pattern matching instead of an
        # exact equality check -- a bare wildcard character matches
        # every row in the table, not just the one account the caller
        # claims to be looking up.
        results = User.query.filter(User.username.like(username)).all()
    return render_template(
        "a01_access_control/lookup_account.html", username=username, results=results
    )
```

No new imports are needed — `User`, `request`, `render_template` are already imported at the top of this file.

- [ ] **Step 5: Create the template**

Create `app/categories/a01_access_control/templates/a01_access_control/lookup_account.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "IDOR via Wildcard Pattern-Matched Lookup" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A01{% endblock %}

{% block explanation %}
<p>
  This "find my account" feature looks up a user by exact username --
  or at least, that's the intent. The actual query uses SQLAlchemy's
  <code>.like()</code> comparison instead of an equality check, which
  performs SQL pattern matching: <code>%</code> matches any sequence of
  characters (including none at all), and <code>_</code> matches any
  single character. Neither is escaped, validated, or rejected.
</p>
{% endblock %}

{% block detect %}
<p>
  Look up your own username first -- it returns exactly one account, as
  expected. Then submit a bare <code>%</code> as the username instead.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Submit <code>%</code> as the username to look up. Since <code>%</code>
  matches any string at all, EVERY account in the system matches the
  query simultaneously -- the response discloses every user's username,
  email, display name, and role in a single request, with no guessing
  and no iteration required.
</p>
<p>
  This is a different failure mode from a classic IDOR (guessing one
  specific identifier at a time): the bug here is choosing the wrong
  comparison operator for what was meant to be an exact match, turning
  a "look up one account" feature into "dump every account."
</p>
{% endblock %}

{% block vulnerable_code %}username = request.form.get("username", "")
results = User.query.filter(User.username.like(username)).all()
{% endblock %}

{% block secure_code %}username = request.form.get("username", "")
results = User.query.filter(User.username == username).all()
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Username to look up</label>
    <input type="text" class="form-control" name="username" value="{{ username }}" placeholder="alice">
  </div>
  <button type="submit" class="btn btn-primary">Look up</button>
</form>
{% if results %}
<table class="table table-sm mt-3">
  <thead><tr><th>Username</th><th>Email</th><th>Display Name</th><th>Role</th></tr></thead>
  <tbody>
    {% for u in results %}
    <tr><td>{{ u.username }}</td><td>{{ u.email }}</td><td>{{ u.display_name }}</td><td>{{ u.role }}</td></tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Register the ExampleNav entry**

In `app/categories/a01_access_control/__init__.py`, insert this new `ExampleNav` immediately after the `password-change-idor` entry's closing `),` and before the `admin-users` entry:

```python
            ExampleNav(
                id="idor-wildcard-lookup",
                title="IDOR via Wildcard Pattern-Matched Lookup",
                group="Insecure Direct Object References (IDOR)",
                difficulty="Medium",
                endpoint="a01_access_control.lookup_account",
                hints=[
                    "This 'find my account' feature looks up a user by username. Look at exactly how the comparison is implemented -- is it checking for an EXACT match, or something looser?",
                    "The query uses SQLAlchemy's .like() instead of == -- that's SQL pattern matching, not equality. In LIKE syntax, % matches any sequence of characters at all, including an empty one.",
                    "Submit a bare % as the username to look up. Every account in the system matches a pattern that matches everything, so the response discloses every user's data in one request -- no guessing a specific ID required at all.",
                    "This is a different bug shape from a classic IDOR: instead of guessing one identifier at a time, a single wildcard character exploits the WRONG comparison operator being used for what was supposed to be an exact-match lookup.",
                ],
            ),
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_a01_idor_wildcard.py -v`
Expected: PASS (both tests).

- [ ] **Step 8: Update A01's cross-cutting test files (intermediate state)**

In `tests/test_a01_hints.py`, change the example-count assertion from `8` to `9`.

In `tests/test_a01_overview.py`, change `test_a01_registered_in_nav`'s difficulty-list assertion to the 9-entry intermediate state (this task's example inserted as the 3rd entry):

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
        "Hard",
    ]
```

The group-name list and group-heading test in this file need NO changes from this task — `idor-wildcard-lookup` joins the existing "Insecure Direct Object References (IDOR)" group, it doesn't create a new one.

- [ ] **Step 9: Run the full A01 test surface**

Run: `pytest tests/test_a01_idor_wildcard.py tests/test_a01_hints.py tests/test_a01_overview.py tests/test_a01_account_update.py tests/test_a01_admin_users.py tests/test_a01_csrf_broken_token.py tests/test_a01_csrf_email_change.py tests/test_a01_directory_traversal.py tests/test_a01_idor.py tests/test_a01_password_change_idor.py -v`
Expected: PASS (all tests, no regressions).

- [ ] **Step 10: Commit**

```bash
git add app/categories/a01_access_control/routes.py \
        app/categories/a01_access_control/__init__.py \
        app/categories/a01_access_control/templates/a01_access_control/lookup_account.html \
        tests/test_a01_idor_wildcard.py \
        tests/test_a01_hints.py \
        tests/test_a01_overview.py
git commit -m "feat(a01): add IDOR via Wildcard Pattern-Matched Lookup example"
```

---

### Task 2: A01 Open Redirect (2 examples, new "Open Redirect" group)

**Files:**
- Modify: `app/categories/a01_access_control/routes.py` (append two new routes at the end of the file, after Task 1's `lookup_account()`)
- Modify: `app/categories/a01_access_control/__init__.py` (append two new `ExampleNav` entries at the very end of the examples list — after Task 1's `idor-wildcard-lookup` entry)
- Create: `app/categories/a01_access_control/templates/a01_access_control/continue_redirect.html`
- Create: `app/categories/a01_access_control/templates/a01_access_control/continue_redirect_filtered.html`
- Create: `tests/test_a01_open_redirect.py`
- Modify: `tests/test_a01_hints.py`
- Modify: `tests/test_a01_overview.py`

**Interfaces:**
- Consumes: `redirect`, `request` (already imported).
- Produces: routes `a01_access_control.continue_redirect` (GET) and `a01_access_control.continue_redirect_filtered` (GET). `ExampleNav` ids `unvalidated-open-redirect` and `open-redirect-allowlist-bypass`, both forming a brand-new `"Open Redirect"` group.

See the Orchestration Note under Task 1 for this task's exact insertion points and the fully-composed final order.

- [ ] **Step 1: Read A01's current routes.py and __init__.py fresh (after Task 1 has landed)**

Read both files in full to confirm Task 1's changes are present and locate the exact end of each (this task's insertion points).

- [ ] **Step 2: Write the failing tests**

Create `tests/test_a01_open_redirect.py`:

```python
def test_continue_redirects_to_internal_path(client):
    response = client.get("/a01/continue", query_string={"next": "/a01/"})
    assert response.status_code == 302
    assert response.headers["Location"] == "/a01/"


def test_continue_redirects_to_arbitrary_external_url(client):
    payload = "https://evil.example.com/phish"
    response = client.get("/a01/continue", query_string={"next": payload})
    assert response.status_code == 302
    assert response.headers["Location"] == payload


def test_continue_filtered_blocks_unrelated_external_url(client):
    response = client.get(
        "/a01/continue-filtered", query_string={"next": "https://evil.example.com/phish"}
    )
    assert response.status_code == 400


def test_continue_filtered_bypassed_via_domain_suffix(client):
    payload = "https://trusted-partner.example.evil.example.com/phish"
    response = client.get("/a01/continue-filtered", query_string={"next": payload})
    assert response.status_code == 302
    assert response.headers["Location"] == payload
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_a01_open_redirect.py -v`
Expected: FAIL — `404 NOT FOUND` for both routes (neither exists yet).

- [ ] **Step 4: Add the two vulnerable routes**

Append these two routes to the end of `app/categories/a01_access_control/routes.py` (after Task 1's `lookup_account()`):

```python
@a01_bp.route("/continue")
def continue_redirect():
    next_url = request.args.get("next", "/")
    # VULNERABLE: redirects to any URL at all, with zero validation --
    # Flask's redirect() sends whatever string it's given as the
    # Location header, external URLs included.
    return redirect(next_url)


@a01_bp.route("/continue-filtered")
def continue_redirect_filtered():
    next_url = request.args.get("next", "/")
    # VULNERABLE: only checks whether the trusted hostname appears
    # ANYWHERE in the string, never that it's genuinely the URL's host --
    # a URL whose real host is entirely different can still contain this
    # substring, e.g. as part of a longer, attacker-controlled subdomain.
    if "trusted-partner.example" in next_url:
        return redirect(next_url)
    return "Invalid redirect target", 400
```

No new imports are needed — `redirect`, `request` are already imported at the top of this file.

- [ ] **Step 5: Create the two templates**

Create `app/categories/a01_access_control/templates/a01_access_control/continue_redirect.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Unvalidated Open Redirect" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A01{% endblock %}

{% block explanation %}
<p>
  This "continue to your destination" feature redirects the browser to
  whatever URL is given in the <code>next</code> parameter, with no
  validation of any kind. Flask's <code>redirect()</code> helper sends
  the exact string it's given as the response's <code>Location</code>
  header -- it performs no host-checking on its own.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit <code>?next=/a01/</code> and confirm you land back on this
  category's overview page. Then try an external URL instead.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Submit <code>?next=https://evil.example.com/phish</code> -- the
  response is a real redirect straight to that external address, no
  validation stops it.
</p>
<p>
  Real-world impact: an attacker crafts a link like
  <code>https://this-trusted-site.com/continue?next=https://evil.example.com/phish</code>
  and distributes it via email or social media. Because the visible
  domain in the link is the trusted site's own, victims are far more
  likely to click it than a raw link to the attacker's domain --
  landing them on a convincing phishing page after a brief,
  legitimate-looking bounce through a site they already trust.
</p>
{% endblock %}

{% block vulnerable_code %}next_url = request.args.get("next", "/")
return redirect(next_url)
{% endblock %}

{% block secure_code %}next_url = request.args.get("next", "/")
# Only ever redirect to a path on this same site -- never an absolute URL:
if next_url.startswith("/") and not next_url.startswith("//"):
    return redirect(next_url)
return redirect("/")
{% endblock %}

{% block live_example %}
<form method="get">
  <div class="mb-2">
    <label class="form-label">Destination URL</label>
    <input type="text" class="form-control" name="next" placeholder="https://evil.example.com/phish">
  </div>
  <button type="submit" class="btn btn-primary">Continue</button>
</form>
{% endblock %}
```

Create `app/categories/a01_access_control/templates/a01_access_control/continue_redirect_filtered.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Open Redirect Allowlist Bypass via Domain Suffix" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A01{% endblock %}

{% block explanation %}
<p>
  This version of the "continue" feature adds a check: the destination
  URL must contain <code>trusted-partner.example</code>, this app's one
  approved external redirect target. This genuinely blocks an
  unrelated external URL.
</p>
{% endblock %}

{% block detect %}
<p>
  Confirm the filter works: try <code>?next=https://evil.example.com/</code>
  -- rejected. Now think about what "contains the substring" actually
  checks, versus what it was meant to check.
</p>
{% endblock %}

{% block exploitation %}
<p>
  The check only tests whether <code>trusted-partner.example</code>
  appears ANYWHERE in the URL string -- not that it's genuinely the
  URL's host. Submit:
</p>
<pre>?next=https://trusted-partner.example.evil.example.com/phish</pre>
<p>
  This string contains <code>trusted-partner.example</code> as a literal
  substring (right where the filter looks for it), so the check passes
  -- but the URL's REAL host is <code>trusted-partner.example.evil.example.com</code>,
  a domain entirely under the attacker's control (<code>trusted-partner.example</code>
  is merely a subdomain label they chose to include). The redirect goes
  to the attacker's server, not the real trusted partner.
</p>
<p>
  This is the classic "substring allowlist" mistake: checking
  <code>if trusted_domain in url</code> instead of genuinely parsing the
  URL and comparing its actual host. The same bug family affects
  <code>startswith()</code> checks bypassed by a matching subdomain
  prefix, and any check that doesn't parse the URL structure before
  comparing.
</p>
{% endblock %}

{% block vulnerable_code %}next_url = request.args.get("next", "/")
if "trusted-partner.example" in next_url:
    return redirect(next_url)
return "Invalid redirect target", 400
{% endblock %}

{% block secure_code %}import urllib.parse

next_url = request.args.get("next", "/")
host = urllib.parse.urlparse(next_url).hostname
if host == "trusted-partner.example":
    return redirect(next_url)
return "Invalid redirect target", 400
{% endblock %}

{% block live_example %}
<form method="get">
  <div class="mb-2">
    <label class="form-label">Destination URL</label>
    <input type="text" class="form-control" name="next" placeholder="https://trusted-partner.example.evil.example.com/phish">
  </div>
  <button type="submit" class="btn btn-primary">Continue</button>
</form>
{% endblock %}
```

- [ ] **Step 6: Register both ExampleNav entries**

In `app/categories/a01_access_control/__init__.py`, append these two new `ExampleNav` entries at the very end of the examples list (after Task 1's `idor-wildcard-lookup` entry — since Task 1's entry is in the MIDDLE of the list per the Orchestration Note, these go after the CURRENT last entry, which is `path-traversal-filter-bypass`):

```python
            ExampleNav(
                id="unvalidated-open-redirect",
                title="Unvalidated Open Redirect",
                group="Open Redirect",
                difficulty="Medium",
                endpoint="a01_access_control.continue_redirect",
                hints=[
                    "This 'continue to your destination' feature redirects to whatever URL is in the next parameter. Check whether there's any validation on that URL at all before redirecting.",
                    "Flask's redirect() sends the exact string it's given as the response's Location header -- it performs no host-checking of its own. Submit ?next=/a01/ first to confirm the basic flow works.",
                    "Now submit ?next=https://evil.example.com/phish -- the response redirects straight there, no validation stops it. A crafted link using this app's own trusted domain, with this payload as the next parameter, would look far more trustworthy to a victim than a raw link to the attacker's site.",
                ],
            ),
            ExampleNav(
                id="open-redirect-allowlist-bypass",
                title="Open Redirect Allowlist Bypass via Domain Suffix",
                group="Open Redirect",
                difficulty="Hard",
                endpoint="a01_access_control.continue_redirect_filtered",
                hints=[
                    "This version only allows redirecting to trusted-partner.example -- confirm the filter genuinely blocks an unrelated domain first. Then think about exactly WHAT the check tests: is it really confirming the URL's host, or something weaker?",
                    "The check is 'trusted-partner.example' in next_url -- a plain substring test, not a real URL-host comparison. Does that substring have to be at the START of the host to pass?",
                    "Submit ?next=https://trusted-partner.example.evil.example.com/phish -- the substring 'trusted-partner.example' genuinely appears in this string, so the check passes, but the URL's real host is trusted-partner.example.evil.example.com, a domain entirely controlled by whoever registered evil.example.com.",
                    "This is the classic 'substring allowlist' mistake, the same technique real-world open-redirect filter bypasses use against domains like 'whitelisted-site.com.evil.com' -- checking 'does this string contain the trusted name' is never equivalent to 'is this URL's actual host the trusted one.'",
                ],
            ),
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_a01_open_redirect.py -v`
Expected: PASS (all 4 tests).

- [ ] **Step 8: Update A01's cross-cutting test files (intermediate state)**

In `tests/test_a01_hints.py`, change the example-count assertion from `9` (after Task 1) to `11` (this task adds 2 examples at once).

In `tests/test_a01_overview.py`, update to the 11-entry intermediate state:

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
        "Hard",
        "Medium",
        "Hard",
    ]
```

```python
    assert [name for name, _ in grouped] == [
        "Insecure Direct Object References (IDOR)",
        "Missing Function-Level Access Control",
        "Mass Assignment",
        "Cross-Site Request Forgery",
        "Path Traversal",
        "Open Redirect",
    ]
```

Add one more assertion to `test_a01_overview_shows_vulnerability_subtype_group_headings`:

```python
    assert "Open Redirect" in body
```

- [ ] **Step 9: Run the full A01 test surface**

Run: `pytest tests/test_a01_open_redirect.py tests/test_a01_idor_wildcard.py tests/test_a01_hints.py tests/test_a01_overview.py tests/test_a01_account_update.py tests/test_a01_admin_users.py tests/test_a01_csrf_broken_token.py tests/test_a01_csrf_email_change.py tests/test_a01_directory_traversal.py tests/test_a01_idor.py tests/test_a01_password_change_idor.py -v`
Expected: PASS (all tests, no regressions).

- [ ] **Step 10: Commit**

```bash
git add app/categories/a01_access_control/routes.py \
        app/categories/a01_access_control/__init__.py \
        app/categories/a01_access_control/templates/a01_access_control/continue_redirect.html \
        app/categories/a01_access_control/templates/a01_access_control/continue_redirect_filtered.html \
        tests/test_a01_open_redirect.py \
        tests/test_a01_hints.py \
        tests/test_a01_overview.py
git commit -m "feat(a01): add Open Redirect examples (unvalidated + allowlist bypass)"
```

---

### Task 3: A01 HTTP Parameter Pollution — Role Escalation (new "HTTP Parameter Pollution" group)

**Files:**
- Modify: `app/categories/a01_access_control/routes.py` (add `abort` to the flask import line; append one new route at the end of the file, after Task 2's `continue_redirect_filtered()`)
- Modify: `app/categories/a01_access_control/__init__.py` (append new `ExampleNav` at the very end of the examples list — after Task 2's `open-redirect-allowlist-bypass` entry)
- Create: `app/categories/a01_access_control/templates/a01_access_control/update_preferences.html`
- Create: `tests/test_a01_http_parameter_pollution.py`
- Modify: `tests/test_a01_hints.py`
- Modify: `tests/test_a01_overview.py`

**Interfaces:**
- Consumes: `get_current_user()`, `db.session`, `User.role` (all already imported/available).
- Produces: route `a01_access_control.update_preferences` (GET/POST). `ExampleNav` id `hpp-role-escalation`, forming a brand-new `"HTTP Parameter Pollution"` group.

See the Orchestration Note under Task 1 for this task's exact insertion points and the fully-composed final order — this task's Step 8 writes the FINAL, complete 12-entry difficulty list and 7-group name list for all of A01.

- [ ] **Step 1: Read A01's current routes.py and __init__.py fresh (after Task 2 has landed)**

Read both files in full to confirm Task 2's changes are present and locate the exact end of each (this task's insertion points).

- [ ] **Step 2: Write the failing tests**

Create `tests/test_a01_http_parameter_pollution.py`:

```python
from app.core.models import User
from app.core.seed import seed_database
from app.extensions import db


def _login_as(client, user_id):
    with client.session_transaction() as sess:
        sess["user_id"] = user_id


def test_single_admin_role_is_rejected(app, client):
    with app.app_context():
        seed_database(app)
        alice = User.query.filter_by(username="alice").first()
        user_id = alice.id
    _login_as(client, user_id)

    response = client.post("/a01/update-preferences", data={"role": "admin"})
    assert response.status_code == 403

    with app.app_context():
        alice = db.session.get(User, user_id)
        assert alice.role != "admin"


def test_duplicate_role_parameter_bypasses_the_check(app, client):
    with app.app_context():
        seed_database(app)
        alice = User.query.filter_by(username="alice").first()
        user_id = alice.id
    _login_as(client, user_id)

    # Simulates HTTP Parameter Pollution: the same field submitted twice,
    # in this exact order -- the check must see "user" (pass) while the
    # write must apply "admin" (the last occurrence).
    response = client.post(
        "/a01/update-preferences",
        data="role=user&role=admin",
        content_type="application/x-www-form-urlencoded",
    )
    assert response.status_code == 200

    with app.app_context():
        alice = db.session.get(User, user_id)
        assert alice.role == "admin"
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_a01_http_parameter_pollution.py -v`
Expected: FAIL — `404 NOT FOUND` for `/a01/update-preferences` (route doesn't exist yet).

- [ ] **Step 4: Add the vulnerable route**

At the top of `app/categories/a01_access_control/routes.py`, change:

```python
from flask import flash, jsonify, redirect, render_template, request, session, url_for
```

to:

```python
from flask import abort, flash, jsonify, redirect, render_template, request, session, url_for
```

Append this route to the end of the file (after Task 2's `continue_redirect_filtered()`):

```python
@a01_bp.route("/update-preferences", methods=["GET", "POST"])
def update_preferences():
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=request.path))
    updated = False
    if request.method == "POST":
        # VULNERABLE: the authorization check below reads only the
        # FIRST occurrence of a duplicated "role" field
        # (request.form.get()'s documented behavior for repeated keys),
        # but the actual write a few lines later deliberately reads the
        # LAST occurrence instead (request.form.getlist()[-1]) -- a
        # "let a later resubmitted field override an earlier one"
        # convention meant for a legitimate multi-step form. An
        # attacker who submits role=user&role=admin passes the check
        # (which only ever sees "user") while the write applies "admin".
        submitted_role = request.form.get("role", "user")
        if submitted_role not in ("user", "premium"):
            abort(403)
        viewer.role = request.form.getlist("role")[-1]
        db.session.commit()
        updated = True
    return render_template(
        "a01_access_control/update_preferences.html", viewer=viewer, updated=updated
    )
```

- [ ] **Step 5: Create the template**

Create `app/categories/a01_access_control/templates/a01_access_control/update_preferences.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "HTTP Parameter Pollution — Role Escalation" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A01{% endblock %}

{% block explanation %}
<p>
  This "preferences" form is meant to let you switch between the
  "user" and "premium" tiers only -- an authorization check rejects
  anything else. The bug isn't in that check itself: it's that the
  check and the actual write don't agree on WHICH value a duplicated
  form field holds. When the same field name is submitted more than
  once, Werkzeug's <code>request.form.get()</code> always returns the
  FIRST occurrence, while <code>request.form.getlist()</code> returns
  every occurrence in order -- and this route's write path deliberately
  reads the LAST one, to let a later hidden field override an earlier
  one in a (fictional) multi-step version of this form.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit the form normally with role set to "admin" directly -- rejected,
  the check works as expected. Now think about what happens if the SAME
  field name is submitted twice, with two different values.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Submit a request with the <code>role</code> field included TWICE, in
  this order:
</p>
<pre>role=user&amp;role=admin</pre>
<p>
  The authorization check reads <code>request.form.get("role")</code>,
  which returns only the FIRST occurrence -- <code>"user"</code> -- so
  the check passes. The actual write, a few lines later, reads
  <code>request.form.getlist("role")[-1]</code> -- the LAST occurrence,
  <code>"admin"</code> -- and applies that instead. The check and the
  write silently disagreed about which submitted value was "the" role,
  and the write's choice wins.
</p>
<p>
  This is HTTP Parameter Pollution: exploiting the fact that there is no
  single, universal rule for how a server handles a repeated parameter
  name. Different frameworks (and, as demonstrated here, even different
  LINES of code within the exact same framework and the exact same
  request) can disagree about which occurrence "counts" -- and an
  attacker only needs ONE inconsistency between a security check and
  the code path it's meant to protect.
</p>
{% endblock %}

{% block vulnerable_code %}submitted_role = request.form.get("role", "user")  # sees the FIRST occurrence
if submitted_role not in ("user", "premium"):
    abort(403)
viewer.role = request.form.getlist("role")[-1]  # applies the LAST occurrence
db.session.commit()
{% endblock %}

{% block secure_code %}# Read the role exactly once, from exactly one place, and validate
# that SAME value before using it -- never mix .get() and .getlist():
submitted_role = request.form.get("role", "user")
if submitted_role not in ("user", "premium"):
    abort(403)
viewer.role = submitted_role
db.session.commit()
{% endblock %}

{% block live_example %}
{% if viewer %}
<p>Logged in as <strong>{{ viewer.username }}</strong> — current role: <strong>{{ viewer.role }}</strong></p>
{% if updated %}
<div class="alert alert-success">Preferences updated.</div>
{% endif %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Tier</label>
    <select class="form-select" name="role">
      <option value="user">user</option>
      <option value="premium">premium</option>
    </select>
  </div>
  <p class="text-muted small">
    This dropdown can only submit "user" or "premium" — to demonstrate
    the exploit, craft a raw request with the role field repeated, e.g.
    via curl: <code>curl -X POST -d "role=user&amp;role=admin" ...</code>
    (with your session cookie).
  </p>
  <button type="submit" class="btn btn-primary">Update preferences</button>
</form>
{% else %}
<a href="{{ url_for('core.switch_user', next=request.path) }}">Log in to try this example</a>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Register the ExampleNav entry**

In `app/categories/a01_access_control/__init__.py`, append this new `ExampleNav` at the very end of the examples list (after Task 2's `open-redirect-allowlist-bypass` entry, before the list's closing `],`):

```python
            ExampleNav(
                id="hpp-role-escalation",
                title="HTTP Parameter Pollution — Role Escalation",
                group="HTTP Parameter Pollution",
                difficulty="Hard",
                endpoint="a01_access_control.update_preferences",
                hints=[
                    "This 'preferences' form only allows 'user' or 'premium' as a role, and an authorization check enforces that. But look closer: does the check and the actual database write both look at the SAME occurrence of the role field, if it's submitted more than once?",
                    "When a form field is submitted twice with the same name, Werkzeug's request.form.get() always returns the FIRST occurrence. request.form.getlist() returns every occurrence, in the order submitted.",
                    "The authorization check uses .get() (sees the first value); the actual write uses .getlist()[-1] (the last value). Submit a raw request with role included TWICE -- role=user&role=admin, in that exact order -- and the check passes on 'user' while the write applies 'admin'.",
                    "Exact reproduction: curl -X POST -d \"role=user&role=admin\" http://127.0.0.1:5001/a01/update-preferences (with your session cookie) -- your account's role becomes admin, even though the very same request would have been rejected if you'd only submitted role=admin once.",
                ],
            ),
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_a01_http_parameter_pollution.py -v`
Expected: PASS (both tests).

- [ ] **Step 8: Update A01's cross-cutting test files (final state)**

In `tests/test_a01_hints.py`, change the example-count assertion from `11` (after Task 2) to `12`.

In `tests/test_a01_overview.py`, update to the FINAL 12-entry state per the Orchestration Note's table:

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
        "Hard",
        "Medium",
        "Hard",
        "Hard",
    ]
```

```python
    assert [name for name, _ in grouped] == [
        "Insecure Direct Object References (IDOR)",
        "Missing Function-Level Access Control",
        "Mass Assignment",
        "Cross-Site Request Forgery",
        "Path Traversal",
        "Open Redirect",
        "HTTP Parameter Pollution",
    ]
```

Add one more assertion to `test_a01_overview_shows_vulnerability_subtype_group_headings`:

```python
    assert "HTTP Parameter Pollution" in body
```

- [ ] **Step 9: Run the full A01 test surface**

Run: `pytest tests/test_a01_http_parameter_pollution.py tests/test_a01_open_redirect.py tests/test_a01_idor_wildcard.py tests/test_a01_hints.py tests/test_a01_overview.py tests/test_a01_account_update.py tests/test_a01_admin_users.py tests/test_a01_csrf_broken_token.py tests/test_a01_csrf_email_change.py tests/test_a01_directory_traversal.py tests/test_a01_idor.py tests/test_a01_password_change_idor.py -v`
Expected: PASS (all tests, no regressions).

- [ ] **Step 10: Commit**

```bash
git add app/categories/a01_access_control/routes.py \
        app/categories/a01_access_control/__init__.py \
        app/categories/a01_access_control/templates/a01_access_control/update_preferences.html \
        tests/test_a01_http_parameter_pollution.py \
        tests/test_a01_hints.py \
        tests/test_a01_overview.py
git commit -m "feat(a01): add HTTP Parameter Pollution role-escalation example"
```

---

### Task 4: A02 Predictable API Key via Time-Seeded PRNG (new "Weak Random Number Generation" group)

**Files:**
- Modify: `app/categories/a02_crypto_failures/routes.py` (add `import random` and `import time` to the top imports; append one new route at the end of the file)
- Modify: `app/categories/a02_crypto_failures/__init__.py` (append new `ExampleNav` at the very end of the examples list)
- Create: `app/categories/a02_crypto_failures/templates/a02_crypto_failures/generate_api_key.html`
- Create: `tests/test_a02_insecure_randomness.py`
- Modify: `tests/test_a02_hints.py`
- Modify: `tests/test_a02_overview.py`

**Interfaces:**
- Consumes: `render_template`, `request` (already imported).
- Produces: route `a02_crypto_failures.generate_api_key` (GET/POST). `ExampleNav` id `predictable-api-key`, forming a brand-new `"Weak Random Number Generation"` group.

This task is entirely independent of Tasks 1-3 — it touches only A02's files, which none of those tasks modify. It can be run at any point relative to them with no ordering constraint; this plan runs it after Task 3 to match its numbering.

- [ ] **Step 1: Read A02's current routes.py and __init__.py fresh, and forgot_password_api.html for tone**

Read `app/categories/a02_crypto_failures/routes.py` in full, `app/categories/a02_crypto_failures/__init__.py` in full, and `app/categories/a02_crypto_failures/templates/a02_crypto_failures/forgot_password_api.html` (for tone/style reference and the `127.0.0.1:5001` port convention already used in this category). If anything has changed from what's shown below, adapt accordingly.

- [ ] **Step 2: Write the failing tests**

Create `tests/test_a02_insecure_randomness.py`:

```python
import random
import re
import time


def test_generate_api_key_page_renders(client):
    response = client.get("/a02/generate-api-key")
    assert response.status_code == 200


def test_generated_key_is_reproducible_from_a_nearby_timestamp(client):
    before = int(time.time())
    response = client.post("/a02/generate-api-key")
    after = int(time.time())
    assert response.status_code == 200

    body = response.data.decode()
    match = re.search(r"([0-9a-f]{32})", body)
    assert match is not None
    real_key = match.group(1)

    # Simulates an attacker who only knows the approximate generation
    # second (e.g. from the HTTP response's own Date header in a real
    # deployment), searching a small window of candidate timestamps --
    # never the 32-character key space itself.
    reproduced = False
    for t in range(before - 2, after + 3):
        random.seed(t)
        guess = "".join(random.choices("0123456789abcdef", k=32))
        if guess == real_key:
            reproduced = True
            break
    assert reproduced, "the real key was not reproducible from any nearby timestamp"
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_a02_insecure_randomness.py -v`
Expected: FAIL — `404 NOT FOUND` for `/a02/generate-api-key` (route doesn't exist yet).

- [ ] **Step 4: Add the vulnerable route**

At the top of `app/categories/a02_crypto_failures/routes.py`, change:

```python
import hashlib
```

to:

```python
import hashlib
import random
import time
```

Append this route to the end of the file (after the current last function, `forgot_password_api()`):

```python
@a02_bp.route("/generate-api-key", methods=["GET", "POST"])
def generate_api_key():
    api_key = None
    if request.method == "POST":
        # VULNERABLE: seeds Python's RNG with the current Unix
        # timestamp before generating the key -- anyone who knows (or
        # can narrow down) the second this happened can re-seed with
        # that same integer and reproduce the exact same "random" key.
        # random is a Mersenne Twister: fully deterministic given the
        # same seed. No brute-force over the key space itself is ever
        # needed, only over a small window of candidate timestamps.
        random.seed(int(time.time()))
        api_key = "".join(random.choices("0123456789abcdef", k=32))
    return render_template("a02_crypto_failures/generate_api_key.html", api_key=api_key)
```

No further new imports are needed — `render_template`, `request` are already imported at the top of this file.

- [ ] **Step 5: Create the template**

Create `app/categories/a02_crypto_failures/templates/a02_crypto_failures/generate_api_key.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Predictable API Key via Time-Seeded PRNG" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A02{% endblock %}

{% block explanation %}
<p>
  This "generate an API key" feature seeds Python's <code>random</code>
  module with the current Unix timestamp
  (<code>random.seed(int(time.time()))</code>) before generating a
  32-character hex key. Seeding a PRNG with a value an attacker can
  observe or estimate makes its ENTIRE subsequent output sequence
  reproducible -- <code>random</code> is a Mersenne Twister, fully
  deterministic given the same seed.
</p>
{% endblock %}

{% block detect %}
<p>
  Generate a key, noting roughly when you did so (to the second).
  Locally, re-seed Python's <code>random</code> with that same integer
  timestamp and generate a key the same way -- does it match?
</p>
{% endblock %}

{% block exploitation %}
<p>
  Generate a key via the form below and note the current time (to the
  second) as precisely as you can -- in a real deployment, the HTTP
  response's own <code>Date</code> header gives an attacker this exact
  information for free, since it reflects the server's clock at the
  moment of response, moments after the key was generated in the same
  request.
</p>
<pre><code class="language-python">import random

candidate_time = 1731239837  # your best estimate of the generation second
for t in range(candidate_time - 3, candidate_time + 4):
    random.seed(t)
    guess = "".join(random.choices("0123456789abcdef", k=32))
    print(t, guess)</code></pre>
<p>
  One of the guesses in that small window -- typically within a second
  or two of the real generation time -- will match the real key
  exactly. No brute-force search over the 32-character key space
  itself is ever needed; the entire attack reduces to searching a
  handful of candidate timestamps.
</p>
{% endblock %}

{% block vulnerable_code %}random.seed(int(time.time()))
api_key = "".join(random.choices("0123456789abcdef", k=32))
{% endblock %}

{% block secure_code %}import secrets

api_key = secrets.token_hex(16)  # cryptographically secure randomness, no seed involved
{% endblock %}

{% block live_example %}
<form method="post">
  <button type="submit" class="btn btn-primary">Generate API key</button>
</form>
{% if api_key %}
<p class="mt-3">Your new API key: <code>{{ api_key }}</code></p>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Register the ExampleNav entry**

In `app/categories/a02_crypto_failures/__init__.py`, append this new `ExampleNav` at the very end of the examples list (after the `reset-token-referrer-leak` entry, before the list's closing `],`):

```python
            ExampleNav(
                id="predictable-api-key",
                title="Predictable API Key via Time-Seeded PRNG",
                group="Weak Random Number Generation",
                difficulty="Hard",
                endpoint="a02_crypto_failures.generate_api_key",
                hints=[
                    "This 'generate an API key' feature uses Python's random module. Look at exactly how that module is seeded before it generates the key -- is the seed something an attacker could ever guess or observe?",
                    "The seed is random.seed(int(time.time())) -- the current Unix timestamp, to the second. random is a Mersenne Twister PRNG: given the same seed, it always produces the exact same output sequence, every time.",
                    "Note the approximate second a key was generated (in a real deployment, the HTTP response's own Date header gives an attacker this for free). Locally, re-seed random with that same integer and generate a key the same way -- try a small window of nearby seconds if you're not sure of the exact one.",
                    "One of those nearby-second guesses will reproduce the real key exactly -- no brute-force over the 32-character key space itself is needed, only over a handful of candidate timestamps, the same 'small search window' oracle pattern used elsewhere in this lab's blind-injection examples.",
                ],
            ),
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_a02_insecure_randomness.py -v`
Expected: PASS (both tests).

- [ ] **Step 8: Update A02's cross-cutting test files**

In `tests/test_a02_hints.py`, change the example-count assertion from `5` to `6`.

In `tests/test_a02_overview.py`, make these three exact edits (verified fresh against the file's current content — confirmed as of repo tip `92192cd`):

In `test_a02_registered_in_nav`, change:
```python
    assert [e.difficulty for e in a02.examples] == ["Easy", "Medium", "Hard", "Easy", "Medium"]
```
to:
```python
    assert [e.difficulty for e in a02.examples] == ["Easy", "Medium", "Hard", "Easy", "Medium", "Hard"]
```

In `test_a02_examples_grouped_by_vulnerability_subtype`, change:
```python
    assert [name for name, _ in grouped] == [
        "Weak Hashing",
        "Weak Encryption",
        "Predictable Tokens",
        "Token Leakage",
    ]
```
to:
```python
    assert [name for name, _ in grouped] == [
        "Weak Hashing",
        "Weak Encryption",
        "Predictable Tokens",
        "Token Leakage",
        "Weak Random Number Generation",
    ]
```

In `test_a02_overview_shows_vulnerability_subtype_group_headings`, add one more assertion line:
```python
    assert '<h3 class="h6 mt-3">Weak Random Number Generation</h3>' in body
```

- [ ] **Step 9: Run the full A02 test surface**

Run: `pytest tests/test_a02_insecure_randomness.py tests/test_a02_hints.py tests/test_a02_overview.py tests/test_a02_credential_dump.py tests/test_a02_credentials.py tests/test_a02_encrypted_notes.py tests/test_a02_reset_token_api_leak.py tests/test_a02_reset_token_referrer_leak.py tests/test_a02_reset_token.py -v`
Expected: PASS (all tests, no regressions).

- [ ] **Step 10: Commit**

```bash
git add app/categories/a02_crypto_failures/routes.py \
        app/categories/a02_crypto_failures/__init__.py \
        app/categories/a02_crypto_failures/templates/a02_crypto_failures/generate_api_key.html \
        tests/test_a02_insecure_randomness.py \
        tests/test_a02_hints.py \
        tests/test_a02_overview.py
git commit -m "feat(a02): add Predictable API Key via Time-Seeded PRNG example"
```

---

### Task 5: Final Integration

**Files:**
- Modify: `tests/test_all_examples_have_hints.py`
- Modify: `tests/test_hints.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: the final state of A01 and A02 after Tasks 1-4 — 100 total examples across all categories, max score 2140.
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

Expected: `total examples: 100` (95 + Task 1's 1 + Task 2's 2 + Task 3's 1 + Task 4's 1). If this doesn't read 100, stop and investigate before proceeding.

- [ ] **Step 2: Update the cross-cutting count assertion**

In `tests/test_all_examples_have_hints.py`, change `assert total == 95` to `assert total == 100`.

- [ ] **Step 3: Update the max-score assertions**

In `tests/test_hints.py`, change both `2010` occurrences to `2140`:

```python
    assert "Score: 10 / 2140 points" in body
```
and:
```python
    assert b"Score: 10 / 2140" in response.data
```

- [ ] **Step 4: Update README.md's intro paragraph**

Find the A01 parenthetical, currently:
```
Currently implemented: **A01 Broken Access Control** (IDOR, missing function-level
authorization, mass assignment / role escalation, IDOR on a password-change API,
CSRF-based email-address takeover, CSRF via token presence-only validation,
arbitrary file read via document download, path traversal filter bypass via
absolute path), **A02 Cryptographic Failures**
```
and change it to:
```
Currently implemented: **A01 Broken Access Control** (IDOR, missing function-level
authorization, mass assignment / role escalation, IDOR on a password-change API,
CSRF-based email-address takeover, CSRF via token presence-only validation,
arbitrary file read via document download, path traversal filter bypass via
absolute path, IDOR via a wildcard pattern-matched lookup, an unvalidated open
redirect, an open-redirect allowlist bypass via domain suffix, and HTTP
parameter pollution enabling role escalation), **A02 Cryptographic Failures**
```

Find the A02 parenthetical, currently:
```
(leaked credential dump, weak ECB encryption, predictable password-reset token,
reset token leaked via the Referer header, reset token leaked in an API response),
```
and change it to:
```
(leaked credential dump, weak ECB encryption, predictable password-reset token,
reset token leaked via the Referer header, reset token leaked in an API response,
and a predictable API key via a time-seeded PRNG),
```

- [ ] **Step 5: Update README.md's category summary table**

Change the A01 row, currently:
```
| A01 Broken Access Control | Implemented | IDOR (Easy), IDOR on Password-Change API (Medium), Hidden Admin Panel (Medium), Mass Assignment Role Escalation (Hard), Account Takeover via CSRF (Email Change) (Medium), CSRF via Token Presence-Only Validation (Medium), Arbitrary File Read via Document Download (Medium), Path Traversal Filter Bypass via Absolute Path (Hard) |
```
to:
```
| A01 Broken Access Control | Implemented | IDOR (Easy), IDOR on Password-Change API (Medium), Hidden Admin Panel (Medium), Mass Assignment Role Escalation (Hard), Account Takeover via CSRF (Email Change) (Medium), CSRF via Token Presence-Only Validation (Medium), Arbitrary File Read via Document Download (Medium), Path Traversal Filter Bypass via Absolute Path (Hard), IDOR via Wildcard Pattern-Matched Lookup (Medium), Unvalidated Open Redirect (Medium), Open Redirect Allowlist Bypass via Domain Suffix (Hard), HTTP Parameter Pollution Role Escalation (Hard) |
```

Change the A02 row, currently (verified fresh against the real file — note the `/` in "Weak Encryption / ECB Mode", which the row's wording actually uses):
```
| A02 Cryptographic Failures | Implemented | Leaked Credential Dump (Easy), Weak Encryption / ECB Mode (Medium), Predictable Password Reset Token (Hard), Reset Token Leaked in API Response (Easy), Reset Token Leaked via Referrer Header (Medium) |
```
to:
```
| A02 Cryptographic Failures | Implemented | Leaked Credential Dump (Easy), Weak Encryption / ECB Mode (Medium), Predictable Password Reset Token (Hard), Reset Token Leaked in API Response (Easy), Reset Token Leaked via Referrer Header (Medium), Predictable API Key via Time-Seeded PRNG (Hard) |
```

- [ ] **Step 6: Run the full test suite**

Run: `pytest -q`
Expected: green, zero failures. Compute the exact expected pass count from the actual new-test counts across Tasks 1-4 (2 + 4 + 2 + 2 = 10 new tests) plus the prior baseline (568 passed + 1 approved GNU-tar-only skip, from round 5's final state) — expect approximately `578 passed, 1 skipped`, but **verify this arithmetic against the actual observed new-test counts from each task's own Step 7/9 runs rather than trusting this estimate blindly** (this plan's own practice from every prior round: never trust a predicted count over an actually-observed one).

- [ ] **Step 7: Commit**

```bash
git add tests/test_all_examples_have_hints.py tests/test_hints.py README.md
git commit -m "test(nav): update total/max-score assertions and README for 5 new examples"
```

---

## Self-Review Notes (for the plan author, not an execution step)

**Spec coverage:** all 5 examples from the spec are fully covered by Tasks 1-4, including exact route names, the empirically-verified `.like()`/wildcard mechanism, the empirically-verified `redirect()`-passes-anything and substring-allowlist-bypass mechanisms, the empirically-verified Werkzeug `.get()`-vs-`.getlist()` duplicate-key behavior, and the empirically-verified `random.seed()` reproducibility.

**Placeholder scan:** no TBD/TODO; every step has literal, complete code. All previously-conditional guidance has been resolved: `tests/test_a02_overview.py` and README.md's A02 table row were both read fresh in full during self-review (after the initial draft), and Task 4 Step 8 / Task 5 Step 5 now give exact before/after text instead of "read fresh and adapt" placeholders. This caught one real discrepancy: the README's A02 row actually reads "Weak Encryption / ECB Mode" (with a slash), not "Weak Encryption ECB Mode" as the initial draft assumed — fixed in Task 5 Step 5.

**Type/naming consistency:** every new route name matches its `ExampleNav.endpoint` value and every `url_for()` call across all four tasks' templates. Every new `ExampleNav.endpoint` points at an HTML-rendering route, never a raw action route (this task set has no split-route examples this round, unlike some prior rounds' CSV-injection/file-inclusion examples — every one of this round's 5 examples uses a single combined GET/POST route, matching the simpler shape of `host_lookup`/`theme_preview`/`export_archive` precedent).

**The Orchestration Note's fully-composed order:** independently derived from A01's actual current 8-entry `__init__.py` (read fresh during plan-writing) plus each of Tasks 1/2/3's own stated insertion points, and cross-checked against each task's own Step 8 test-file edits at every intermediate stage (9-entry after Task 1, 11-entry after Task 2, 12-entry final after Task 3) — consistent throughout, avoiding the exact "asserts a later task's final state too early" class of bug a prior round's plan self-review caught and fixed.

**Task 5's final assertions:** the 95→100 and 2010→2140 changes are arithmetically exact (Task 1: +1 Medium = +20; Task 2: +1 Medium +1 Hard = +50; Task 3: +1 Hard = +30; Task 4: +1 Hard = +30; total +130). Task 5 Step 1 has the implementer verify the actual total before touching any assertion, rather than trusting this arithmetic blindly, matching this plan's own Global Constraints spirit and the practice established in every prior round's final task.
