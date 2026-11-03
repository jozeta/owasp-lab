# OWASP Lab Audit Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix every bug found by the full 105-example lab audit (16 unintended-bypass bugs, 6 caching/stale-state bugs, 2 plain correctness bugs) without weakening any example's intended, hint-documented vulnerability.

**Architecture:** Each task patches the specific file(s) a defect lives in and adds the negative-case test the audit found missing. No shared new infrastructure except one new `AuthSession` column (Task 9) and nine new filesystem paths the DB reset must also clear (Task 1). Tasks are independent of each other (different files, different categories) except that all depend on the clean baseline this plan starts from.

**Tech Stack:** Flask, SQLAlchemy (SQLite in tests, Postgres in Docker), Jinja2, vendored jQuery 1.12.4, pytest.

**Spec:** `/private/tmp/claude-501/-Users-zeta-Desktop-code-owasp-lab/f6204b24-f2f3-4ce5-ace1-06b027d08f1c/scratchpad/lab-audit-findings.md` — the consolidated findings of an 11-agent parallel audit across all 10 OWASP categories (105 examples). Each task below cites the exact findings section it implements.

## Global Constraints

- **The vulnerabilities are the product.** Every fix below closes exactly one of: (a) an UNINTENDED extra path to an example's own proof condition, while leaving that example's INTENDED, hint-documented technique fully exploitable, or (b) a stale-state/caching bug, or (c) a plain crash/missing-bounds-check bug unrelated to exploitability. No fix may make an example's intended technique stop working. No fix may make an example *more* secure than its hints describe (e.g. Task 10 adds 3 specific blocked strings, not proper IP canonicalization, which would also block the 3 taught bypasses).
- Every task's new/changed test must be run against `.venv/bin/python -m pytest` in this worktree (SQLite in-memory backend) — the baseline is 654 passed, 3 skipped. A task is not done until the *whole* suite is green again, not just its own new test.
- Do not touch the live Docker instance or Postgres; all verification is against the SQLite test app via the existing `app`/`client` pytest fixtures (see `tests/conftest.py` and each test file's own `seed_database(app)` convention).
- Every negative test must assert the *fix's own file:line* behavior, not just that "something changed" — reproduce the audit's exact repro input and assert it now fails/produces the neutral outcome, the same way each existing positive test asserts the exact intended-technique input succeeds.

## Review Focus

- A fix that closes the unintended path but *also* closes the intended path (verified per-task by re-running that example's existing, already-passing tests — if any of them start failing, the fix is wrong, not the test).
- A fix that only works in isolation but breaks once another example's state shares the same session/DB row (A07, Task 9 — `AuthSession` is one shared row per `sid` cookie across all 15 examples in that category; a stale flag from a prior example visited in the same browser session must not leak into another).
- A caching fix (Task 1) that clears a path eagerly at *import* time instead of at `reset_database()` call time, which would break normal operation between resets (the fix must only ever run when a reset is actually requested).
- A test that asserts on the *wrong* observable (e.g. a byte string that also appears in that page's own static "vulnerable_code" teaching sample, passing vacuously even if the real fix is broken or absent — see `test_filter_challenge_level1_blocks_naive_script_tag`'s existing comment on exactly this trap, and apply the same caution to every new negative test in this plan).
- A regex-based filter fix (Tasks 5, 6, 8) with an unintended escape hatch — e.g. a payload that neither matches the new denylist nor is the intended bypass, silently reopening a *different* unintended path. Each of those tasks' steps include trying at least one such extra payload before calling the task done.

---

### Task 1: Clear stale filesystem state on lab reset

**Files:**
- Modify: `app/core/seed.py:70-82` (`reset_database`)
- Test: `tests/test_seed.py` (create if it doesn't already cover `reset_database`; check first)

**Interfaces:**
- Consumes: `app.categories.a03_injection.routes.{CSS_EXFIL_LOG_PATH, SNIPPETS_DIR, ATTACHMENTS_DIR, ARCHIVE_EXPORT_DIR}`, `app.categories.a06_vulnerable_components.routes.IMAGETRAGICK_PROOF_PATH`, `app.categories.a09_logging_monitoring_failures.routes.LOG_FILE_PATH` — all pre-existing module constants, no new names.
- Produces: nothing new; `reset_database(app)`'s existing signature and callers (`core_bp`'s `reset_lab`/`force_reset`) are unchanged.

Findings: `lab-audit-findings.md` lines 52-64 (A03), 81-87 (A06, `imagetragick-rce`/`imagetragick-extension-bypass`), 35-41 (A09).

- [ ] **Step 1: Write the failing tests**

Check first whether `tests/test_seed.py` exists; if not, create it.

```python
import os

from app.categories.a03_injection.routes import (
    ARCHIVE_EXPORT_DIR,
    ATTACHMENTS_DIR,
    CSS_EXFIL_LOG_PATH,
    SNIPPETS_DIR,
)
from app.categories.a06_vulnerable_components.routes import IMAGETRAGICK_PROOF_PATH
from app.categories.a09_logging_monitoring_failures.routes import LOG_FILE_PATH
from app.core.seed import reset_database


def _touch(path, content="stale"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def test_reset_database_clears_stale_files_and_dirs(app):
    _touch(CSS_EXFIL_LOG_PATH)
    _touch(LOG_FILE_PATH)
    _touch(IMAGETRAGICK_PROOF_PATH)
    os.makedirs(SNIPPETS_DIR, exist_ok=True)
    _touch(os.path.join(SNIPPETS_DIR, "leftover.txt"))
    os.makedirs(ATTACHMENTS_DIR, exist_ok=True)
    _touch(os.path.join(ATTACHMENTS_DIR, "poc.svg"))
    os.makedirs(ARCHIVE_EXPORT_DIR, exist_ok=True)
    _touch(os.path.join(ARCHIVE_EXPORT_DIR, "notes.txt"))

    reset_database(app)

    assert not os.path.exists(CSS_EXFIL_LOG_PATH)
    assert not os.path.exists(LOG_FILE_PATH)
    assert not os.path.exists(IMAGETRAGICK_PROOF_PATH)
    assert not os.path.isdir(SNIPPETS_DIR)
    assert not os.path.isdir(ATTACHMENTS_DIR)
    assert not os.path.isdir(ARCHIVE_EXPORT_DIR)


def test_reset_database_does_not_error_when_nothing_stale_exists(app):
    # Paths may legitimately not exist yet on a fresh app -- reset must
    # not crash just because there's nothing to clean up.
    reset_database(app)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_seed.py -v`
Expected: FAIL — files/dirs still present after `reset_database`.

- [ ] **Step 3: Implement the fix in `app/core/seed.py`**

Add `import os` and `import shutil` to the top of the file. Extend `reset_database`:

```python
import os
import shutil

from werkzeug.security import generate_password_hash

from app.core.models import Settings, User
from app.core.nav import CATEGORIES
from app.extensions import db

# ... SEED_USERS, seed_database unchanged ...


def reset_database(app):
    with app.app_context():
        db.drop_all()
        db.create_all()
    seed_database(app)
    # The A07 "MFA Code Not Bound to Session" example keeps pending codes in
    # a module-level dict, not in the database, so a DB reset alone would
    # otherwise leave old codes valid indefinitely. Import locally to avoid
    # a circular import at module load time.
    from app.categories.a07_auth_failures.routes import PENDING_MFA_CODES_BY_USERNAME

    PENDING_MFA_CODES_BY_USERNAME.clear()

    # Several exercises write proof/log/upload state to the filesystem
    # instead of the database -- a DB reset alone leaves all of it behind,
    # so "Reset lab" silently fails to give these exercises a clean state.
    # Import locally, same reason as above.
    from app.categories.a03_injection.routes import (
        ARCHIVE_EXPORT_DIR,
        ATTACHMENTS_DIR,
        CSS_EXFIL_LOG_PATH,
        SNIPPETS_DIR,
    )
    from app.categories.a06_vulnerable_components.routes import IMAGETRAGICK_PROOF_PATH
    from app.categories.a09_logging_monitoring_failures.routes import LOG_FILE_PATH

    for stale_file in (CSS_EXFIL_LOG_PATH, LOG_FILE_PATH, IMAGETRAGICK_PROOF_PATH):
        if os.path.exists(stale_file):
            os.remove(stale_file)
    for stale_dir in (SNIPPETS_DIR, ATTACHMENTS_DIR, ARCHIVE_EXPORT_DIR):
        if os.path.isdir(stale_dir):
            shutil.rmtree(stale_dir)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_seed.py -v`
Expected: PASS

- [ ] **Step 5: Run the whole suite**

Run: `.venv/bin/python -m pytest -q`
Expected: 654 + 2 new = 656 passed, 3 skipped (no regressions in `tests/test_a03_*`, `tests/test_a06_*`, `tests/test_a09_*`, which create these same paths).

- [ ] **Step 6: Commit**

```bash
git add app/core/seed.py tests/test_seed.py
git commit -m "fix: reset lab also clears stale filesystem state (A03/A06/A09)"
```

---

### Task 2: A01 open-redirect-allowlist-bypass — scope the check to the URL's host

**Files:**
- Modify: `app/categories/a01_access_control/routes.py:206-220` (`continue_redirect_filtered`)
- Test: `tests/test_a01_open_redirect.py`

**Interfaces:**
- Consumes: `urllib.parse.urlparse` (stdlib, not currently imported in this file — check imports first).
- Produces: nothing new.

Findings: `lab-audit-findings.md` lines 14-16. Intended technique (`app/categories/a01_access_control/__init__.py:163-168`): `?next=https://trusted-partner.example.evil.example.com/phish` — the *host* starts with the trusted string but isn't it or a real subdomain of it. Unintended bypasses found: the trusted string appearing in the URL's path/query/fragment while the host is unrelated.

- [ ] **Step 1: Write the failing test**

```python
def test_continue_filtered_rejects_substring_in_path_not_host(client):
    response = client.get(
        "/a01/continue-filtered",
        query_string={"next": "https://evil.example.com/trusted-partner.example"},
    )
    assert response.status_code == 400


def test_continue_filtered_rejects_substring_in_query_not_host(client):
    response = client.get(
        "/a01/continue-filtered",
        query_string={"next": "https://evil.example.com/?x=trusted-partner.example"},
    )
    assert response.status_code == 400
```

Add both to `tests/test_a01_open_redirect.py` (read the file first to match its existing style/imports).

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_a01_open_redirect.py -v`
Expected: FAIL — both currently redirect (302) instead of returning 400.

- [ ] **Step 3: Implement the fix**

Add `import urllib.parse` near the top of `app/categories/a01_access_control/routes.py` if not already present (check first — `urllib.parse` is used elsewhere in this codebase's other category packages, but confirm this specific file's current imports before adding a duplicate).

```python
@a01_bp.route("/continue-filtered")
def continue_redirect_filtered():
    next_url = request.args.get("next")
    if next_url is None:
        return render_template("a01_access_control/continue_redirect_filtered.html")
    # VULNERABLE: checks whether the trusted hostname is a PREFIX of the
    # URL's actual host, never that it's genuinely the URL's host (or a
    # real subdomain of it) -- an attacker who registers
    # trusted-partner.example.evil.example.com still passes this check,
    # the classic "substring/prefix allowlist" open-redirect mistake.
    host = (urllib.parse.urlparse(next_url).hostname or "").lower()
    if host.startswith("trusted-partner.example"):
        return redirect(next_url)
    return "Invalid redirect target", 400
```

This narrows the check from "the string appears anywhere in the URL" to "the URL's host starts with the trusted string" — closing the path/query/fragment bypasses while keeping the taught host-prefix bypass (`trusted-partner.example.evil.example.com`) working exactly as before.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_a01_open_redirect.py -v`
Expected: PASS, including the pre-existing `test_continue_filtered_bypassed_via_domain_suffix` (confirms the intended technique still works).

- [ ] **Step 5: Run the whole suite**

Run: `.venv/bin/python -m pytest -q`
Expected: 656 + 2 = 658 passed, 3 skipped.

- [ ] **Step 6: Commit**

```bash
git add app/categories/a01_access_control/routes.py tests/test_a01_open_redirect.py
git commit -m "fix: scope open-redirect allowlist check to the URL's host (A01)"
```

---

### Task 3: A02 reset-token — stop defaulting to a free admin token

**Files:**
- Modify: `app/categories/a02_crypto_failures/routes.py:100-121` (`reset_password_referrer`)
- Test: `tests/test_a02_reset_token.py`, `tests/test_a02_reset_token_referrer_leak.py`

**Interfaces:**
- Consumes: `generate_reset_token` (existing, unchanged signature).
- Produces: nothing new.

Findings: `lab-audit-findings.md` lines 24, 26, 29. Root cause: `token = request.args.get("token") or generate_reset_token("admin")` hands out a real admin token whenever none is supplied — both breaking `reset-token`'s own puzzle (view this page, skip computing the MD5 yourself) and letting `reset-token-referrer-leak` be solved by POSTing with no token at all (never touching the Referer-leak flow it's named for). Note the page's own documented `vulnerable_code` teaching block (`reset_password_referrer.html:48-52`) already shows the code as `token = request.args.get("token")` with **no** fallback — the real implementation doesn't match its own documentation.

- [ ] **Step 1: Write the failing tests**

In `tests/test_a02_reset_token.py`, add (this file already has a `_token_for` helper — reuse it):

```python
def test_reset_password_referrer_no_longer_hands_out_a_free_admin_token(app, client):
    seed_database(app)

    response = client.get("/a02/reset-password-referrer")
    assert response.status_code == 200
    assert _token_for("admin").encode() not in response.data
```

In `tests/test_a02_reset_token_referrer_leak.py`, **replace** `test_reset_password_referrer_page_renders_with_default_token` (it asserts the exact bug being fixed) with:

```python
def test_reset_password_referrer_page_shows_no_token_by_default(client):
    response = client.get("/a02/reset-password-referrer")
    assert response.status_code == 200
    assert generate_reset_token("admin").encode() not in response.data


def test_posting_with_no_token_at_all_does_not_reset_the_password(client):
    response = client.post(
        "/a02/reset-password-referrer", data={"new_password": "attacker-chosen"}
    )
    assert response.status_code == 200
    assert b"invalid or expired" in response.data.lower()


def test_posting_with_a_genuinely_leaked_token_resets_the_password(client):
    # The intended flow: a real token (as if legitimately emailed to the
    # account owner) ends up in this page's URL, gets leaked via Referer
    # (covered by test_external_sink_captures_and_displays_referer_with_token
    # below), and the attacker then uses it here to complete the reset.
    token = generate_reset_token("admin")
    response = client.post(
        f"/a02/reset-password-referrer?token={token}",
        data={"new_password": "attacker-chosen"},
    )
    assert response.status_code == 200
    assert b"Password reset." in response.data

    login_response = client.post(
        "/a02/legacy-login",
        data={"username": "admin", "password": "attacker-chosen"},
    )
    assert b"takeover confirmed" in login_response.data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_a02_reset_token.py tests/test_a02_reset_token_referrer_leak.py -v`
Expected: the two new/replaced tests FAIL (the page currently always shows a valid admin token, and POSTing with no token currently succeeds).

- [ ] **Step 3: Implement the fix**

```python
@a02_bp.route("/reset-password-referrer", methods=["GET", "POST"])
def reset_password_referrer():
    # VULNERABLE: the reset token lives in this page's own URL (query
    # string), and nothing anywhere in this app sets a Referrer-Policy
    # header -- any outbound link on this page (see the "Security Tips"
    # link below) carries the full current URL, token included, to
    # whatever it links to.
    token = request.args.get("token")
    error = None
    success = False
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        matched_credential = None
        if token:
            for credential in LegacyCredential.query.all():
                if generate_reset_token(credential.username) == token:
                    matched_credential = credential
                    break
        if matched_credential is None:
            error = "This reset token is invalid or expired."
        else:
            matched_credential.weak_password_hash = hashlib.md5(new_password.encode()).hexdigest()
            db.session.commit()
            success = True
    return render_template(
        "a02_crypto_failures/reset_password_referrer.html", token=token, error=error, success=success
    )
```

This removes the `or generate_reset_token("admin")` default entirely — `token` is now exactly what the request supplied (or `None`), matching the page's own documented `vulnerable_code` sample. When `token` is falsy, the POST branch no longer even attempts a match (the real security fix is not reaching for a secretly-generated admin token when the caller supplied nothing).

Check the template's `live_example` block (`reset_password_referrer.html:68`, `<p>Current token in the URL: <strong>{{ token }}</strong></p>`) — confirm it renders sensibly with `token=None` (Jinja renders `None` as the literal text "None"; if that reads oddly, change the line to `{{ token or "(none supplied)" }}`, but only if the existing tests don't already pin the exact current output — check before changing the template).

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_a02_reset_token.py tests/test_a02_reset_token_referrer_leak.py -v`
Expected: PASS, including the pre-existing `test_reset_password_referrer_page_sets_no_referrer_policy` and `test_external_sink_captures_and_displays_referer_with_token` (both unaffected by this change).

- [ ] **Step 5: Run the whole suite**

Run: `.venv/bin/python -m pytest -q`
Expected: 658 + 4 - 1 (one test replaced, three added net) = 661 passed, 3 skipped.

- [ ] **Step 6: Commit**

```bash
git add app/categories/a02_crypto_failures/routes.py tests/test_a02_reset_token.py tests/test_a02_reset_token_referrer_leak.py
git commit -m "fix: stop reset-password-referrer from defaulting to a free admin token (A02)"
```

---

### Task 4: A03 blind-sqli — remove the visible boolean oracle

**Files:**
- Modify: `app/categories/a03_injection/routes.py:124-132` (`check_username`), `app/categories/a03_injection/templates/a03_injection/check_username.html:97-100`
- Test: `tests/test_a03_check_username.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `check_username` no longer passes `exists` to the template in a way that changes visible text; template always renders a neutral "Checked." result.

Findings: `lab-audit-findings.md` line 49. The route exposes `exists` (found/not-found) directly as "available"/"already taken" text, making the hinted TIME-based side channel unnecessary — full data extraction is possible via the directly-visible boolean alone. Fix: stop the response text from varying with `exists` at all, forcing genuine timing exploitation (as the hints teach) to remain the only signal.

- [ ] **Step 1: Read the current test file and template in full**

`tests/test_a03_check_username.py` has 4 tests directly dependent on the "available"/"already taken" text (`test_check_username_reports_available_for_unknown_user`, `test_check_username_reports_taken_for_known_user`, `test_check_username_sqli_flips_result_via_boolean_injection`, `test_check_username_sqli_still_works_with_teaching_text_hidden`) — note this file's own comment: "The real exploitation instructions use PostgreSQL's pg_sleep() for a genuine timing side-channel -- that's verified live against Postgres in the plan's final Docker-verification task, not here (SQLite has no pg_sleep)." SQLite's test suite has never been able to test the real timing technique; it only ever stood in with the boolean technique as a proxy. After this fix, the boolean proxy is gone too, so these 4 tests must be rewritten to test what SQLite *can* still prove: the injection point remains genuinely unparameterized (a broken-SQL input errors out), and the response text no longer varies.

- [ ] **Step 2: Write the new/replaced tests**

Replace the file's contents with:

```python
from app.core.seed import seed_database


def test_check_username_response_is_identical_for_unknown_and_known_user(app, client):
    seed_database(app)

    unknown_response = client.get(
        "/a03/check-username", query_string={"username": "definitely-not-a-real-user"}
    )
    known_response = client.get("/a03/check-username", query_string={"username": "alice"})

    assert unknown_response.status_code == 200
    assert known_response.status_code == 200
    assert b"available" not in unknown_response.data.lower()
    assert b"already taken" not in known_response.data.lower()
    assert b"Checked." in unknown_response.data
    assert b"Checked." in known_response.data


def test_check_username_still_executes_raw_sql_unparameterized(app, client):
    # The injection point itself must remain genuinely vulnerable -- only
    # the visible available/taken signal was removed. A lone unescaped
    # quote breaks the raw concatenated query, proving it's still built
    # by string concatenation, not bound parameters.
    seed_database(app)
    response = client.get("/a03/check-username", query_string={"username": "o'brien"})
    assert response.status_code == 500


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
    assert b"Checked." in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_check_username_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Blind Time-Based SQL Injection" in response.data
    assert b'href="/a03/check-username"' in response.data


def test_check_username_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a03/check-username")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b":username" in response.data


def test_check_username_shows_detect_content(app, client):
    with app.app_context():
        from app.core.models import Settings
        from app.extensions import db

        settings = Settings.get()
        settings.show_exploit_instructions = True
        settings.scoring_enabled = False
        db.session.commit()
    response = client.get("/a03/check-username")
    assert response.status_code == 200
    assert b"Enter a single quote on its own" in response.data
```

Note: `test_check_username_still_executes_raw_sql_unparameterized` expects a 500 — confirm this matches how the rest of this test suite handles an unhandled exception from a raw-SQL route under `TESTING=True` (other tests in this plan, e.g. Task 7, treat an uncaught exception as the real crash behavior in production — check `config.py`'s `TestConfig` for whether `TESTING=True` makes Flask re-raise instead of returning 500. If it re-raises, change this test to `pytest.raises` around the `client.get(...)` call instead of asserting `status_code == 500` — verify which behavior this specific test app actually has before finalizing, don't guess).

- [ ] **Step 3: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_a03_check_username.py -v`
Expected: FAIL — the route still renders "available"/"already taken".

- [ ] **Step 4: Implement the fix**

In `app/categories/a03_injection/routes.py`:

```python
def check_username():
    username = request.args.get("username", "")
    checked = False
    if username:
        # VULNERABLE: raw string-concatenated SQL, no parameterization.
        # The response text below is intentionally identical regardless
        # of the result -- this example's lesson is that even with NO
        # visible signal at all, a conditional timing side-channel
        # (see this example's hints) can still extract data.
        query = f"SELECT COUNT(*) FROM injection_accounts WHERE username = '{username}'"
        db.session.execute(text(query)).scalar()
        checked = True
    return render_template("a03_injection/check_username.html", username=username, checked=checked)
```

In `app/categories/a03_injection/templates/a03_injection/check_username.html`, replace the block around line 97-100:

```jinja
{% if checked %}
<p>Checked.</p>
{% endif %}
```

(Read the surrounding template first to match its exact current structure/classes — replace only the `{% if exists is not none %}...{% endif %}` block, keep everything else unchanged.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_a03_check_username.py -v`
Expected: PASS.

- [ ] **Step 6: Run the whole suite**

Run: `.venv/bin/python -m pytest -q`
Expected: 661 + 6 - 4 (4 replaced, 2 net new) = 663 passed, 3 skipped.

- [ ] **Step 7: Commit**

```bash
git add app/categories/a03_injection/routes.py app/categories/a03_injection/templates/a03_injection/check_username.html tests/test_a03_check_username.py
git commit -m "fix: remove visible boolean oracle from blind-sqli example (A03)"
```

---

### Task 5: A03 filter-challenge Level 2 — close the trivial non-script bypass

**Files:**
- Modify: `app/categories/a03_injection/routes.py:405-411` (`filter_level_2`)
- Test: `tests/test_a03_filter_challenge.py` (confirm exact filename first)

**Interfaces:**
- Consumes: `re` (already imported).
- Produces: nothing new.

Findings: `lab-audit-findings.md` line 50. `filter_level_2` only strips literal `<script>`/`</script>`, blocking nothing else, so the Level-1-intended `<img onerror>` payload also defeats Level 2 without needing the taught nested-reconstruction trick. Fix: block other dangerous tags and inline event-handler attributes outright, while preserving the exact "doesn't re-scan its own output after stripping" flaw for `<script>` specifically.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_a03_filter_challenge.py`:

```python
def test_filter_challenge_level2_blocks_trivial_non_script_bypass(client):
    # The Level-1-intended payload must NOT also solve Level 2 -- Level 2
    # is a distinct, harder challenge requiring the nested-script
    # reconstruction trick specifically.
    payload = "<img src=x onerror=console.log('LEVEL-1-BYPASS')>"
    response = client.get(
        "/a03/filter-challenge", query_string={"level": "2", "payload": payload}
    )
    assert response.status_code == 200
    assert b"onerror=console.log" not in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_a03_filter_challenge.py -v`
Expected: FAIL — the img/onerror payload currently passes through unchanged.

- [ ] **Step 3: Implement the fix**

```python
def filter_level_2(payload: str) -> str:
    # VULNERABLE: strips "<script>" and "</script>" as two SEPARATE passes
    # -- doesn't re-scan its own output, so nested/interleaved tags
    # reconstruct a real <script> tag from the leftover fragments. Other
    # dangerous tags and inline event-handler attributes are rejected
    # outright, so the reconstruction trick is the only way through.
    if re.search(r"<\s*/?\s*(iframe|svg|img|body|object|embed)\b", payload, flags=re.IGNORECASE):
        return "[blocked: dangerous tag detected]"
    if re.search(r"\bon\w+\s*=", payload, flags=re.IGNORECASE):
        return "[blocked: event handler attribute detected]"
    payload = re.sub(r"<script>", "", payload, flags=re.IGNORECASE)
    payload = re.sub(r"</script>", "", payload, flags=re.IGNORECASE)
    return payload
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_a03_filter_challenge.py -v`
Expected: PASS, including the pre-existing `test_filter_challenge_level2_legitimate_input_passes_through`, `test_filter_challenge_level2_strips_naive_script_tag`, and critically `test_filter_challenge_level2_bypass_reconstructs_script_tag` (confirms the intended nested-reconstruction technique — which never contains `iframe`/`svg`/`img`/`body`/`object`/`embed`/`on\w+=` — still passes through untouched).

- [ ] **Step 5: Run the whole suite**

Run: `.venv/bin/python -m pytest -q`
Expected: 663 + 1 = 664 passed, 3 skipped.

- [ ] **Step 6: Commit**

```bash
git add app/categories/a03_injection/routes.py tests/test_a03_filter_challenge.py
git commit -m "fix: close trivial non-script bypass in filter-challenge Level 2 (A03)"
```

---

### Task 6: A03 ssti-blacklist-bypass — block class-traversal primitives

**Files:**
- Modify: `app/categories/a03_injection/routes.py:291` (`SSTI_BLOCKED_KEYWORDS`)
- Test: `tests/test_a03_bio_preview.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing new.

Findings: `lab-audit-findings.md` line 58. The blacklist is bypassable via Jinja `__subclasses__()` class-traversal (`''.__class__.__mro__[1].__subclasses__()[N](...)`), reaching `subprocess.Popen` with zero blacklisted words present. The intended technique (`~`-string-concatenation of `import`/`os`/`popen`) uses `self.__init__.__globals__.__builtins__[...]` and `.__dict__[...]` — **do not** add `__globals__`, `__builtins__`, `__init__`, `__dict__`, or `self` to the blacklist, or the intended technique breaks. Only the traversal-specific primitives the audit's payload used are safe to add: `__class__`, `__mro__`, `__subclasses__`, `__base__`, `__bases__` — none of which appear in the intended payload.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_a03_bio_preview.py`:

```python
def test_bio_preview_blacklist_blocks_subclasses_traversal(client):
    payload = (
        "{{ ''.__class__.__mro__[1].__subclasses__()[193]"
        "('id',shell=True,stdout=-1).communicate() }}"
    )
    response = client.post("/a03/bio-preview", data={"bio_template": payload})
    assert response.status_code == 200
    assert b"uid=" not in response.data
    assert b"Blocked" in response.data
```

(The fixed index `193` is environment-dependent — if this specific index doesn't resolve to `subprocess.Popen` in the test environment, the test should still pass for the right reason: assert on the *blacklist rejection*, which happens before the index is ever evaluated, so the exact index value doesn't actually matter for this test — confirm this is true by checking that `blocked_word` short-circuits before `render_template_string` is ever called.)

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_a03_bio_preview.py -v`
Expected: FAIL — currently reaches `uid=` output, not blocked.

- [ ] **Step 3: Implement the fix**

```python
SSTI_BLOCKED_KEYWORDS = [
    "os",
    "import",
    "exec",
    "eval",
    "popen",
    "subprocess",
    "system",
    "__class__",
    "__mro__",
    "__subclasses__",
    "__base__",
    "__bases__",
]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_a03_bio_preview.py -v`
Expected: PASS, including the pre-existing `test_bio_preview_blacklist_bypass_achieves_real_command_execution` (confirms the intended `~`-concatenation technique — which never contains `__class__`/`__mro__`/`__subclasses__`/`__base__`/`__bases__` — still works).

- [ ] **Step 5: Run the whole suite**

Run: `.venv/bin/python -m pytest -q`
Expected: 664 + 1 = 665 passed, 3 skipped.

- [ ] **Step 6: Commit**

```bash
git add app/categories/a03_injection/routes.py tests/test_a03_bio_preview.py
git commit -m "fix: block Jinja class-traversal bypass of SSTI blacklist (A03)"
```

---

### Task 7: A04 — reject negative quantities and guard the rounding-exploit overflow

**Files:**
- Modify: `app/categories/a04_insecure_design/routes.py:178-199` (`limited_stock_cart`), `:272-297` (`loyalty_convert`)
- Test: `tests/test_a04_overselling.py`, `tests/test_a04_rounding_exploit.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing new.

Findings: `lab-audit-findings.md` lines 71-72. `limited_stock_cart` has no lower-bound check (`quantity=-5` confirms a nonsensical negative order). `loyalty_convert` crashes with an unhandled `OverflowError` on a huge `points` value (the existing try/except only guards `int()` parsing, not the later float multiplication).

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_a04_overselling.py`:

```python
def test_negative_quantity_is_rejected(client):
    response = client.post("/a04/limited-stock-cart", data={"quantity": "-5"})
    assert response.status_code == 200
    assert b"Order confirmed: -5" not in response.data
    assert b"Enter a quantity of at least 1." in response.data


def test_zero_quantity_is_rejected(client):
    response = client.post("/a04/limited-stock-cart", data={"quantity": "0"})
    assert response.status_code == 200
    assert b"Order confirmed: 0" not in response.data
    assert b"Enter a quantity of at least 1." in response.data
```

Add to `tests/test_a04_rounding_exploit.py`:

```python
def test_pathologically_large_points_value_does_not_crash(client):
    response = client.post("/a04/loyalty-convert", data={"points": "9" * 320})
    assert response.status_code == 200
    assert b"too large" in response.data.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_a04_overselling.py tests/test_a04_rounding_exploit.py -v`
Expected: FAIL — negative/zero quantity currently confirms an order; the huge-points request currently 500s (or re-raises under `TESTING=True` — check which, same caveat as Task 4).

- [ ] **Step 3: Implement the fixes**

```python
def limited_stock_cart():
    ordered_quantity = None
    total_cents = None
    error = None
    if request.method == "POST":
        try:
            quantity = int(request.form.get("quantity", "1"))
        except (ValueError, OverflowError):
            quantity = 1
        if quantity <= 0:
            error = "Enter a quantity of at least 1."
        else:
            # VULNERABLE: the page displays a fixed "Only 3 left!" stock
            # count, but this handler never validates the submitted
            # quantity against STOCK_COUNT (or against any real inventory
            # at all) -- any quantity above zero is accepted and priced
            # normally.
            ordered_quantity = quantity
            total_cents = DEMO_PRODUCT_PRICE_CENTS * quantity
    return render_template(
        "a04_insecure_design/limited_stock_cart.html",
        product_name=DEMO_PRODUCT_NAME,
        product_price_display=_format_cents(DEMO_PRODUCT_PRICE_CENTS),
        stock_count=STOCK_COUNT,
        ordered_quantity=ordered_quantity,
        total_display=_format_cents(total_cents) if total_cents is not None else None,
        error=error,
    )
```

Check the template `limited_stock_cart.html` for whether it already renders an `error` variable (other A04 templates do, e.g. `loyalty_convert.html`) — add `{% if error %}<p class="text-danger">{{ error }}</p>{% endif %}` near the form if it doesn't already exist, matching this category's established error-display convention (read `loyalty_convert.html` first for the exact markup/class to match).

```python
def loyalty_convert():
    error = None
    if request.method == "POST":
        try:
            points = int(request.form.get("points", "0"))
        except (ValueError, OverflowError):
            points = 0
        if points > 0:
            try:
                true_value_cents = points * POINTS_TO_CENTS_RATE
                # VULNERABLE: rounds UP to a minimum of 1 cent whenever the
                # true fractional value is positive, with no minimum
                # conversion amount enforced and no rate limit on repeated
                # conversions -- a customer's balance never actually loses
                # anything on the sending side of this "conversion", so
                # repeating a tiny conversion many times mints real cents
                # from a fractional value that should have rounded to zero.
                credited_cents = max(1, round(true_value_cents))
            except OverflowError:
                error = "That's too large a number of points to convert at once."
            else:
                session["a04_store_credit_cents"] = (
                    session.get("a04_store_credit_cents", 0) + credited_cents
                )
        else:
            error = "Enter a positive number of points."
    balance_cents = session.get("a04_store_credit_cents", 0)
    return render_template(
        "a04_insecure_design/loyalty_convert.html",
        balance_display=_format_cents(balance_cents),
        error=error,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_a04_overselling.py tests/test_a04_rounding_exploit.py -v`
Expected: PASS, including the pre-existing `test_ordering_far_more_than_stock_is_never_rejected` (confirms the intended upper-bound-exceeding technique still works) and `test_repeating_the_conversion_nets_free_money` (confirms the rounding exploit itself still works for normal-sized inputs).

- [ ] **Step 5: Run the whole suite**

Run: `.venv/bin/python -m pytest -q`
Expected: 665 + 3 = 668 passed, 3 skipped.

- [ ] **Step 6: Commit**

```bash
git add app/categories/a04_insecure_design/routes.py app/categories/a04_insecure_design/templates/a04_insecure_design/limited_stock_cart.html tests/test_a04_overselling.py tests/test_a04_rounding_exploit.py
git commit -m "fix: reject negative stock quantity and guard rounding-exploit overflow (A04)"
```

---

### Task 8: A06 jQuery DOM XSS — require the CVE-2020-11022 technique specifically

**Files:**
- Modify: `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/comment_preview.html`, `app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/account_preview.html`
- Test: `tests/test_a06_jquery_dom_xss.py`, `tests/test_a06_jquery_session_theft.py`

**Interfaces:**
- Consumes: nothing new (this is client-side JavaScript inside the page's inline `<script>` block — there is no server round-trip for the preview action at all, confirm this before starting: `raw = $('#comment-input').val()` reads directly from the DOM, never POSTed anywhere).
- Produces: nothing new.

**Risk flag for the implementer:** this is the highest-risk task in the plan. The existing test suite only asserts on rendered page *source* (Flask test client, no JS execution) — it cannot execute JavaScript. This task's fix must be verified with an actual browser (the audit used headless Chromium via an available browser-automation tool) against the real vendored `static/vendor/jquery-vulnerable/jquery-1.12.4.js`, not just reasoned about. If live verification shows the design below does not correctly distinguish the two payloads, stop and report back rather than guessing at a second design — this needs a human decision, not a second blind attempt.

Findings: `lab-audit-findings.md` lines 86. Both pages call `$('#comment-preview').html(raw)` with zero filtering, so the documented CVE-2020-11022 self-closing-`<style/>` technique isn't actually required — a plain `<img onerror>` fires identically. Fix: add a client-side pre-filter, naive enough that a developer unaware of the CVE would write it (it assumes anything starting with a `<style>` tag is inert CSS and skips scanning it), which blocks the plain payload while remaining bypassable by the exact self-closing-tag technique the hints teach.

- [ ] **Step 1: Write the failing source-presence tests**

Add to `tests/test_a06_jquery_dom_xss.py`:

```python
def test_comment_preview_wires_up_a_client_side_filter_before_html_call(client):
    response = client.get("/a06/comment-preview")
    body = response.data.decode()
    assert "isLikelyMaliciousMarkup" in body
```

Add to `tests/test_a06_jquery_session_theft.py`:

```python
def test_account_preview_wires_up_a_client_side_filter_before_html_call(client):
    response = client.get("/a06/account-preview")
    body = response.data.decode()
    assert "isLikelyMaliciousMarkup" in body
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_a06_jquery_dom_xss.py tests/test_a06_jquery_session_theft.py -v`
Expected: FAIL — no such function in the page source yet.

- [ ] **Step 3: Implement the client-side filter in both templates**

In `comment_preview.html`, replace **both** the `vulnerable_code` display block's JS sample and the real `live_example` block's inline `<script>` (keep them in sync, as they already are) with:

```html
<script>
  function isLikelyMaliciousMarkup(raw) {
    // Naive, deliberately incomplete client-side filter: blocks common
    // dangerous tags and inline event-handler attributes, but assumes
    // anything starting with a <style> tag is harmless CSS and skips
    // the check entirely -- CSS can't execute script... except this
    // exact blind spot is what CVE-2020-11022 exploits: jQuery's own
    // htmlPrefilter rewrites a self-closing <style /> into
    // <style></style> BEFORE the browser parses it, closing the style
    // context one tag early and turning what looked like inert
    // style-block content into live, executable markup.
    if (/^\s*<style\b/i.test(raw)) {
      return false;
    }
    var dangerousTag = /<\s*\/?\s*(script|img|svg|iframe|body|object|embed)\b/i;
    var eventHandler = /\bon\w+\s*=/i;
    return dangerousTag.test(raw) || eventHandler.test(raw);
  }

  $('#preview-btn').on('click', function () {
    var raw = $('#comment-input').val();
    if (isLikelyMaliciousMarkup(raw)) {
      $('#comment-preview').text('[blocked: dangerous markup detected]');
      return;
    }
    // VULNERABLE: relies on jQuery's own htmlPrefilter to make raw
    // .html() "safe" once this filter approves it -- jQuery < 3.5.0's
    // htmlPrefilter regex can be defeated by a self-closing tag,
    // letting injected markup execute (CVE-2020-11022).
    $('#comment-preview').html(raw);
  });
</script>
```

Apply the identical `isLikelyMaliciousMarkup` function and the same guarded `.html(raw)` call to `account_preview.html`'s inline `<script>` block (read its current exact structure first — it has the same two-element shape, `vulnerable_code` display block and real `live_example` script).

- [ ] **Step 4: Run the source-presence tests**

Run: `.venv/bin/python -m pytest tests/test_a06_jquery_dom_xss.py tests/test_a06_jquery_session_theft.py -v`
Expected: PASS, including every pre-existing test in both files (none of them assert on the *absence* of extra JS, only on the presence of `$('#comment-preview').html(raw)`, `jquery-1.12.4.js`, and `jquery-vulnerable/jquery-3` absence — all still true).

- [ ] **Step 5: Live-verify in a real browser (mandatory, not optional)**

Using an available browser automation tool (the audit used headless Chromium via a Playwright-style tool), load `/a06/comment-preview` against a running instance of this app (start one via `.venv/bin/python -c "from app import create_app; create_app().run(port=5055)"` or equivalent in a background process), and:

1. Type `<img src=1 onerror=window.__xss_proof='PLAIN-BLOCKED'>` into `#comment-input`, click `#preview-btn`. Assert `window.__xss_proof` is **not** set, and `#comment-preview` shows the blocked message.
2. Type the real exploitation payload `<style><style /><img src=1 onerror=window.__xss_proof='CVE-FIRED'>` into `#comment-input`, click `#preview-btn`. Assert `window.__xss_proof === 'CVE-FIRED'`.

Repeat both checks against `/a06/account-preview`. If either check fails, the filter's regex needs adjustment — do not mark this task done until both checks pass against the real vendored jQuery file. Stop the background app instance when done.

- [ ] **Step 6: Run the whole suite**

Run: `.venv/bin/python -m pytest -q`
Expected: 668 + 2 = 670 passed, 3 skipped.

- [ ] **Step 7: Commit**

```bash
git add app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/comment_preview.html app/categories/a06_vulnerable_components/templates/a06_vulnerable_components/account_preview.html tests/test_a06_jquery_dom_xss.py tests/test_a06_jquery_session_theft.py
git commit -m "fix: require the CVE-2020-11022 technique specifically for jQuery XSS examples (A06)"
```

---

### Task 9: A07 — scope MFA-dashboard and account-recovery shortcuts to their own example

**Files:**
- Modify: `app/categories/a07_auth_failures/models.py` (`AuthSession`), `app/categories/a07_auth_failures/routes.py` (`mfa_login`, `mfa_dashboard`, `mfa_login_bruteforce`, `mfa_login_unbound`, `mfa_login_magic_value`, `account_lookup`, `mfa_forgot_password`, `mfa_leaked_login`, `mfa_leaked_dashboard`, `mfa_reusable_login`, `mfa_reusable_dashboard`)
- Test: `tests/test_a07_mfa_bypass.py`, new `tests/test_a07_mfa_dashboard_scoping.py`, `tests/test_a07_unicode_normalization.py`, `tests/test_a07_username_collision.py`, `tests/test_a07_mfa_leaked_code.py`, `tests/test_a07_mfa_reusable_code.py` (confirm exact existing filenames first — grep `tests/` for each example's id)
- Modify: `README.md` lines 130-136 (schema-caveat paragraph — add this column to the existing list)

**Interfaces:**
- Produces: `AuthSession.active_mfa_flow: str | None` — a new nullable column recording which login flow is in progress on this shared session row, set by every login route in this category to its own identifier (or `None`/a neutral value for routes that aren't part of an "MFA flow" per se but still touch `mfa_verified`), consumed by every dashboard/proof route that currently checks `mfa_verified` or `username` alone.

Findings: `lab-audit-findings.md` lines 94, 96, 100-101. Two systemic root causes, both because `AuthSession` is one shared row per `sid` cookie reused across all 15 examples in this category:

**(a)** `/a07/mfa-dashboard` only checks `username`, letting `mfa-bypass-magic-value`, `mfa-brute-force`, `mfa-not-bound-to-session` skip their own verify step entirely by reaching this dashboard right after login. `mfa-bypass` (example #10) is the ONE example whose intended lesson is exactly this check gap — it must keep working with zero code verification.

**(b)** `account_lookup` logs the caller in as any username that merely equals itself after normalization (no genuine Unicode collision required), breaking `unicode-normalization-takeover` and (via `/a07/forgot-password`) `username-collision-reset`. Separately, `mfa_forgot_password` sets a blanket `mfa_verified=True` for any account with no password, acting as an unscoped skeleton key for `mfa_leaked_dashboard`/`mfa_reusable_dashboard`'s own `mfa_verified` checks — but `password-reset-disables-mfa`'s own test only ever checks `session_row.mfa_verified is True` directly via the DB, never reaching either of those dashboards, so scoping this does not touch that example's intended behavior.

- [ ] **Step 1: Add the new column**

In `app/categories/a07_auth_failures/models.py`, add to `AuthSession`:

```python
    # Records which MFA login flow is currently in progress on this
    # shared session row. Several examples in this category reuse the
    # same username/mfa_verified fields on the same row, so a dashboard
    # or proof route that only checked those two fields could be
    # satisfied by a completely different example's login/reset flow.
    # Set by every login/reset route in this category to its own
    # identifier; checked by the matching dashboard/proof route.
    active_mfa_flow = db.Column(db.String(30), nullable=True)
```

- [ ] **Step 2: Write the failing tests for root cause (a)**

Create `tests/test_a07_mfa_dashboard_scoping.py` (read `tests/test_a07_mfa_bypass.py` first for the `_login_as`/seeding conventions this category's tests already use, and match them):

```python
from app.core.seed import seed_database


def _login(client, endpoint, username, password):
    return client.post(endpoint, data={"username": username, "password": password})


def test_mfa_bypass_still_reaches_dashboard_without_entering_a_code(app, client):
    # The ONE example whose intended lesson is this exact gap must keep
    # working with zero code verification.
    seed_database(app)
    _login(client, "/a07/mfa-login", "dana", "dana-training-pw1")  # adjust creds per seed data
    response = client.get("/a07/mfa-dashboard")
    assert response.status_code == 200
    assert b"Welcome" in response.data


def test_mfa_bruteforce_login_then_skip_to_dashboard_is_rejected(app, client):
    seed_database(app)
    _login(client, "/a07/mfa-login-bruteforce", "dana", "dana-training-pw1")
    response = client.get("/a07/mfa-dashboard", follow_redirects=True)
    assert b"Welcome, dana" not in response.data


def test_mfa_unbound_login_then_skip_to_dashboard_is_rejected(app, client):
    seed_database(app)
    _login(client, "/a07/mfa-login-unbound", "dana", "dana-training-pw1")
    response = client.get("/a07/mfa-dashboard", follow_redirects=True)
    assert b"Welcome, dana" not in response.data


def test_mfa_magic_value_login_then_skip_to_dashboard_is_rejected(app, client):
    seed_database(app)
    _login(client, "/a07/mfa-login-magic-value", "dana", "dana-training-pw1")
    response = client.get("/a07/mfa-dashboard", follow_redirects=True)
    assert b"Welcome, dana" not in response.data
```

Read `app/categories/a07_auth_failures/seed.py` (or wherever `A07Account` rows are seeded) first to confirm the actual seeded username/password used in this category's own tests (the placeholder `dana`/`dana-training-pw1` above must be replaced with whatever the real seed data is — check `tests/test_a07_mfa_bypass.py`'s own existing login calls for the exact credentials already in use).

- [ ] **Step 3: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest tests/test_a07_mfa_dashboard_scoping.py -v`
Expected: the three "skip to dashboard" tests FAIL (currently all reach "Welcome, dana").

- [ ] **Step 4: Implement root cause (a)'s fix**

```python
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
            session_row.active_mfa_flow = "bypass"
            db.session.commit()
            return _redirect("a07_auth_failures.mfa_verify", session_row)
        error = "Invalid username or password."
    return _render("a07_auth_failures/mfa_login.html", session_row, error=error)


@a07_bp.route("/mfa-dashboard")
def mfa_dashboard():
    session_row = get_or_create_session()
    if not session_row.username:
        return _redirect("a07_auth_failures.mfa_login", session_row)
    # VULNERABLE (mfa-bypass's own intended lesson): a session that
    # authenticated via the plain MFA login flow reaches this dashboard
    # with just a username, no code verification required at all. Every
    # OTHER example sharing this dashboard already sets mfa_verified on
    # its own real success, so this only exempts the one flow it's meant
    # to exempt.
    if session_row.active_mfa_flow != "bypass" and not session_row.mfa_verified:
        return _redirect("a07_auth_failures.mfa_login", session_row)
    return _render("a07_auth_failures/mfa_dashboard.html", session_row)
```

In `mfa_login_bruteforce`, `mfa_login_unbound`, `mfa_login_magic_value` — each already sets `session_row.mfa_verified = False` right after the password check; add `session_row.active_mfa_flow = "bruteforce"` / `"unbound"` / `"magic_value"` respectively on the same line, so a stale `"bypass"` value from an earlier visit to the real mfa-bypass flow in the same browser session can't leak through.

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_a07_mfa_dashboard_scoping.py -v`
Expected: PASS.

- [ ] **Step 6: Write the failing tests for root cause (b) — account_lookup**

Read `tests/test_a07_unicode_normalization.py` in full first (confirm its exact existing test names/style/seed conventions) and add:

```python
def test_account_lookup_rejects_the_real_username_submitted_plainly(app, client):
    seed_database(app)
    response = client.post("/a07/account-lookup", data={"username": "dana"})
    assert response.status_code == 200
    assert b"No account found." in response.data
    assert b"Matched and logged in as" not in response.data
```

Confirm the pre-existing test for the intended lookalike technique (register `"d" + chr(0x24D0) + "na"`, then submit that same string) still exists and is unchanged — it must still pass after this fix.

- [ ] **Step 7: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_a07_unicode_normalization.py -v`
Expected: the new test FAILS (currently logs in as dana).

- [ ] **Step 8: Implement `account_lookup`'s fix**

```python
@a07_bp.route("/account-lookup", methods=["GET", "POST"])
def account_lookup():
    session_row = get_or_create_session()
    error = None
    matched_username = None
    if request.method == "POST":
        query_username = request.form.get("username", "")
        normalized_query = _normalize_username(query_username)
        accounts = A07Account.query.order_by(A07Account.id).all()
        # The submitted string must itself be a real, already-registered
        # username -- a random guess with no prior registration, however
        # it's cased or accented, is not a Unicode-collision technique.
        submitted_is_registered = any(a.username == query_username for a in accounts)
        if submitted_is_registered:
            for account_row in accounts:
                # VULNERABLE: treats any two DIFFERENT usernames that
                # normalize to the same string as the SAME account for
                # recovery purposes -- a Unicode lookalike character
                # that NFKC-normalizes to an ASCII letter collides with
                # a completely different, real ASCII-only account.
                if (
                    account_row.username != query_username
                    and _normalize_username(account_row.username) == normalized_query
                ):
                    matched_username = account_row.username
                    session_row.username = account_row.username
                    db.session.commit()
                    break
        if matched_username is None:
            error = "No account found."
    return _render(
        "a07_auth_failures/account_lookup.html",
        session_row,
        error=error,
        matched_username=matched_username,
    )
```

- [ ] **Step 9: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_a07_unicode_normalization.py -v`
Expected: PASS, including the pre-existing lookalike-registration test.

Find and run the `username-collision-reset` test file too (grep `tests/` for its id) — per the findings, this bypass is entirely closed as a side effect of this same fix (it depended on `account_lookup` wrongly accepting plain "dana"). Confirm its own intended registration-with-trailing-space test still passes, and add one negative test there too:

```python
def test_bare_username_no_longer_grants_account_lookup_access(app, client):
    seed_database(app)
    response = client.post("/a07/account-lookup", data={"username": "dana"})
    assert b"No account found." in response.data
```

- [ ] **Step 10: Write the failing tests for root cause (b) — mfa_forgot_password scoping**

Read `tests/test_a07_mfa_leaked_code.py`/equivalent and `tests/test_a07_mfa_reusable_code.py`/equivalent in full first (confirm exact filenames and existing conventions), add to each:

```python
def test_password_reset_shortcut_does_not_unlock_this_dashboard(app, client):
    seed_database(app)
    client.post(
        "/a07/mfa-forgot-password", data={"username": "dana", "new_password": "x"}
    )
    response = client.get("/a07/mfa-leaked-code/dashboard", follow_redirects=True)  # or mfa-reusable-code/dashboard
    assert b"Welcome, dana" not in response.data
```

- [ ] **Step 11: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest -k "mfa_leaked_code or mfa_reusable_code" -v`
Expected: both new tests FAIL (currently reach "Welcome, dana").

- [ ] **Step 12: Implement the scoping fix**

In `mfa_leaked_login`, add `session_row.active_mfa_flow = "leaked_code"` alongside its existing `session_row.mfa_verified = False`. In `mfa_leaked_dashboard`:

```python
@a07_bp.route("/mfa-leaked-code/dashboard")
def mfa_leaked_dashboard():
    session_row = get_or_create_session()
    if (
        not session_row.username
        or not session_row.mfa_verified
        or session_row.active_mfa_flow != "leaked_code"
    ):
        return _redirect("a07_auth_failures.mfa_leaked_login", session_row)
    return _render("a07_auth_failures/mfa_leaked_dashboard.html", session_row)
```

Apply the identical pattern to `mfa_reusable_login` (`active_mfa_flow = "reusable_code"`) and `mfa_reusable_dashboard`.

In `mfa_forgot_password`, add one line clearing/overwriting the flow marker so a stale `"leaked_code"`/`"reusable_code"` value from an earlier visit in the same browser session can't survive a password reset:

```python
            account_row.password_hash = generate_password_hash(new_password, method="pbkdf2:sha256")
            session_row.username = account_row.username
            # VULNERABLE: completing a password reset marks this session as
            # already MFA-verified -- the code-entry step (the actual
            # second factor) is never required at all after a reset,
            # silently disabling MFA protection for the account.
            session_row.mfa_verified = True
            session_row.active_mfa_flow = "password_reset"
            db.session.commit()
```

- [ ] **Step 13: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest -k "mfa_leaked_code or mfa_reusable_code or mfa_forgot_password" -v`
Expected: PASS, including the pre-existing `test_password_reset_marks_mfa_verified_without_entering_code` (still asserts `session_row.mfa_verified is True` directly — unaffected by the new column) and both examples' own intended full-flow tests.

- [ ] **Step 14: Update the README schema caveat**

In `README.md` around line 132, add `active_mfa_flow` to the existing parenthetical list of columns that require a `docker compose down -v` reset on an old volume:

```markdown
If you're running under Docker and your Postgres data volume was created before a
schema change landed (for example, an older checkout without the A07 MFA examples'
`pending_mfa_code` or `active_mfa_flow` columns, or without per-user progress tracking's
`user_id` column on `example_progress`), clicking "Reset lab" in the UI reseeds rows but
won't add new columns to already-existing tables. ...
```

- [ ] **Step 15: Run the whole suite**

Run: `.venv/bin/python -m pytest -q`
Expected: 670 + roughly 9 new tests = 679 passed, 3 skipped (exact count depends on the real existing filenames/test counts found in Steps 6/9/10 — confirm the actual delta from your own `pytest -q` run, don't assume this number is exact).

- [ ] **Step 16: Commit**

```bash
git add app/categories/a07_auth_failures/models.py app/categories/a07_auth_failures/routes.py tests/test_a07_mfa_dashboard_scoping.py tests/test_a07_unicode_normalization.py tests/test_a07_username_collision.py tests/test_a07_mfa_leaked_code.py tests/test_a07_mfa_reusable_code.py README.md
git commit -m "fix: scope A07's shared session fields to each MFA example (2 root causes, 7 examples)"
```

(Adjust the `git add` file list to the actual test filenames confirmed in Steps 6/9/10.)

---

### Task 10: A10 blocklist-alternate-ip-bypass — close the three untaught encodings

**Files:**
- Modify: `app/categories/a10_ssrf/routes.py:90` (`BLOCKED_HOSTS`)
- Test: `tests/test_a10_blocklist_alternate_ip_bypass.py` (confirm exact filename first)

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing new.

Findings: `lab-audit-findings.md` line 79. `BLOCKED_HOSTS = {"127.0.0.1", "localhost"}` is an exact-string check; the 3 taught bypasses (decimal `2130706433`, hex `0x7f000001`, short-form `127.1`) work as intended and must keep working — do **not** switch to IP canonicalization/parsing, which would also catch those and make the exercise unsolvable. Only add the 3 untaught strings the audit live-confirmed actually connect on this host: zero-padded octet `127.00.0.1`, trailing-dot `localhost.`, and the IPv6 loopback literal — `urllib.parse.urlparse(...).hostname` returns this as `"::1"` (brackets stripped), confirmed via `python3 -c "import urllib.parse; print(urllib.parse.urlparse('http://[::1]/x').hostname)"`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_a10_blocklist_alternate_ip_bypass.py`, modeled on the file's existing `test_alternate_ip_encodings_bypass_the_blocklist` (same live local-HTTP-server pattern — read that test first and reuse its `Handler`/server setup):

```python
def test_newly_closed_alternate_encodings_are_blocked(client):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"REACHED-VIA-ALTERNATE-ENCODING")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for host in ["127.00.0.1", "localhost.", "[::1]"]:
            response = client.post(
                "/a10/import-avatar", data={"avatar_url": f"http://{host}:{port}/"}
            )
            assert response.status_code == 200
            assert b"REACHED-VIA-ALTERNATE-ENCODING" not in response.data, (
                f"payload {host!r} should now be blocked"
            )
            assert b'<p class="mt-3 text-danger">That host is not allowed' in response.data
    finally:
        server.shutdown()
        thread.join(timeout=5)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_a10_blocklist_alternate_ip_bypass.py -v`
Expected: FAIL — all 3 currently reach the local server.

- [ ] **Step 3: Implement the fix**

```python
BLOCKED_HOSTS = {
    "127.0.0.1",
    "localhost",
    "127.00.0.1",
    "localhost.",
    "::1",
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/test_a10_blocklist_alternate_ip_bypass.py -v`
Expected: PASS, including the pre-existing `test_alternate_ip_encodings_bypass_the_blocklist` (confirms the 3 taught techniques — `2130706433`, `0x7f000001`, `127.1`, `0` — still bypass the blocklist exactly as before; none of those strings were added above).

- [ ] **Step 5: Run the whole suite**

Run: `.venv/bin/python -m pytest -q`
Expected: 679 + 1 = 680 passed, 3 skipped.

- [ ] **Step 6: Commit**

```bash
git add app/categories/a10_ssrf/routes.py tests/test_a10_blocklist_alternate_ip_bypass.py
git commit -m "fix: close 3 untaught alternate-IP-encoding bypasses (A10)"
```

---

## Self-Review

**1. Spec coverage:** All 24 findings from `lab-audit-findings.md` map to a task — Task 1 (6 caching findings across A03/A06/A09), Task 2 (A01's 1 bypass), Task 3 (A02's 2 bypasses + 1 coverage gap), Tasks 4-6 (A03's 3 remaining bypasses), Task 7 (A04's 2 correctness bugs), Task 8 (A06's 2 bypasses), Task 9 (A07's 7 bypasses, both root causes), Task 10 (A10's 1 bypass). A05 and A08 needed no task (audit found zero issues in either). Minor coverage-gap NOTEs that aren't bugs (A01's avatar-upload scope note, A03's error-based-sqli Postgres-only gap, A05's cors-regex suffix-variant note, A06's lodash minor note) are deliberately left out of scope — they're pre-existing, self-documented, or non-bug observations, not findings this plan was asked to fix.

**2. Step scan:** Every code step gives exact file:line and exact replacement code (no "add appropriate validation" placeholders); every test step gives exact test code with the audit's own exact repro inputs; every verification step names the pytest command and the expected count delta.

**3. Type consistency:** `AuthSession.active_mfa_flow` (Task 9) is the only new interface surfaced across steps within a task; its values (`"bypass"`, `"bruteforce"`, `"unbound"`, `"magic_value"`, `"leaked_code"`, `"reusable_code"`, `"password_reset"`) are used consistently between the login-route-setter steps and the dashboard-checker steps within that same task.

**4. Review Focus:** Each of the 4 Review Focus items has a task whose steps explicitly test it — Task 9's Step 2/5 (intended technique preserved across shared session state), Task 1's Step 1 (reset-time-only clearing, verified by the "nothing stale" no-crash test), Tasks 5/6/8's "legitimate input passes through" + "intended technique still passes" re-runs, and Task 2's explicit note about the `test_filter_challenge_level1_blocks_naive_script_tag` vacuous-assertion trap informing every new negative test's assertion choice.

**5. Proportion:** This plan is long because it touches 9 independent files/categories with a precise "don't break the intended exploit" constraint on each — each individual task is short relative to the route logic it patches (a handful of lines changed per task, Task 9 being the deliberate exception given it resolves 7 of the 24 findings at once). No task's code block exceeds what its own diff will actually be.
