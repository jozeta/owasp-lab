# PayloadsAllTheThings-Derived Additions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 15 new intentionally-vulnerable examples to the OWASP Top 10
Training Lab, sourced from PayloadsAllTheThings' Account Takeover and
Brute Force & Rate Limit reference pages, spanning A01, A02, A04, A05, and
A07 (63 → 78 examples total).

**Architecture:** Each example is a fully independent route (or small
route pair for multi-step flows), following every existing category's
established one-clean-flaw-per-route convention — no shared "correct
baseline" flow. Most examples reuse existing models (`User`,
`LegacyCredential`, `A07Account`, `AuthSession`) or Flask's built-in
`session` for ephemeral per-browser state; only where an example needs
state visible *across* browser sessions (one case) does it get dedicated
new storage.

**Tech Stack:** Flask 3.0.3, SQLAlchemy, Jinja2, pytest.

**Spec:** `docs/superpowers/specs/2026-09-23-owasp-lab-payloadsallthethings-additions-design.md`

## Global Constraints

- The vulnerabilities ARE the deliverable — never soften, sanitize, or
  add defensive checks to any new vulnerable code path. Every new route
  must be genuinely, demonstrably exploitable exactly as described below:
  no CSRF token really means no CSRF token; no rate limiting really means
  no rate limiting; the IDOR really trusts a client-supplied identifier
  with zero ownership check.
- Hint content is plain Python strings rendered through Jinja's
  autoescaped `{{ hint }}` expression (established in the scoring+hints
  project) — write literal unescaped `<`/`>`/`&` characters in hint
  text, never `&lt;`/`&gt;`/`&amp;` HTML entities. 3-5 hints per example,
  vague-to-explicit, final hint near-full-walkthrough.
- `tests/conftest.py` is off-limits — never modify it, for any reason, in
  any task.
- A01's `User`/`switch_user` system has **no real password
  authentication** — `switch_user` is a pure identity-picker (`session["user_id"]
  = int(request.form["user_id"])`, no password check anywhere). Any new
  A01 example must not assume a working password-login flow exists to
  "prove takeover" through; observe impact by reading the affected
  field back (e.g. reload the profile/account page), matching how the
  existing `idor`/`mass-assignment` examples already do this.
- Every new example gets an `ExampleNav` entry with `hints=[...]`
  following the exact rubric already established: name the general
  technique first without the specific payload, narrow toward the
  specific mechanism, final hint gives the exact working reproduction
  steps.
- Match each category's existing code style exactly: A07 uses its own
  `_render()`/`_redirect()` helpers and `get_or_create_session()` from
  `session_store.py` for every route; A01/A02/A04/A05 use plain
  `render_template()`/`redirect()` with no shared session-row
  abstraction.

---

## Design Note: A01 Example #1 Retargeted (Email, Not Password)

The spec's Decision #2 framed A01 example #1 as "Account Takeover via CSRF"
on a *password-change* endpoint. Fresh reading of `app/core/views.py`'s
`switch_user()` (the only identity mechanism A01 has) confirms this app
has **no real password-based login anywhere** — `switch_user` is a plain
"pick a user id from a dropdown" convenience with no password field and
no check at all. A CSRF-password-change demo would have no meaningful
"prove the takeover worked by logging in with the new password" step.

Task 1 below retargets this example to **email change** instead: same
CSRF teaching point (a state-changing, account-recovery-relevant field
gets silently overwritten by a forged cross-site request), same severity
rationale (whoever controls the registered email controls every future
password-reset flow), but observable the same way this category's other
examples already are — reload the profile and see the field changed. This
is noted here transparently as a plan-writing-time correction, matching
this session's established pattern for self-caught spec/reality
conflicts.

---

## Task 1: A01 Additions — CSRF (Email Change) + IDOR on Password-Change API

**Files:**
- Modify: `app/categories/a01_access_control/routes.py`
- Modify: `app/categories/a01_access_control/__init__.py`
- Create: `app/categories/a01_access_control/templates/a01_access_control/change_email.html`
- Create: `app/categories/a01_access_control/templates/a01_access_control/password_change_api.html`
- Test: `tests/test_a01_csrf_email_change.py`
- Test: `tests/test_a01_password_change_idor.py`

**Interfaces:**
- Consumes: `app.core.auth.get_current_user()`, `app.core.models.User`
  (existing, unchanged).
- Produces: routes `a01_access_control.change_email` (`GET/POST
  /a01/change-email`) and `a01_access_control.password_change_api`
  (`POST /a01/api/password-change`). Nothing later depends on these.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a01_csrf_email_change.py`:

```python
from app.core.models import User
from app.extensions import db


def _login_as(client, user_id):
    with client.session_transaction() as sess:
        sess["user_id"] = user_id


def test_change_email_page_renders_for_logged_in_user(app, client):
    with app.app_context():
        alice = User.query.filter_by(username="alice").first()
        user_id = alice.id
    _login_as(client, user_id)

    response = client.get("/a01/change-email")
    assert response.status_code == 200
    assert b"Change email address" in response.data


def test_change_email_has_no_csrf_token(app, client):
    with app.app_context():
        alice = User.query.filter_by(username="alice").first()
        user_id = alice.id
    _login_as(client, user_id)

    response = client.get("/a01/change-email")
    assert b"csrf_token" not in response.data
    assert b'name="csrf"' not in response.data


def test_change_email_succeeds_with_no_token_simulating_csrf(app, client):
    with app.app_context():
        alice = User.query.filter_by(username="alice").first()
        user_id = alice.id
    _login_as(client, user_id)

    # Simulates an attacker's cross-site auto-submitting form: no CSRF
    # token field, no Origin/Referer check on the server, just the
    # victim's own session cookie (which `client` already carries).
    response = client.post(
        "/a01/change-email",
        data={"new_email": "attacker@evil.test"},
        follow_redirects=True,
    )
    assert response.status_code == 200

    with app.app_context():
        alice = db.session.get(User, user_id)
        assert alice.email == "attacker@evil.test"
```

Create `tests/test_a01_password_change_idor.py`:

```python
from app.core.models import User
from app.extensions import db


def test_password_change_api_updates_arbitrary_user_by_email(app, client):
    with app.app_context():
        bob = User.query.filter_by(username="bob").first()
        bob_id = bob.id
        bob_email = bob.email
        original_hash = bob.password_hash

    # No login, no session at all -- the endpoint trusts the "email"
    # field in the request body to pick which account to update, never
    # checking it against any authenticated identity.
    response = client.post(
        "/a01/api/password-change",
        json={"email": bob_email, "new_password": "attacker-chosen-password"},
    )
    assert response.status_code == 200

    with app.app_context():
        bob = db.session.get(User, bob_id)
        assert bob.password_hash != original_hash


def test_password_change_api_rejects_unknown_email(client):
    response = client.post(
        "/a01/api/password-change",
        json={"email": "nobody@nowhere.test", "new_password": "x"},
    )
    assert response.status_code == 404


def test_password_change_api_page_renders(client):
    response = client.get("/a01/api/password-change")
    assert response.status_code == 200
    assert b"IDOR on Password-Change API" in response.data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_a01_csrf_email_change.py tests/test_a01_password_change_idor.py -v`
Expected: FAIL — routes don't exist yet (404s).

- [ ] **Step 3: Add the two new routes**

Modify `app/categories/a01_access_control/routes.py`. Current imports at
the top of the file:

```python
from flask import flash, redirect, render_template, request, url_for

from app.categories.a01_access_control import a01_bp
from app.core.auth import get_current_user
from app.core.models import User
from app.extensions import db
```

Replace the import block with (adds `jsonify`, `generate_password_hash`):

```python
from flask import flash, jsonify, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash

from app.categories.a01_access_control import a01_bp
from app.core.auth import get_current_user
from app.core.models import User
from app.extensions import db
```

Append these two routes at the end of the file (after `account_update`):

```python


@a01_bp.route("/change-email", methods=["GET", "POST"])
def change_email():
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=request.path))
    changed = False
    if request.method == "POST":
        # VULNERABLE: no CSRF token, no confirmation of the current
        # email/password -- any POST that arrives carrying the victim's
        # session cookie succeeds, including one triggered by an
        # auto-submitting form on an attacker's own page.
        viewer.email = request.form.get("new_email", "")
        db.session.commit()
        changed = True
    return render_template("a01_access_control/change_email.html", viewer=viewer, changed=changed)


@a01_bp.route("/api/password-change", methods=["GET", "POST"])
def password_change_api():
    if request.method == "GET":
        return render_template("a01_access_control/password_change_api.html")
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    new_password = data.get("new_password", "")
    # VULNERABLE: trusts the client-supplied "email" field to pick which
    # account to update -- no session, no ownership check, no
    # confirmation that the caller is the account holder at all.
    target = User.query.filter_by(email=email).first()
    if target is None:
        return jsonify({"error": "No account with that email."}), 404
    target.password_hash = generate_password_hash(new_password)
    db.session.commit()
    return jsonify({"status": "password updated"})
```

- [ ] **Step 4: Create `change_email.html`**

Create `app/categories/a01_access_control/templates/a01_access_control/change_email.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Account Takeover via CSRF (Email Change)" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A01{% endblock %}

{% block explanation %}
<p>
  This "change my email" form updates your account's registered email
  address from a plain POST, with no CSRF token and no confirmation of
  your current password or current email. Changing the registered email
  is just as dangerous as changing the password directly — whoever
  controls the email on file controls every future "forgot password"
  flow for that account.
</p>
{% endblock %}

{% block detect %}
<p>
  View the page source of the form below (or fetch it with curl) and
  search for any hidden field named something like <code>csrf_token</code>
  or <code>csrf</code> — there isn't one. A form this sensitive with no
  anti-CSRF token at all is the detection signal: any page anywhere on
  the internet can build an identical form and target it at this exact
  URL, and the browser will attach your session cookie automatically.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Log in as any user, then — instead of using the real form below —
  imagine this HTML hosted on a completely different, attacker-controlled
  site:
</p>
<pre><code class="language-html">&lt;form action="http://127.0.0.1:5001/a01/change-email" method="POST" id="f"&gt;
  &lt;input type="hidden" name="new_email" value="attacker@evil.test"&gt;
&lt;/form&gt;
&lt;script&gt;document.getElementById('f').submit();&lt;/script&gt;</code></pre>
<p>
  A logged-in victim who merely visits that attacker page has their
  session cookie sent along automatically by the browser — the request
  looks completely legitimate to the server, and the victim's account
  email silently changes to one the attacker controls, with no
  interaction beyond loading a page.
</p>
<p>
  CSRF was folded into OWASP's Broken Access Control category in the
  2021 revision, but it remains one of the most common real-world
  findings whenever a state-changing endpoint is reachable by a plain,
  unauthenticated-origin-checked POST — this app has zero CSRF protection
  anywhere, and this is the first example to name that gap directly as
  the vulnerability rather than relying on it incidentally.
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/change-email", methods=["POST"])
def change_email():
    viewer = get_current_user()
    # no CSRF token check, no current-password confirmation
    viewer.email = request.form.get("new_email", "")
    db.session.commit()
{% endblock %}

{% block secure_code %}@app.route("/change-email", methods=["POST"])
def change_email():
    viewer = get_current_user()
    validate_csrf_token(request.form.get("csrf_token"))  # rejects if missing/wrong
    if not check_password_hash(viewer.password_hash, request.form.get("current_password", "")):
        abort(403)
    viewer.email = request.form.get("new_email", "")
    db.session.commit()
{% endblock %}

{% block live_example %}
{% if viewer %}
<p>Logged in as <strong>{{ viewer.username }}</strong> — current email: <strong>{{ viewer.email }}</strong></p>
{% if changed %}
<div class="alert alert-success">Email updated.</div>
{% endif %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">New email</label>
    <input type="email" class="form-control" name="new_email" placeholder="new@example.com">
  </div>
  <button type="submit" class="btn btn-primary">Update email</button>
</form>
{% else %}
<a href="{{ url_for('core.switch_user', next=request.path) }}">Log in to try this example</a>
{% endif %}
{% endblock %}
```

- [ ] **Step 5: Create `password_change_api.html`**

Create `app/categories/a01_access_control/templates/a01_access_control/password_change_api.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "IDOR on Password-Change API" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A01{% endblock %}

{% block explanation %}
<p>
  This JSON API is meant to let a logged-in user change their own
  password. Instead of identifying the account from the caller's
  session, it trusts an <code>email</code> field in the request body to
  decide which account to update — no session, no authentication, no
  ownership check of any kind. This is the write-based sibling of this
  category's read-only IDOR example: instead of just viewing another
  user's data, you can overwrite it.
</p>
{% endblock %}

{% block detect %}
<p>
  Send a request to <code>/a01/api/password-change</code> with absolutely
  no session cookie or authentication header at all, just an
  <code>email</code> and a <code>new_password</code> in a JSON body — if
  it succeeds without ever checking who you are, the endpoint has no
  ownership check.
</p>
{% endblock %}

{% block exploitation %}
<p>
  With no login at all, from a completely fresh browser or a bare curl
  command:
</p>
<pre><code class="language-bash">curl -X POST http://127.0.0.1:5001/a01/api/password-change \
  -H "Content-Type: application/json" \
  -d '{"email": "bob@owasp-lab.local", "new_password": "attacker-chosen-password"}'</code></pre>
<p>
  Bob's password is now whatever the attacker set it to — no proof of
  ownership of Bob's account was ever required, only knowledge of his
  email address, which is rarely a secret.
</p>
<p>
  Write-based IDORs are more severe than read-based ones: a read-only
  IDOR leaks data, but a write-based IDOR like this one lets an attacker
  directly overwrite account credentials for any user whose email they
  can guess or already know — a full, unauthenticated account takeover
  primitive.
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/api/password-change", methods=["POST"])
def password_change_api():
    data = request.get_json()
    # VULNERABLE: identifies the target account from client-supplied
    # data instead of the caller's own authenticated session
    target = User.query.filter_by(email=data["email"]).first()
    target.password_hash = generate_password_hash(data["new_password"])
    db.session.commit()
{% endblock %}

{% block secure_code %}@app.route("/api/password-change", methods=["POST"])
def password_change_api():
    viewer = get_current_user()
    if viewer is None:
        abort(401)
    data = request.get_json()
    # Always derive the target from the authenticated session, never
    # from client-supplied data
    viewer.password_hash = generate_password_hash(data["new_password"])
    db.session.commit()
{% endblock %}

{% block live_example %}
<p class="text-muted">
  This is a JSON API endpoint with no HTML form — use curl or a similar
  tool as shown in the Exploitation section above:
  <code>POST /a01/api/password-change</code> with a JSON body of
  <code>{"email": "...", "new_password": "..."}</code>.
</p>
{% endblock %}
```

- [ ] **Step 6: Add both `ExampleNav` entries**

Modify `app/categories/a01_access_control/__init__.py`. Current
`examples=[...]` list ends with:

```python
            ExampleNav(
                id="mass-assignment",
                title="Account Update Role Escalation",
                group="Mass Assignment",
                difficulty="Hard",
                endpoint="a01_access_control.account_update",
                hints=[
                    "This form is meant to update your display name and bio. Look at how the server processes the submission — does it only accept the fields the form actually shows you?",
                    "The handler loops over every key in the submitted form data and sets it directly as an attribute on your user record, skipping only the 'id' field. Nothing limits it to display_name/bio.",
                    "The User model has a 'role' column. Submit the account-update form with an extra field named role set to admin (e.g. by adding a hidden field via your browser's dev tools, or crafting the raw request) — the handler happily sets your own role to admin, since it never restricts which fields it accepts.",
                    "Exact reproduction: POST to /a01/account/update with form data including role=admin alongside the normal fields — e.g. curl -X POST -d \"display_name=Me&bio=hi&role=admin\" http://127.0.0.1:5000/a01/account/update (with your session cookie) works.",
                ],
            ),
        ],
    )
)
```

Replace the closing `],` and everything after it with (inserting the new
`idor` sibling first since it's Medium and belongs in that group right
after the existing Easy `idor`, then the new CSRF group after
`mass-assignment`):

Find:
```python
            ExampleNav(
                id="idor",
                title="View Another User's Profile (IDOR)",
                group="Insecure Direct Object References (IDOR)",
                difficulty="Easy",
                endpoint="a01_access_control.idor",
                hints=[
                    "This page shows a user profile by ID, and the ID is right there in the URL. What happens if you don't view your own profile, but someone else's?",
                    "The route is /a01/profile/<user_id> — nothing on the server checks whether the ID you ask for belongs to the account you're logged in as.",
                    "Log in as any user, then edit the URL to /a01/profile/2 (or any other user ID) — the server happily returns that other user's full profile with no ownership check at all.",
                ],
            ),
            ExampleNav(
                id="admin-users",
```

Replace with:
```python
            ExampleNav(
                id="idor",
                title="View Another User's Profile (IDOR)",
                group="Insecure Direct Object References (IDOR)",
                difficulty="Easy",
                endpoint="a01_access_control.idor",
                hints=[
                    "This page shows a user profile by ID, and the ID is right there in the URL. What happens if you don't view your own profile, but someone else's?",
                    "The route is /a01/profile/<user_id> — nothing on the server checks whether the ID you ask for belongs to the account you're logged in as.",
                    "Log in as any user, then edit the URL to /a01/profile/2 (or any other user ID) — the server happily returns that other user's full profile with no ownership check at all.",
                ],
            ),
            ExampleNav(
                id="password-change-idor",
                title="IDOR on Password-Change API",
                group="Insecure Direct Object References (IDOR)",
                difficulty="Medium",
                endpoint="a01_access_control.password_change_api",
                hints=[
                    "This JSON API is meant to change YOUR password. Look at how it decides whose password to change — does it use your session, or something you supply?",
                    "The endpoint looks up the target account by an 'email' field in your request body, never checking it against any authenticated session at all.",
                    "With no login, no cookie, no authentication header whatsoever: curl -X POST http://127.0.0.1:5000/a01/api/password-change -H 'Content-Type: application/json' -d '{\"email\": \"bob@owasp-lab.local\", \"new_password\": \"attacker-chosen-password\"}' — Bob's password is now whatever you set it to, with zero proof you own his account.",
                ],
            ),
            ExampleNav(
                id="admin-users",
```

Find:
```python
            ExampleNav(
                id="mass-assignment",
                title="Account Update Role Escalation",
                group="Mass Assignment",
                difficulty="Hard",
                endpoint="a01_access_control.account_update",
                hints=[
                    "This form is meant to update your display name and bio. Look at how the server processes the submission — does it only accept the fields the form actually shows you?",
                    "The handler loops over every key in the submitted form data and sets it directly as an attribute on your user record, skipping only the 'id' field. Nothing limits it to display_name/bio.",
                    "The User model has a 'role' column. Submit the account-update form with an extra field named role set to admin (e.g. by adding a hidden field via your browser's dev tools, or crafting the raw request) — the handler happily sets your own role to admin, since it never restricts which fields it accepts.",
                    "Exact reproduction: POST to /a01/account/update with form data including role=admin alongside the normal fields — e.g. curl -X POST -d \"display_name=Me&bio=hi&role=admin\" http://127.0.0.1:5000/a01/account/update (with your session cookie) works.",
                ],
            ),
        ],
    )
)
```

Replace with:
```python
            ExampleNav(
                id="mass-assignment",
                title="Account Update Role Escalation",
                group="Mass Assignment",
                difficulty="Hard",
                endpoint="a01_access_control.account_update",
                hints=[
                    "This form is meant to update your display name and bio. Look at how the server processes the submission — does it only accept the fields the form actually shows you?",
                    "The handler loops over every key in the submitted form data and sets it directly as an attribute on your user record, skipping only the 'id' field. Nothing limits it to display_name/bio.",
                    "The User model has a 'role' column. Submit the account-update form with an extra field named role set to admin (e.g. by adding a hidden field via your browser's dev tools, or crafting the raw request) — the handler happily sets your own role to admin, since it never restricts which fields it accepts.",
                    "Exact reproduction: POST to /a01/account/update with form data including role=admin alongside the normal fields — e.g. curl -X POST -d \"display_name=Me&bio=hi&role=admin\" http://127.0.0.1:5000/a01/account/update (with your session cookie) works.",
                ],
            ),
            ExampleNav(
                id="csrf-email-change",
                title="Account Takeover via CSRF (Email Change)",
                group="Cross-Site Request Forgery",
                difficulty="Medium",
                endpoint="a01_access_control.change_email",
                hints=[
                    "This 'change my email' form updates a sensitive field with a plain POST. Check the form's HTML source for anything that would stop a DIFFERENT website from submitting the exact same request on your behalf.",
                    "There is no CSRF token anywhere in this form, and the server never checks where the request came from — only that a valid session cookie was attached, which browsers do automatically for same-origin AND cross-origin form submissions alike.",
                    "Build a tiny HTML page hosted anywhere else with an auto-submitting form targeting http://127.0.0.1:5000/a01/change-email with a hidden new_email field set to an address you control, then visit that page while logged in here — your email changes with no further interaction.",
                    "Why this matters beyond just changing an email: whoever controls the email on file controls every future password-reset flow for that account, making an email-change CSRF just as dangerous as a direct password-change CSRF.",
                ],
            ),
        ],
    )
)
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a01_csrf_email_change.py tests/test_a01_password_change_idor.py -v`
Expected: PASS (6 passed)

- [ ] **Step 8: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass. Baseline before this plan was 449. This task adds 6
new tests → 455 total.

- [ ] **Step 9: Commit**

```bash
git add app/categories/a01_access_control tests/test_a01_csrf_email_change.py tests/test_a01_password_change_idor.py
git commit -m "feat(a01): add CSRF email-change and password-change IDOR examples

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 2: A02 Additions — Reset Token Leaked via Referrer Header + Reset Token Leaked in API Response

**Files:**
- Modify: `app/categories/a02_crypto_failures/routes.py`
- Modify: `app/categories/a02_crypto_failures/__init__.py`
- Create: `app/categories/a02_crypto_failures/templates/a02_crypto_failures/reset_password_referrer.html`
- Create: `app/categories/a02_crypto_failures/templates/a02_crypto_failures/external_referrer_sink.html`
- Create: `app/categories/a02_crypto_failures/templates/a02_crypto_failures/forgot_password_api.html`
- Test: `tests/test_a02_reset_token_referrer_leak.py`
- Test: `tests/test_a02_reset_token_api_leak.py`

**Interfaces:**
- Consumes: `app.categories.a02_crypto_failures.routes.generate_reset_token(username)`
  (existing, `hashlib.md5(f"{username}:{RESET_TOKEN_SALT}").hexdigest()[:10]`),
  `app.categories.a02_crypto_failures.models.LegacyCredential` (existing,
  has `username`/`weak_password_hash`, seeded with usernames including
  `"admin"` via `seed_legacy_credentials`).
- Produces: routes `a02_crypto_failures.reset_password_referrer` (`GET/POST
  /a02/reset-password-referrer`), `a02_crypto_failures.external_referrer_sink`
  (`GET /a02/external-referrer-sink`), `a02_crypto_failures.forgot_password_api`
  (`GET/POST /a02/api/forgot-password`). Nothing later depends on these.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a02_reset_token_referrer_leak.py`:

```python
from app.categories.a02_crypto_failures.routes import generate_reset_token


def test_reset_password_referrer_page_renders_with_default_token(client):
    response = client.get("/a02/reset-password-referrer")
    assert response.status_code == 200
    assert generate_reset_token("admin").encode() in response.data


def test_reset_password_referrer_page_sets_no_referrer_policy(client):
    response = client.get("/a02/reset-password-referrer")
    assert "Referrer-Policy" not in response.headers


def test_reset_password_referrer_page_links_to_external_sink(client):
    response = client.get("/a02/reset-password-referrer")
    assert b"/a02/external-referrer-sink" in response.data


def test_external_sink_captures_and_displays_referer_with_token(client):
    token = generate_reset_token("admin")
    reset_url = f"/a02/reset-password-referrer?token={token}"

    # Simulates a browser following the "Security Tips" link on the reset
    # page: the browser automatically attaches the current page's full URL
    # (token included) as the Referer header, since nothing sets a
    # Referrer-Policy to prevent it.
    response = client.get(
        "/a02/external-referrer-sink",
        headers={"Referer": f"http://localhost{reset_url}"},
    )
    assert response.status_code == 200
    assert token.encode() in response.data
```

Create `tests/test_a02_reset_token_api_leak.py`:

```python
import hashlib

from app.categories.a02_crypto_failures.routes import generate_reset_token


def test_forgot_password_api_page_renders(client):
    response = client.get("/a02/api/forgot-password")
    assert response.status_code == 200
    assert b"Reset Token Leaked in API Response" in response.data


def test_forgot_password_api_returns_token_directly_in_json(client):
    response = client.post("/a02/api/forgot-password", json={"username": "admin"})
    assert response.status_code == 200
    data = response.get_json()
    assert data["resetToken"] == generate_reset_token("admin")


def test_leaked_token_actually_works_for_takeover(client):
    response = client.post("/a02/api/forgot-password", json={"username": "admin"})
    token = response.get_json()["resetToken"]

    reset_response = client.post(
        f"/a02/reset-password/{token}", data={"new_password": "attacker-new-password"}
    )
    assert reset_response.status_code == 200

    login_response = client.post(
        "/a02/legacy-login", data={"username": "admin", "password": "attacker-new-password"}
    )
    assert b"success" in login_response.data


def test_forgot_password_api_rejects_unknown_username(client):
    response = client.post("/a02/api/forgot-password", json={"username": "nobody"})
    assert response.status_code == 404
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_a02_reset_token_referrer_leak.py tests/test_a02_reset_token_api_leak.py -v`
Expected: FAIL — routes don't exist yet (404s).

- [ ] **Step 3: Add the three new routes**

Modify `app/categories/a02_crypto_failures/routes.py`. Current import line:

```python
from flask import render_template, request
```

Replace with (adds `jsonify`, `session`):

```python
from flask import jsonify, render_template, request, session
```

Append these three routes at the end of the file (after `legacy_login`):

```python


@a02_bp.route("/reset-password-referrer", methods=["GET", "POST"])
def reset_password_referrer():
    # A demo token for the seeded "admin" account is used when none is
    # supplied, so this page is directly viewable without first walking
    # through a real "request a reset" step.
    token = request.args.get("token") or generate_reset_token("admin")
    error = None
    success = False
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        matched_credential = None
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
    # VULNERABLE: the reset token lives in this page's own URL (query
    # string), and nothing anywhere in this app sets a Referrer-Policy
    # header -- any outbound link on this page (see the "Security Tips"
    # link below) carries the full current URL, token included, to
    # whatever it links to.
    return render_template(
        "a02_crypto_failures/reset_password_referrer.html", token=token, error=error, success=success
    )


@a02_bp.route("/external-referrer-sink")
def external_referrer_sink():
    # Plays the role of a third-party page (an analytics widget, an ad, a
    # "security tips" article -- anything embeddable or linkable) that the
    # reset-password page above links out to. In a real deployment this
    # would live on an attacker-controlled domain, silently logging every
    # visitor's in-flight reset token via the Referer header their browser
    # sends automatically.
    captured_referer = request.headers.get("Referer", "")
    session["a02_captured_referer"] = captured_referer
    return render_template(
        "a02_crypto_failures/external_referrer_sink.html", captured_referer=captured_referer
    )


@a02_bp.route("/api/forgot-password", methods=["GET", "POST"])
def forgot_password_api():
    if request.method == "GET":
        return render_template("a02_crypto_failures/forgot_password_api.html")
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    credential = LegacyCredential.query.filter_by(username=username).first()
    if credential is None:
        return jsonify({"error": "No account with that username."}), 404
    # VULNERABLE: returns the actual reset token directly in the API
    # response instead of only ever delivering it through a real
    # email/SMS channel -- anyone who can guess or already knows a
    # username gets a working reset token immediately, with no access to
    # that user's inbox required at all.
    token = generate_reset_token(username)
    return jsonify({"status": "ok", "resetToken": token})
```

- [ ] **Step 4: Create `reset_password_referrer.html`**

Create `app/categories/a02_crypto_failures/templates/a02_crypto_failures/reset_password_referrer.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Reset Token Leaked via Referrer Header" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A02{% endblock %}

{% block explanation %}
<p>
  This password-reset page is reached via a link with the reset token
  embedded directly in the URL's query string — a common, otherwise
  reasonable pattern. The problem is what happens next: this page links
  out to another page (a "Security Tips" link, standing in for any
  embeddable or clickable third-party resource — an ad, an analytics
  script, a support widget), and nothing anywhere in this app sets a
  <code>Referrer-Policy</code> header. By default, browsers send the full
  current URL as the <code>Referer</code> header on outbound navigations
  — token included — to whatever that link points to.
</p>
{% endblock %}

{% block detect %}
<p>
  Check this page's response headers for <code>Referrer-Policy</code> —
  there isn't one. Combined with a token living in the URL's query
  string rather than, say, a POST body or a short-lived server-side
  session, that's the exact shape that leaks via Referer.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Visit this page with a valid reset token in the URL (a demo one for the
  <code>admin</code> account is filled in below already), then click
  the "Security Tips" link on the page. That destination page can read
  <code>request.headers['Referer']</code> and recover the full URL you
  just came from — token and all:
</p>
<pre><code class="language-bash">curl -s http://127.0.0.1:5001/a02/external-referrer-sink \
  -H "Referer: http://127.0.0.1:5001/a02/reset-password-referrer?token=abc1234567"</code></pre>
<p>
  The response echoes back the captured Referer header, exposing the
  token in full. In a real deployment, that "Security Tips" page would
  live on an entirely different, attacker-controlled domain — the
  attacker never has to trick anyone into anything beyond clicking one
  ordinary-looking link on a page they already trust.
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/reset-password-referrer")
def reset_password_referrer():
    token = request.args.get("token")
    # token stays in the URL; no Referrer-Policy header set anywhere
    return render_template("reset_password_referrer.html", token=token)

# elsewhere in the same page's HTML:
# &lt;a href="/external-referrer-sink"&gt;Security Tips&lt;/a&gt;
{% endblock %}

{% block secure_code %}@app.route("/reset-password-referrer")
def reset_password_referrer():
    token = request.args.get("token")
    resp = make_response(render_template("reset_password_referrer.html", token=token))
    # Strips the token from the Referer header on any outbound navigation
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp
{% endblock %}

{% block live_example %}
<p>Current token in the URL: <strong>{{ token }}</strong></p>
{% if error %}<div class="alert alert-danger">{{ error }}</div>{% endif %}
{% if success %}<div class="alert alert-success">Password reset.</div>{% endif %}
<form method="post" class="mb-3">
  <input type="hidden" name="token" value="{{ token }}">
  <div class="mb-2">
    <label class="form-label">New password</label>
    <input type="password" class="form-control" name="new_password">
  </div>
  <button type="submit" class="btn btn-primary">Reset password</button>
</form>
<a href="{{ url_for('a02_crypto_failures.external_referrer_sink') }}">Security Tips</a>
{% endblock %}
```

- [ ] **Step 5: Create `external_referrer_sink.html`**

Create `app/categories/a02_crypto_failures/templates/a02_crypto_failures/external_referrer_sink.html`:

```html
{% extends "core/base.html" %}
{% block title %}Security Tips — A02{% endblock %}

{% block content %}
<h1>Security Tips</h1>
<p class="text-muted">
  This page stands in for a third-party site (an analytics widget, an ad,
  or any other embeddable/clickable resource) that the reset-password
  page links out to.
</p>
<div class="card">
  <div class="card-body">
    <h5 class="card-title">Captured Referer header</h5>
    <code>{{ captured_referer or "(no Referer header was sent)" }}</code>
  </div>
</div>
{% if "token=" in captured_referer %}
<div class="alert alert-danger mt-3">
  A password reset token just leaked to this page via the Referer header.
</div>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Create `forgot_password_api.html`**

Create `app/categories/a02_crypto_failures/templates/a02_crypto_failures/forgot_password_api.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Reset Token Leaked in API Response" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A02{% endblock %}

{% block explanation %}
<p>
  This JSON API triggers a password reset. A correctly designed reset
  flow only ever delivers the token through a side channel the requester
  doesn't control — email or SMS to the account's registered address —
  and never echoes it back in the API's own response. This one does
  exactly that: the token comes straight back in the JSON body.
</p>
{% endblock %}

{% block detect %}
<p>
  Trigger the reset API and read the entire JSON response body, not just
  the status code — look for a field that looks like a token.
</p>
{% endblock %}

{% block exploitation %}
<pre><code class="language-bash">curl -X POST http://127.0.0.1:5001/a02/api/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"username": "admin"}'</code></pre>
<p>
  The response is <code>{"status": "ok", "resetToken": "..."}</code> —
  a fully working reset token, handed directly to whoever asked for it.
  No access to the admin account's inbox was ever required. Immediately
  use it:
</p>
<pre><code class="language-bash">curl -X POST http://127.0.0.1:5001/a02/reset-password/&lt;resetToken&gt; \
  -d "new_password=attacker-new-password"</code></pre>
<p>
  The account is now fully compromised — just from knowing a username.
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/api/forgot-password", methods=["POST"])
def forgot_password_api():
    username = request.json["username"]
    token = generate_reset_token(username)
    # VULNERABLE: hands the real token back in the response instead of
    # only ever sending it through email/SMS
    return jsonify({"status": "ok", "resetToken": token})
{% endblock %}

{% block secure_code %}@app.route("/api/forgot-password", methods=["POST"])
def forgot_password_api():
    username = request.json["username"]
    token = generate_reset_token(username)
    send_password_reset_email(username, token)  # token never enters the response
    return jsonify({"status": "ok"})
{% endblock %}

{% block live_example %}
<p class="text-muted">
  This is a JSON API endpoint with no HTML form — use curl as shown in
  the Exploitation section above: <code>POST /a02/api/forgot-password</code>
  with a JSON body of <code>{"username": "admin"}</code>.
</p>
{% endblock %}
```

- [ ] **Step 7: Add both `ExampleNav` entries**

Modify `app/categories/a02_crypto_failures/__init__.py`. Find the closing
of the `examples=[...]` list:

```python
            ExampleNav(
                id="reset-token",
                title="Predictable Password Reset Token",
                group="Predictable Tokens",
                difficulty="Hard",
                endpoint="a02_crypto_failures.forgot_password",
                hints=[
                    "The reset flow never shows you a token when you request one — normal secure flows do exactly this too, so that alone isn't the tell. Look instead at HOW the token is generated: is it derived from anything you already know?",
                    "The token is computed as md5(f'{username}:SOME_SALT')[:10] — a pure function of the username and a fixed, never-rotated secret. If you knew that secret, you could compute anyone's token yourself.",
                    "This example's own source discloses the exact salt used: resetSalt2024. Compute hashlib.md5(f'admin:resetSalt2024'.encode()).hexdigest()[:10] in Python.",
                    "Visit /a02/reset-password/<the token you computed> and submit a new password for the admin account — the app never checks you own that account, only that you know a valid token for it.",
                    "Confirm the takeover by logging in at /a02/legacy-login as admin with your new password.",
                ],
            ),
        ],
        seed_fn=seed_legacy_credentials,
    )
)
```

Replace with:

```python
            ExampleNav(
                id="reset-token",
                title="Predictable Password Reset Token",
                group="Predictable Tokens",
                difficulty="Hard",
                endpoint="a02_crypto_failures.forgot_password",
                hints=[
                    "The reset flow never shows you a token when you request one — normal secure flows do exactly this too, so that alone isn't the tell. Look instead at HOW the token is generated: is it derived from anything you already know?",
                    "The token is computed as md5(f'{username}:SOME_SALT')[:10] — a pure function of the username and a fixed, never-rotated secret. If you knew that secret, you could compute anyone's token yourself.",
                    "This example's own source discloses the exact salt used: resetSalt2024. Compute hashlib.md5(f'admin:resetSalt2024'.encode()).hexdigest()[:10] in Python.",
                    "Visit /a02/reset-password/<the token you computed> and submit a new password for the admin account — the app never checks you own that account, only that you know a valid token for it.",
                    "Confirm the takeover by logging in at /a02/legacy-login as admin with your new password.",
                ],
            ),
            ExampleNav(
                id="reset-token-api-leak",
                title="Reset Token Leaked in API Response",
                group="Token Leakage",
                difficulty="Easy",
                endpoint="a02_crypto_failures.forgot_password_api",
                hints=[
                    "This is a JSON API meant to kick off a password reset — trigger it and look closely at the full response body, not just the status code.",
                    "A real password reset should only ever send the token through email or SMS. Check whether this API's JSON response contains the token itself.",
                    "curl -X POST http://127.0.0.1:5000/a02/api/forgot-password -H \"Content-Type: application/json\" -d '{\"username\": \"admin\"}' — the response includes a resetToken field directly. Use it immediately at /a02/reset-password/<token> to take over the account, no email access needed at all.",
                ],
            ),
            ExampleNav(
                id="reset-token-referrer-leak",
                title="Reset Token Leaked via Referrer Header",
                group="Token Leakage",
                difficulty="Medium",
                endpoint="a02_crypto_failures.reset_password_referrer",
                hints=[
                    "This reset-password page is reached via a link containing your token in the URL's query string. Look at what else is on this page — does it link out anywhere?",
                    "There's a 'Security Tips' link at the bottom pointing to another page. Nothing on this page sets a Referrer-Policy header, so when a browser follows that link, it sends the full current URL — token included — as the Referer header to whatever it links to.",
                    "Click the Security Tips link on this page — the destination page reads request.headers['Referer'] and recovers your reset token without you ever giving it up directly. In a real deployment that link could point anywhere, including an attacker-controlled domain.",
                    "Exact reproduction: curl -s http://127.0.0.1:5000/a02/external-referrer-sink -H \"Referer: http://127.0.0.1:5000/a02/reset-password-referrer?token=<any token>\" — the response echoes the captured Referer header back, token and all.",
                ],
            ),
        ],
        seed_fn=seed_legacy_credentials,
    )
)
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a02_reset_token_referrer_leak.py tests/test_a02_reset_token_api_leak.py -v`
Expected: PASS (8 passed)

- [ ] **Step 9: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass. 455 (after Task 1) + 8 → 463 total.

- [ ] **Step 10: Commit**

```bash
git add app/categories/a02_crypto_failures tests/test_a02_reset_token_referrer_leak.py tests/test_a02_reset_token_api_leak.py
git commit -m "feat(a02): add reset-token referrer-leak and API-response-leak examples

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 3: A04 Addition — Password Reset Poisoning via Host Header

**Files:**
- Modify: `app/categories/a04_insecure_design/routes.py`
- Modify: `app/categories/a04_insecure_design/__init__.py`
- Create: `app/categories/a04_insecure_design/templates/a04_insecure_design/forgot_password.html`
- Test: `tests/test_a04_host_header_reset_poisoning.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: route `a04_insecure_design.forgot_password` (`GET/POST
  /a04/forgot-password`). Nothing later depends on this.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a04_host_header_reset_poisoning.py`:

```python
def test_forgot_password_page_renders(client):
    response = client.get("/a04/forgot-password")
    assert response.status_code == 200
    assert b"Password Reset Poisoning" in response.data


def test_forgot_password_uses_request_host_unvalidated(client):
    response = client.post(
        "/a04/forgot-password",
        data={"email": "victim@owasp-lab.local"},
        headers={"Host": "attacker.evil.test"},
    )
    assert response.status_code == 200
    assert b"http://attacker.evil.test/a04/reset-password-confirm" in response.data


def test_forgot_password_honors_x_forwarded_host_over_host(client):
    response = client.post(
        "/a04/forgot-password",
        data={"email": "victim@owasp-lab.local"},
        headers={"Host": "real-app.local", "X-Forwarded-Host": "attacker.evil.test"},
    )
    assert response.status_code == 200
    assert b"http://attacker.evil.test/a04/reset-password-confirm" in response.data


def test_forgot_password_uses_real_host_when_nothing_forged(client):
    response = client.post(
        "/a04/forgot-password",
        data={"email": "victim@owasp-lab.local"},
        headers={"Host": "127.0.0.1:5001"},
    )
    assert response.status_code == 200
    assert b"http://127.0.0.1:5001/a04/reset-password-confirm" in response.data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_a04_host_header_reset_poisoning.py -v`
Expected: FAIL — route doesn't exist yet (404s).

- [ ] **Step 3: Add the new route**

Modify `app/categories/a04_insecure_design/routes.py`. Current import
line:

```python
from flask import redirect, render_template, request, session, url_for
```

Add `secrets` to the top-level imports (new first line of the file):

```python
import secrets

from flask import redirect, render_template, request, session, url_for
```

Append this route at the end of the file (after `checkout_confirm`):

```python


@a04_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    reset_link = None
    email = None
    if request.method == "POST":
        email = request.form.get("email", "")
        # VULNERABLE: builds the password-reset link using the Host the
        # client claims to be talking to -- preferring X-Forwarded-Host
        # when present, exactly as a real app behind a reverse proxy
        # often does -- instead of a fixed, server-configured domain. An
        # attacker who controls either header controls where the "reset"
        # link points.
        host = request.headers.get("X-Forwarded-Host") or request.host
        token = secrets.token_hex(8)
        reset_link = f"http://{host}/a04/reset-password-confirm?token={token}&email={email}"
    return render_template(
        "a04_insecure_design/forgot_password.html", reset_link=reset_link, email=email
    )
```

- [ ] **Step 4: Create `forgot_password.html`**

Create `app/categories/a04_insecure_design/templates/a04_insecure_design/forgot_password.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Password Reset Poisoning via Host Header" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A04{% endblock %}

{% block explanation %}
<p>
  This "forgot password" form builds the password-reset link it shows you
  (this lab doesn't send real email — the link is displayed directly,
  same as elsewhere in this app) using the <strong>Host</strong> header
  the request claims to have arrived on, preferring
  <strong>X-Forwarded-Host</strong> when present — a common pattern for
  apps sitting behind a reverse proxy that needs to know its own public
  hostname. Neither header is validated against a fixed, trusted list of
  real domains.
</p>
{% endblock %}

{% block detect %}
<p>
  Send the same request twice with a different <code>Host</code> header
  each time and compare the generated reset link — if the link's domain
  changes to match whatever you sent, the app trusts client-supplied
  host information for something security-sensitive.
</p>
{% endblock %}

{% block exploitation %}
<pre><code class="language-bash">curl -X POST http://127.0.0.1:5001/a04/forgot-password \
  -H "Host: attacker.evil.test" \
  -d "email=victim@owasp-lab.local"</code></pre>
<p>
  The generated reset link now points at
  <code>http://attacker.evil.test/a04/reset-password-confirm?token=...</code>
  instead of the real application. In a real deployment behind a reverse
  proxy, <strong>X-Forwarded-Host</strong> is trusted the same way and is
  often even easier to forge than <code>Host</code> itself:
</p>
<pre><code class="language-bash">curl -X POST http://127.0.0.1:5001/a04/forgot-password \
  -H "X-Forwarded-Host: attacker.evil.test" \
  -d "email=victim@owasp-lab.local"</code></pre>
<p>
  If a real victim's password-reset email had been built this way and
  they clicked the poisoned link, their reset token would be sent
  straight to the attacker's own server — via the token in the query
  string, the same class of leak the referrer-header example in A02
  demonstrates by a different route — instead of the real site,
  handing the attacker a fully working password-reset flow for that
  victim's account.
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    email = request.form["email"]
    # VULNERABLE: trusts client-supplied host information
    host = request.headers.get("X-Forwarded-Host") or request.host
    token = secrets.token_hex(8)
    reset_link = f"http://{host}/reset-password-confirm?token={token}&email={email}"
    send_password_reset_email(email, reset_link)
{% endblock %}

{% block secure_code %}APP_DOMAIN = "owasp-lab.example.com"  # fixed, server-configured

@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    email = request.form["email"]
    token = secrets.token_hex(8)
    # Uses a hardcoded, trusted domain -- never client-supplied headers
    reset_link = f"https://{APP_DOMAIN}/reset-password-confirm?token={token}&email={email}"
    send_password_reset_email(email, reset_link)
{% endblock %}

{% block live_example %}
<form method="post" class="mb-3">
  <div class="mb-2">
    <label class="form-label">Email</label>
    <input type="email" class="form-control" name="email" value="{{ email or '' }}">
  </div>
  <button type="submit" class="btn btn-primary">Send reset link</button>
</form>
{% if reset_link %}
<div class="alert alert-info">
  Reset link generated (shown here since this lab doesn't send real
  email): <br><code>{{ reset_link }}</code>
</div>
{% endif %}
{% endblock %}
```

- [ ] **Step 5: Add the `ExampleNav` entry**

Modify `app/categories/a04_insecure_design/__init__.py`. Find the closing
of the `examples=[...]` list:

```python
            ExampleNav(
                id="checkout-bypass",
                title="Multi-Step Checkout Bypass",
                group="Workflow Bypass",
                difficulty="Hard",
                endpoint="a04_insecure_design.checkout_shipping",
                hints=[
                    "This checkout has three steps: shipping, payment, confirm. Does the server actually verify you completed steps 1 and 2 before letting you reach step 3?",
                    "The shipping step just records 'shipping done' in your session and is never read again by any later step. The confirm step only checks whether an order ID already exists in your session.",
                    "Visit /a04/checkout/confirm directly, skipping /a04/checkout/shipping and /a04/checkout/payment entirely (clear your session first, or use a fresh browser/incognito window) — the server creates a new 'confirmed' order anyway, marked unpaid, with no verification any prior step occurred.",
                    "This is a workflow-bypass / business-logic flaw: enforcing a UI sequence (multi-page checkout) is not the same as enforcing it server-side. The fix is for the confirm step to verify session state set by the earlier steps rather than trusting that the user simply followed the intended page order.",
                ],
            ),
        ],
    )
)
```

Replace with:

```python
            ExampleNav(
                id="checkout-bypass",
                title="Multi-Step Checkout Bypass",
                group="Workflow Bypass",
                difficulty="Hard",
                endpoint="a04_insecure_design.checkout_shipping",
                hints=[
                    "This checkout has three steps: shipping, payment, confirm. Does the server actually verify you completed steps 1 and 2 before letting you reach step 3?",
                    "The shipping step just records 'shipping done' in your session and is never read again by any later step. The confirm step only checks whether an order ID already exists in your session.",
                    "Visit /a04/checkout/confirm directly, skipping /a04/checkout/shipping and /a04/checkout/payment entirely (clear your session first, or use a fresh browser/incognito window) — the server creates a new 'confirmed' order anyway, marked unpaid, with no verification any prior step occurred.",
                    "This is a workflow-bypass / business-logic flaw: enforcing a UI sequence (multi-page checkout) is not the same as enforcing it server-side. The fix is for the confirm step to verify session state set by the earlier steps rather than trusting that the user simply followed the intended page order.",
                ],
            ),
            ExampleNav(
                id="host-header-reset-poisoning",
                title="Password Reset Poisoning via Host Header",
                group="Password Reset Design Flaws",
                difficulty="Hard",
                endpoint="a04_insecure_design.forgot_password",
                hints=[
                    "This 'forgot password' form generates a reset link for you (since this lab doesn't send real email). Look closely at the domain in the generated link — where does the server get it from?",
                    "The reset link's domain comes directly from the request's Host header (or X-Forwarded-Host if present) rather than a fixed, server-configured value.",
                    "Send the request with a forged Host header — e.g. curl -X POST http://127.0.0.1:5000/a04/forgot-password -H 'Host: attacker.evil.test' -d 'email=victim@owasp-lab.local' — the generated reset link now points to attacker.evil.test instead of the real site.",
                    "In a real deployment behind a reverse proxy, X-Forwarded-Host is often trusted the same way and is even easier to forge — try -H 'X-Forwarded-Host: attacker.evil.test' too. If a victim's real password-reset email had been built this way and they clicked the poisoned link, their reset token would be sent straight to the attacker's server instead of the real one.",
                ],
            ),
        ],
    )
)
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a04_host_header_reset_poisoning.py -v`
Expected: PASS (4 passed)

- [ ] **Step 7: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass. 463 (after Task 2) + 4 → 467 total.

- [ ] **Step 8: Commit**

```bash
git add app/categories/a04_insecure_design tests/test_a04_host_header_reset_poisoning.py
git commit -m "feat(a04): add password reset poisoning via Host header example

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 4: A05 Addition — Clickjacking on a Sensitive Action Page

**Files:**
- Modify: `app/categories/a05_security_misconfiguration/routes.py`
- Modify: `app/categories/a05_security_misconfiguration/__init__.py`
- Create: `app/categories/a05_security_misconfiguration/templates/a05_security_misconfiguration/delete_account.html`
- Create: `app/categories/a05_security_misconfiguration/templates/a05_security_misconfiguration/delete_account_clickjack_demo.html`
- Test: `tests/test_a05_clickjacking_delete_account.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: routes `a05_security_misconfiguration.delete_account`
  (`GET/POST /a05/delete-account`) and
  `a05_security_misconfiguration.delete_account_clickjack_demo` (`GET
  /a05/delete-account-clickjack-demo`). Nothing later depends on these.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a05_clickjacking_delete_account.py`:

```python
def test_delete_account_page_renders(client):
    response = client.get("/a05/delete-account")
    assert response.status_code == 200
    assert b"Delete my account" in response.data


def test_delete_account_page_has_no_frame_protection(client):
    response = client.get("/a05/delete-account")
    assert "X-Frame-Options" not in response.headers
    csp = response.headers.get("Content-Security-Policy", "")
    assert "frame-ancestors" not in csp


def test_delete_account_post_deletes_immediately(client):
    response = client.post("/a05/delete-account")
    assert response.status_code == 200
    assert b"Account deleted" in response.data


def test_clickjack_demo_embeds_real_delete_page_in_iframe(client):
    response = client.get("/a05/delete-account-clickjack-demo")
    assert response.status_code == 200
    assert b"<iframe" in response.data
    assert b"/a05/delete-account" in response.data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_a05_clickjacking_delete_account.py -v`
Expected: FAIL — routes don't exist yet (404s).

- [ ] **Step 3: Add the two new routes**

Modify `app/categories/a05_security_misconfiguration/routes.py`. Append
these two routes at the end of the file (after `admin_panel`):

```python


@a05_bp.route("/delete-account", methods=["GET", "POST"])
def delete_account():
    deleted = False
    if request.method == "POST":
        # VULNERABLE: performs a real, irreversible action immediately
        # from a plain POST with no confirmation step -- and, just as
        # importantly, this response (like every other page in this app)
        # sets no X-Frame-Options header and no Content-Security-Policy
        # frame-ancestors directive, so it can be embedded in an
        # invisible iframe on any attacker-controlled page and clicked
        # through without the victim ever realizing it.
        deleted = True
    return render_template("a05_security_misconfiguration/delete_account.html", deleted=deleted)


@a05_bp.route("/delete-account-clickjack-demo")
def delete_account_clickjack_demo():
    return render_template("a05_security_misconfiguration/delete_account_clickjack_demo.html")
```

- [ ] **Step 4: Create `delete_account.html`**

Create `app/categories/a05_security_misconfiguration/templates/a05_security_misconfiguration/delete_account.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Clickjacking on a Sensitive Action Page" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A05{% endblock %}

{% block explanation %}
<p>
  This "delete my account" page performs a real, irreversible action from
  a single click, with no confirmation dialog and no re-authentication.
  On its own that's already risky UX — but the more fundamental
  misconfiguration is that this response, like every other page in this
  app, sets no <code>X-Frame-Options</code> header and no
  <code>Content-Security-Policy: frame-ancestors</code> directive. That
  means this exact page can be loaded inside an <code>&lt;iframe&gt;</code>
  on any other website in the world.
</p>
{% endblock %}

{% block detect %}
<p>
  Check this page's response headers for <code>X-Frame-Options</code> or
  a <code>Content-Security-Policy</code> containing
  <code>frame-ancestors</code> — neither is present anywhere in this app.
  A sensitive, one-click, irreversible action page with no framing
  protection at all is exactly what clickjacking targets.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Visit <a href="{{ url_for('a05_security_misconfiguration.delete_account_clickjack_demo') }}">the
  clickjacking demo page</a> — it shows a fake "Claim your prize" button
  with this real delete-account page loaded invisibly underneath it,
  precisely positioned so the decoy button sits directly on top of the
  real "Delete my account" button. Clicking the decoy actually clicks the
  real button hidden beneath it.
</p>
<p>
  This is a real, well-documented technique: an attacker hosts a page
  styled however they like, embeds the victim's already-logged-in
  sensitive-action page in a transparent (<code>opacity: 0</code>)
  iframe positioned exactly under a decoy element, and tricks the victim
  into clicking through. Because it's a real click inside a real,
  logged-in iframe, the browser attaches the victim's genuine session
  cookie — the resulting action is completely authentic from the
  server's point of view, indistinguishable from the victim clicking the
  real button on purpose.
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/delete-account", methods=["POST"])
def delete_account():
    # no X-Frame-Options / CSP frame-ancestors set anywhere in the app
    perform_account_deletion(current_user)
    return render_template("delete_account.html", deleted=True)
{% endblock %}

{% block secure_code %}@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    return response

@app.route("/delete-account", methods=["POST"])
def delete_account():
    if not verify_password(current_user, request.form["current_password"]):
        abort(403)
    perform_account_deletion(current_user)
    return render_template("delete_account.html", deleted=True)
{% endblock %}

{% block live_example %}
{% if deleted %}
<div class="alert alert-danger">Account deleted.</div>
{% else %}
<form method="post">
  <button type="submit" class="btn btn-danger">Delete my account</button>
</form>
{% endif %}
{% endblock %}
```

- [ ] **Step 5: Create `delete_account_clickjack_demo.html`**

Create `app/categories/a05_security_misconfiguration/templates/a05_security_misconfiguration/delete_account_clickjack_demo.html`:

```html
{% extends "core/base.html" %}
{% block title %}Claim Your Prize! — Clickjacking Demo{% endblock %}

{% block content %}
<h1>Clickjacking Demo</h1>
<p class="text-muted">
  This page simulates an attacker-controlled site. The box below layers a
  transparent iframe of the real <code>/a05/delete-account</code> page
  directly over a decoy "Claim your prize" button, aligned so that
  clicking the decoy actually clicks the real "Delete my account" button
  hidden underneath.
</p>
<div style="position: relative; width: 260px; height: 80px;">
  <button
    style="position: absolute; top: 0; left: 0; width: 260px; height: 80px; font-size: 1.2rem;"
    class="btn btn-success"
  >
    🎉 Claim Your Prize!
  </button>
  <iframe
    src="{{ url_for('a05_security_misconfiguration.delete_account') }}"
    style="position: absolute; top: 0; left: 0; width: 260px; height: 80px; opacity: 0.15; border: 2px dashed red;"
  ></iframe>
</div>
<p class="text-muted mt-3">
  (The iframe is shown at 15% opacity here so you can see the overlay
  technique — a real attacker would set it to fully transparent.)
</p>
{% endblock %}
```

- [ ] **Step 6: Add the `ExampleNav` entry**

Modify `app/categories/a05_security_misconfiguration/__init__.py`. Find
the closing of the `examples=[...]` list:

```python
            ExampleNav(
                id="default-admin-creds",
                title="Forgotten Admin Panel with Default Credentials",
                group="Exposed Debug & Admin Interfaces",
                difficulty="Hard",
                endpoint="a05_security_misconfiguration.admin_login",
                hints=[
                    "This is a forgotten internal admin panel. Before trying anything clever, consider: tools like this often ship with default credentials that get forgotten after deployment. What's this tool's typical default username?",
                    "Try the single most common default admin username: admin. The password is a specific, memorable-looking string that was clearly set once and never rotated since — think in terms of the product name plus a deployment year.",
                    "Log in at /a05/admin-login with username admin and password DataVault@2019 — these factory-default credentials were never changed after this internal tool went live, and they grant full access to the admin panel's customer records (names, emails, and password hints) at /a05/admin-panel.",
                ],
            ),
        ],
    )
)
```

Replace with:

```python
            ExampleNav(
                id="default-admin-creds",
                title="Forgotten Admin Panel with Default Credentials",
                group="Exposed Debug & Admin Interfaces",
                difficulty="Hard",
                endpoint="a05_security_misconfiguration.admin_login",
                hints=[
                    "This is a forgotten internal admin panel. Before trying anything clever, consider: tools like this often ship with default credentials that get forgotten after deployment. What's this tool's typical default username?",
                    "Try the single most common default admin username: admin. The password is a specific, memorable-looking string that was clearly set once and never rotated since — think in terms of the product name plus a deployment year.",
                    "Log in at /a05/admin-login with username admin and password DataVault@2019 — these factory-default credentials were never changed after this internal tool went live, and they grant full access to the admin panel's customer records (names, emails, and password hints) at /a05/admin-panel.",
                ],
            ),
            ExampleNav(
                id="clickjacking-delete-account",
                title="Clickjacking on a Sensitive Action Page",
                group="Missing Security Headers",
                difficulty="Easy",
                endpoint="a05_security_misconfiguration.delete_account",
                hints=[
                    "This 'delete my account' page performs a real, irreversible action from a plain POST. Check its response headers — is there anything that would stop this page from being loaded inside another site's <iframe>?",
                    "There's no X-Frame-Options header and no Content-Security-Policy frame-ancestors directive anywhere in this app — any page on the internet can embed this exact page inside an invisible iframe.",
                    "Visit /a05/delete-account-clickjack-demo — it shows a fake 'Claim your prize' button with the real delete-account page loaded invisibly underneath it, precisely aligned. Clicking the decoy button actually clicks the real Delete Account button hidden beneath it.",
                    "This is a real technique: an attacker hosts a page styled however they like, embeds the victim's already-logged-in sensitive-action page in a transparent iframe positioned exactly under a decoy element, and tricks the victim into clicking through — the browser sends the victim's real session cookie, so the resulting action is completely genuine from the server's point of view.",
                ],
            ),
        ],
    )
)
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a05_clickjacking_delete_account.py -v`
Expected: PASS (4 passed)

- [ ] **Step 8: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass. 467 (after Task 3) + 4 → 471 total.

- [ ] **Step 9: Commit**

```bash
git add app/categories/a05_security_misconfiguration tests/test_a05_clickjacking_delete_account.py
git commit -m "feat(a05): add clickjacking-on-delete-account example

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Orchestration Note: Tasks 5-8 All Edit A07's `__init__.py`

Tasks 5, 6, 7, and 8 each insert `ExampleNav` entries into
`app/categories/a07_auth_failures/__init__.py`'s `examples=[...]` list,
and each task's own instructions describe its insertion point relative
to an existing entry's `id` (e.g. "immediately before `mfa-bypass`"),
not as a rigid full-block find/replace against the file's *original*
pre-project contents. This is intentional and required: if these four
tasks run in order (5, then 6, then 7, then 8 — the intended order),
each one changes what immediately surrounds the anchor entries the next
task targets. **When implementing each of these four tasks, always
re-read the actual current contents of `__init__.py` first and locate
the insertion point by the named `id`, rather than pattern-matching an
exact old/new code block copied verbatim from an earlier state of the
plan.** The worked-out final result, after all four tasks land in order,
is: the "Multi-Factor Authentication Bypass" group reads (Easy→Hard)
`mfa-bypass-magic-value, mfa-leaked-code, mfa-reusable-code,
mfa-brute-force, mfa-bypass, mfa-not-bound-to-session`; a new "Account
Recovery Abuse" group (Task 5) follows it; a new "Cross-Site Request
Forgery" group (Task 8, sole entry `csrf-disable-2fa`) is last. Task 9
gives the exact resulting flat list this must produce.

---

## Task 5: A07 Additions — Account Recovery Abuse (3 examples)

**Files:**
- Modify: `app/categories/a07_auth_failures/routes.py`
- Modify: `app/categories/a07_auth_failures/__init__.py`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/register.html`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/forgot_password_self.html`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/account_lookup.html`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_forgot_password.html`
- Test: `tests/test_a07_username_collision.py`
- Test: `tests/test_a07_unicode_normalization.py`
- Test: `tests/test_a07_mfa_forgot_password.py`

**Interfaces:**
- Consumes: `app.categories.a07_auth_failures.models.A07Account`/`AuthSession` (existing, unchanged — `A07Account(id, username unique, password_hash)`, `AuthSession(id, username nullable, mfa_verified default False, created_at)`), `app.categories.a07_auth_failures.session_store.get_or_create_session()` (existing), `routes.py`'s existing `_render(template_name, session_row, **context)` / `_redirect(endpoint, session_row, **kwargs)` helpers (existing, unchanged).
- Produces: routes `a07_auth_failures.register` (`GET/POST /a07/register`), `a07_auth_failures.forgot_password_self` (`GET/POST /a07/forgot-password`), `a07_auth_failures.account_lookup` (`GET/POST /a07/account-lookup`), `a07_auth_failures.mfa_forgot_password` (`GET/POST /a07/mfa-forgot-password`). Nothing later in this plan depends on these. No new DB tables or columns — all three examples reuse `A07Account`/`AuthSession` exactly as they already exist.

No new dedicated storage is needed: username-collision and Unicode-normalization both just need new `A07Account` rows (the model already allows any string, including whitespace or arbitrary Unicode, since `username` is a plain unconstrained `String(80)`); password-reset-disables-2FA only mutates an existing `AuthSession` row's existing `mfa_verified` column.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a07_username_collision.py`:

```python
from werkzeug.security import check_password_hash, generate_password_hash

from app.categories.a07_auth_failures.models import A07Account
from app.extensions import db


def test_register_page_renders(client):
    response = client.get("/a07/register")
    assert response.status_code == 200
    assert b"Password Reset via Username Collision" in response.data


def test_register_stores_username_with_whitespace_exactly(app, client):
    client.post("/a07/register", data={"username": "admin ", "password": "attacker-pw"})
    with app.app_context():
        account = A07Account.query.filter_by(username="admin ").first()
        assert account is not None


def test_username_collision_password_reset_hits_victim_account(app, client):
    with app.app_context():
        victim = A07Account(
            username="admin",
            password_hash=generate_password_hash("victim-original-pw", method="pbkdf2:sha256"),
        )
        db.session.add(victim)
        db.session.commit()
        victim_id = victim.id

    # Attacker registers with the victim's username plus a trailing space --
    # a technically distinct, brand-new account.
    response = client.post(
        "/a07/register", data={"username": "admin ", "password": "attacker-pw"}, follow_redirects=True
    )
    assert response.status_code == 200

    # Attacker (now logged in via session as "admin ") requests a password
    # reset "for themselves".
    response = client.post(
        "/a07/forgot-password", data={"new_password": "attacker-chosen-password"}, follow_redirects=True
    )
    assert response.status_code == 200

    with app.app_context():
        victim_after = db.session.get(A07Account, victim_id)
        assert check_password_hash(victim_after.password_hash, "attacker-chosen-password")

    # The attacker's own, distinct "admin " account is untouched.
    with app.app_context():
        attacker_account = A07Account.query.filter_by(username="admin ").first()
        assert check_password_hash(attacker_account.password_hash, "attacker-pw")
```

Create `tests/test_a07_unicode_normalization.py`:

```python
import unicodedata

from werkzeug.security import generate_password_hash

from app.categories.a07_auth_failures.models import A07Account
from app.extensions import db


def test_account_lookup_page_renders(client):
    response = client.get("/a07/account-lookup")
    assert response.status_code == 200
    assert b"Account Takeover via Unicode Normalization" in response.data


def test_lookalike_character_normalizes_to_target_username():
    lookalike_username = "demⓞ"
    assert unicodedata.normalize("NFKC", lookalike_username) == "demo"


def test_unicode_lookalike_username_collides_with_real_account(app, client):
    with app.app_context():
        victim = A07Account(
            username="demo", password_hash=generate_password_hash("victim-pw", method="pbkdf2:sha256")
        )
        db.session.add(victim)
        db.session.commit()

    lookalike_username = "demⓞ"  # NFKC-normalizes to "demo"
    client.post("/a07/register", data={"username": lookalike_username, "password": "attacker-pw"})

    response = client.post("/a07/account-lookup", data={"username": "demo"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"demo" in response.data

    # The attacker's session is now authenticated AS the victim's real account.
    account_response = client.get("/a07/account")
    assert b"Logged in as" in account_response.data
    assert b"demo" in account_response.data
```

Create `tests/test_a07_mfa_forgot_password.py`:

```python
from werkzeug.security import generate_password_hash

from app.categories.a07_auth_failures.models import A07Account, AuthSession
from app.extensions import db


def test_mfa_forgot_password_page_renders(client):
    response = client.get("/a07/mfa-forgot-password")
    assert response.status_code == 200
    assert b"Password Reset Silently Disables 2FA" in response.data


def test_mfa_forgot_password_rejects_unknown_username(client):
    response = client.post("/a07/mfa-forgot-password", data={"username": "nobody", "new_password": "x"})
    assert response.status_code == 200
    assert b"No account" in response.data


def test_password_reset_marks_mfa_verified_without_entering_code(app, client):
    with app.app_context():
        account = A07Account(
            username="dana2fa",
            password_hash=generate_password_hash("original-pw", method="pbkdf2:sha256"),
        )
        db.session.add(account)
        db.session.commit()

    response = client.post(
        "/a07/mfa-forgot-password",
        data={"username": "dana2fa", "new_password": "attacker-new-pw"},
    )
    assert response.status_code == 200

    # The verification-code step (/a07/mfa-verify) was never touched at
    # all, yet the session is now marked MFA-verified purely from
    # resetting the password.
    with app.app_context():
        session_row = AuthSession.query.filter_by(username="dana2fa").first()
        assert session_row is not None
        assert session_row.mfa_verified is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_a07_username_collision.py tests/test_a07_unicode_normalization.py tests/test_a07_mfa_forgot_password.py -v`
Expected: FAIL — routes don't exist yet (404s).

- [ ] **Step 3: Add the four new routes**

Modify `app/categories/a07_auth_failures/routes.py`. Current top of file:

```python
from flask import make_response, redirect, render_template, request, url_for
from werkzeug.security import check_password_hash

from app.categories.a07_auth_failures import a07_bp
from app.categories.a07_auth_failures.models import A07Account
from app.categories.a07_auth_failures.session_store import SID_COOKIE, get_or_create_session
from app.extensions import db
```

Replace with (adds `unicodedata` and `generate_password_hash`):

```python
import unicodedata

from flask import make_response, redirect, render_template, request, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app.categories.a07_auth_failures import a07_bp
from app.categories.a07_auth_failures.models import A07Account
from app.categories.a07_auth_failures.session_store import SID_COOKIE, get_or_create_session
from app.extensions import db
```

Append these four routes at the end of the file (after `mfa_dashboard`):

```python


@a07_bp.route("/register", methods=["GET", "POST"])
def register():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if A07Account.query.filter_by(username=username).first() is not None:
            error = "That username is already taken."
        else:
            # VULNERABLE: stores the username exactly as submitted, with no
            # whitespace stripping or normalization -- "admin" and "admin "
            # are treated as two entirely distinct accounts here.
            account_row = A07Account(
                username=username, password_hash=generate_password_hash(password, method="pbkdf2:sha256")
            )
            db.session.add(account_row)
            db.session.commit()
            session_row.username = username
            db.session.commit()
            return _redirect("a07_auth_failures.forgot_password_self", session_row)
    return _render("a07_auth_failures/register.html", session_row, error=error)


@a07_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password_self():
    session_row = get_or_create_session()
    error = None
    success = False
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        # VULNERABLE: strips whitespace when looking up which account to
        # reset, but registration stored the username with no such
        # normalization -- if another account exists whose username
        # exactly equals yours after stripping, THAT account gets reset
        # instead of the one you actually registered.
        target_username = (session_row.username or "").strip()
        target = A07Account.query.filter_by(username=target_username).first()
        if target is None:
            error = "No matching account found."
        else:
            target.password_hash = generate_password_hash(new_password, method="pbkdf2:sha256")
            db.session.commit()
            success = True
    return _render(
        "a07_auth_failures/forgot_password_self.html", session_row, error=error, success=success
    )


def _normalize_username(value):
    return unicodedata.normalize("NFKC", value).casefold()


@a07_bp.route("/account-lookup", methods=["GET", "POST"])
def account_lookup():
    session_row = get_or_create_session()
    error = None
    matched_username = None
    if request.method == "POST":
        query_username = request.form.get("username", "")
        normalized_query = _normalize_username(query_username)
        # VULNERABLE: treats any two usernames that normalize to the same
        # string as the SAME account for recovery purposes -- a Unicode
        # lookalike character that NFKC-normalizes to an ASCII letter
        # collides with a completely different, real ASCII-only account.
        for account_row in A07Account.query.all():
            if _normalize_username(account_row.username) == normalized_query:
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


@a07_bp.route("/mfa-forgot-password", methods=["GET", "POST"])
def mfa_forgot_password():
    session_row = get_or_create_session()
    error = None
    success = False
    if request.method == "POST":
        username = request.form.get("username", "")
        new_password = request.form.get("new_password", "")
        account_row = A07Account.query.filter_by(username=username).first()
        if account_row is None:
            error = "No account with that username."
        else:
            account_row.password_hash = generate_password_hash(new_password, method="pbkdf2:sha256")
            session_row.username = account_row.username
            # VULNERABLE: completing a password reset marks this session as
            # already MFA-verified -- the code-entry step (the actual
            # second factor) is never required at all after a reset,
            # silently disabling MFA protection for the account.
            session_row.mfa_verified = True
            db.session.commit()
            success = True
    return _render(
        "a07_auth_failures/mfa_forgot_password.html", session_row, error=error, success=success
    )
```

- [ ] **Step 4: Create `register.html`**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/register.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Password Reset via Username Collision" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A07{% endblock %}

{% block explanation %}
<p>
  This registration form accepts any username exactly as typed, including
  leading or trailing whitespace — <code>"admin"</code> and
  <code>"admin "</code> are stored as two entirely distinct accounts. The
  self-service "forgot my password" flow that follows registration,
  however, looks up which account to reset by <strong>stripping</strong>
  whitespace from your session's username first. If another account
  already exists whose username exactly equals yours after stripping,
  the reset lands on THAT account instead of the one you actually
  registered.
</p>
{% endblock %}

{% block detect %}
<p>
  Register an account whose username is an existing one plus a trailing
  space (e.g. an account you know exists, with a space appended), then
  use the "forgot password" flow immediately afterward — check whose
  password actually changes.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Register a new account with username <code>admin </code> (note the
      trailing space) and any password of your choosing, at the form
      below.</li>
  <li>You're automatically taken to the password reset page. Submit a new
      password there.</li>
</ol>
<p>
  The reset flow strips whitespace from your session's username
  (<code>"admin "</code> → <code>"admin"</code>) before looking up which
  account to update — and if a real <code>admin</code> account already
  exists, ITS password gets overwritten, not the one you just
  registered. You now control the real admin account's password without
  ever knowing its original password, purely by exploiting a whitespace
  mismatch between registration (no normalization) and password reset
  (normalizes before matching).
</p>
<p>
  This is the same class of bug as a real-world account-takeover
  vulnerability in CTFd (CVE-2020-7245): register with the victim's
  username plus whitespace, then trigger a reset for "yourself" and let
  the loose matching redirect it onto the victim's real account.
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]  # stored exactly as typed, no normalization
    account = Account(username=username, password_hash=hash_password(request.form["password"]))
    db.session.add(account)
    db.session.commit()
    session["username"] = username  # unstripped

@app.route("/forgot-password", methods=["POST"])
def forgot_password_self():
    target_username = session["username"].strip()  # VULNERABLE: normalizes on lookup only
    target = Account.query.filter_by(username=target_username).first()
    target.password_hash = hash_password(request.form["new_password"])
{% endblock %}

{% block secure_code %}@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"].strip()  # normalize once, consistently, at write time
    if Account.query.filter_by(username=username).first():
        abort(409)
    account = Account(username=username, password_hash=hash_password(request.form["password"]))
    db.session.add(account)
    db.session.commit()
    session["username"] = username

@app.route("/forgot-password", methods=["POST"])
def forgot_password_self():
    target = Account.query.filter_by(username=session["username"]).first()  # same normalized value everywhere
    target.password_hash = hash_password(request.form["new_password"])
{% endblock %}

{% block live_example %}
{% if error %}<p class="text-danger">{{ error }}</p>{% endif %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Username</label>
    <input class="form-control" type="text" name="username" placeholder="admin ">
  </div>
  <div class="mb-2">
    <label class="form-label">Password</label>
    <input class="form-control" type="password" name="password">
  </div>
  <button type="submit" class="btn btn-primary">Register</button>
</form>
{% endblock %}
```

- [ ] **Step 5: Create `forgot_password_self.html`**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/forgot_password_self.html`
(supporting flow page — extends plain `core/base.html`, matching `mfa_verify.html`/`account.html`'s convention):

```html
{% extends "core/base.html" %}
{% block title %}Forgot Password — A07{% endblock %}

{% block content %}
<h1>Forgot Password</h1>
<p>Logged in as: <strong>{{ session_row.username }}</strong></p>
<form method="post">
  <div class="mb-2">
    <label class="form-label">New password</label>
    <input class="form-control" type="password" name="new_password">
  </div>
  <button type="submit" class="btn btn-primary">Reset my password</button>
</form>
{% if success %}
<p class="mt-3 text-success">Password reset.</p>
{% endif %}
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Create `account_lookup.html`**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/account_lookup.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Account Takeover via Unicode Normalization" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A07{% endblock %}

{% block explanation %}
<p>
  This "find my account" recovery feature looks up an account by
  comparing usernames after Unicode NFKC normalization and case-folding
  — meant to be forgiving about accents, full-width characters, and
  capitalization. The problem: several visually similar Unicode
  characters normalize down to plain ASCII letters. A username built
  from one of those lookalike characters can normalize to the exact same
  string as a completely different, real account's ASCII username — and
  this feature treats that as a match, logging you in as the matched
  account.
</p>
{% endblock %}

{% block detect %}
<p>
  Register an account using a username built from an unusual-looking
  Unicode character in place of an ordinary letter, then use this lookup
  form with a target username that's the plain-ASCII version — see
  whether the lookup treats them as the same account.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Register a new account at
  <a href="{{ url_for('a07_auth_failures.register') }}">/a07/register</a> with the username
  <code>demⓞ</code> (that's "dem" followed by U+24DE, CIRCLED LATIN
  SMALL LETTER O — it looks like an "o" but isn't one). Any password
  works.
</p>
<p>
  Then submit <code>demo</code> (the real, existing account's plain
  ASCII username) into the lookup form below. Unicode NFKC normalization
  strips the circle decoration from U+24DE, turning
  <code>"dem" + "ⓞ"</code> into plain <code>"demo"</code> — so the
  lookup's normalized comparison treats your lookalike registration and
  the real <code>demo</code> account as the same identity, and logs your
  session in AS the real <code>demo</code> account.
</p>
<p>
  Tools like <a href="https://github.com/tomnomnom/hacks/tree/master/unisub">unisub</a>
  can suggest which Unicode lookalike characters normalize to a given
  target character for exactly this kind of attack.
</p>
{% endblock %}

{% block vulnerable_code %}import unicodedata

def normalize_username(value):
    return unicodedata.normalize("NFKC", value).casefold()

@app.route("/account-lookup", methods=["POST"])
def account_lookup():
    query = normalize_username(request.form["username"])
    for account in Account.query.all():
        # VULNERABLE: treats ANY two usernames with the same normalized
        # form as the same identity for account-recovery purposes
        if normalize_username(account.username) == query:
            session["username"] = account.username  # logs in as the MATCH, not the input
            return redirect(url_for("account"))
{% endblock %}

{% block secure_code %}@app.route("/account-lookup", methods=["POST"])
def account_lookup():
    # Exact match only -- no normalization-based equivalence between
    # visually similar but distinct usernames
    account = Account.query.filter_by(username=request.form["username"]).first()
    if account is None:
        abort(404)
    send_account_recovery_email(account)  # never logs the requester in directly
{% endblock %}

{% block live_example %}
{% if error %}<p class="text-danger">{{ error }}</p>{% endif %}
{% if matched_username %}
<p class="text-success">Matched and logged in as: <strong>{{ matched_username }}</strong></p>
{% endif %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Username to look up</label>
    <input class="form-control" type="text" name="username" placeholder="demo">
  </div>
  <button type="submit" class="btn btn-primary">Find account</button>
</form>
{% endblock %}
```

- [ ] **Step 7: Create `mfa_forgot_password.html`**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_forgot_password.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Password Reset Silently Disables 2FA" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A07{% endblock %}

{% block explanation %}
<p>
  This password-reset flow is meant purely to let a user set a new
  password. But completing it also marks the current session as having
  already passed multi-factor verification — with no code ever entered,
  and no re-check of the second factor anywhere in the process. A
  password reset and a second-factor check are two independent proofs of
  identity; conflating "you reset your password" with "you completed
  MFA" quietly removes the second-factor protection entirely.
</p>
{% endblock %}

{% block detect %}
<p>
  Complete a password reset for an account, then check whether that
  session's MFA-verified state got set to true — without you ever having
  submitted a verification code anywhere.
</p>
{% endblock %}

{% block exploitation %}
<pre><code class="language-bash">curl -X POST http://127.0.0.1:5001/a07/mfa-forgot-password \
  -d "username=dana&new_password=attacker-chosen-password" \
  -c cookies.txt</code></pre>
<p>
  The response confirms the password reset succeeded — but behind the
  scenes, the session tied to those cookies is now also flagged as
  MFA-verified, purely as a side effect of resetting the password. Any
  account, MFA-protected or not, becomes fully accessible through this
  one step: no password AND no verification code ever had to be known in
  advance, only the username.
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/mfa-forgot-password", methods=["POST"])
def mfa_forgot_password():
    account = Account.query.filter_by(username=request.form["username"]).first()
    account.password_hash = hash_password(request.form["new_password"])
    session_row.username = account.username
    # VULNERABLE: a password reset is treated as equivalent to completing MFA
    session_row.mfa_verified = True
    db.session.commit()
{% endblock %}

{% block secure_code %}@app.route("/mfa-forgot-password", methods=["POST"])
def mfa_forgot_password():
    account = Account.query.filter_by(username=request.form["username"]).first()
    account.password_hash = hash_password(request.form["new_password"])
    session_row.username = account.username
    # Resetting the password never implies MFA was completed -- the
    # normal /mfa-verify step is still required afterward
    session_row.mfa_verified = False
    db.session.commit()
{% endblock %}

{% block live_example %}
{% if error %}<p class="text-danger">{{ error }}</p>{% endif %}
{% if success %}<p class="text-success">Password reset. (Check: was MFA silently marked verified too?)</p>{% endif %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Username</label>
    <input class="form-control" type="text" name="username" value="dana">
  </div>
  <div class="mb-2">
    <label class="form-label">New password</label>
    <input class="form-control" type="password" name="new_password">
  </div>
  <button type="submit" class="btn btn-primary">Reset password</button>
</form>
{% endblock %}
```

- [ ] **Step 8: Add all three `ExampleNav` entries**

Modify `app/categories/a07_auth_failures/__init__.py`. Find the closing
of the `examples=[...]` list (the `mfa-bypass` entry followed by the
list's close and `seed_fn`):

```python
            ExampleNav(
                id="mfa-bypass",
                title="Bypassable Multi-Factor Authentication",
                group="Multi-Factor Authentication Bypass",
                difficulty="Hard",
                endpoint="a07_auth_failures.mfa_login",
                hints=[
                    "This login has two steps: password, then a verification code. Once you've completed just the FIRST step, what does the server actually know about your session?",
                    "After a successful password check, the session is updated with your username but mfa_verified is explicitly set to False — the app clearly intends you to complete step two before being treated as logged in.",
                    "Look at what the dashboard route actually checks before granting access — does it verify mfa_verified, or only that a username is present on the session at all?",
                    "Log in with a valid username/password at /a07/mfa-login (this sets your session's username but not mfa_verified), then skip the code-entry step entirely and navigate directly to /a07/mfa-dashboard — the dashboard only checks that a username is set, never that MFA was actually completed, so you're in.",
                ],
            ),
        ],
        seed_fn=seed_a07_accounts,
    )
)
```

Note for whoever assembles the final plan: Tasks 6, 7, and 8 ALSO insert entries into this same file, some before and some after the `mfa-bypass` entry. When assembling, insert this task's three "Account Recovery Abuse" entries as a new group appended immediately after the `mfa-bypass` entry (and after any Task 6/7/8 entries that land in the "Multi-Factor Authentication Bypass" group), before the list's closing `],`. The three entries below must stay together and in this exact Medium → Hard → Hard order (the two Hard entries' relative order doesn't matter since they're tied):

```python
            ExampleNav(
                id="password-reset-disables-mfa",
                title="Password Reset Silently Disables 2FA",
                group="Account Recovery Abuse",
                difficulty="Medium",
                endpoint="a07_auth_failures.mfa_forgot_password",
                hints=[
                    "This password-reset form is meant to do exactly one thing: set a new password. Check what else changes on your session afterward, specifically anything related to MFA.",
                    "Completing this reset sets your session's MFA-verified flag to true directly — no verification code was ever submitted anywhere in this flow.",
                    "curl -X POST http://127.0.0.1:5000/a07/mfa-forgot-password -d 'username=dana&new_password=attacker-chosen-password' -c cookies.txt — the response confirms the password reset, and the session tied to those cookies is now marked as having passed MFA too, purely as a side effect.",
                ],
            ),
            ExampleNav(
                id="username-collision-reset",
                title="Password Reset via Username Collision",
                group="Account Recovery Abuse",
                difficulty="Hard",
                endpoint="a07_auth_failures.register",
                hints=[
                    "This registration form stores your username exactly as you typed it. What happens if you add invisible whitespace to a username that already belongs to someone else?",
                    "Register an account with a username that already exists PLUS a trailing space (e.g. admin with a space appended) — since it's technically a different string, registration succeeds as a brand-new, separate account.",
                    "The password-reset flow that follows registration strips whitespace before looking up which account to update. If a REAL account already exists whose username exactly equals your padded username after stripping, the reset targets that real account instead of the one you just registered.",
                    "Exact reproduction: register username 'admin ' (with a trailing space) at /a07/register with any password, then submit a new password at the forgot-password page you're redirected to — the real admin account's password changes, not the 'admin ' account you registered. This mirrors a real CVE (CTFd, CVE-2020-7245).",
                ],
            ),
            ExampleNav(
                id="unicode-normalization-takeover",
                title="Account Takeover via Unicode Normalization",
                group="Account Recovery Abuse",
                difficulty="Hard",
                endpoint="a07_auth_failures.account_lookup",
                hints=[
                    "This 'find my account' feature normalizes usernames before comparing them, to be forgiving about accents and capitalization. Some Unicode characters LOOK like ordinary letters but aren't — what happens if normalization turns two visually-similar-but-different usernames into the exact same string?",
                    "First register an account at /a07/register using an unusual Unicode character in place of an ordinary letter (e.g. U+24DE, CIRCLED LATIN SMALL LETTER O, in place of a real 'o') — it looks almost identical but is a completely different character.",
                    "Unicode NFKC normalization strips the circle decoration from a character like U+24DE, turning it into a plain 'o'. Submit the REAL account's plain-ASCII username into this lookup form — the normalized comparison treats your lookalike-username account and the real account as the same identity.",
                    "Exact reproduction: register username 'dem' + chr(0x24DE) (renders as 'demⓞ') at /a07/register, then submit 'demo' into this page's lookup form — you're logged in as the real demo account, no password required at all.",
                ],
            ),
```

- [ ] **Step 9: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a07_username_collision.py tests/test_a07_unicode_normalization.py tests/test_a07_mfa_forgot_password.py -v`
Expected: PASS (11 passed)

- [ ] **Step 10: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass.

- [ ] **Step 11: Commit**

```bash
git add app/categories/a07_auth_failures tests/test_a07_username_collision.py tests/test_a07_unicode_normalization.py tests/test_a07_mfa_forgot_password.py
git commit -m "feat(a07): add Account Recovery Abuse group (username collision, unicode normalization, reset-disables-2FA)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 6: A07 Additions — MFA Code Leaked to Client + MFA Code Reusability

**Files:**
- Modify: `app/categories/a07_auth_failures/models.py`
- Modify: `app/categories/a07_auth_failures/routes.py`
- Modify: `app/categories/a07_auth_failures/__init__.py`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_leaked_login.html`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_leaked_verify.html`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_leaked_dashboard.html`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_reusable_login.html`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_reusable_verify.html`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_reusable_dashboard.html`
- Test: `tests/test_a07_mfa_leaked_code.py`
- Test: `tests/test_a07_mfa_reusable_code.py`

**Interfaces:**
- Consumes: `app.categories.a07_auth_failures.models.A07Account`,
  `app.categories.a07_auth_failures.session_store.get_or_create_session()`,
  `app.categories.a07_auth_failures.routes._render()`/`_redirect()`
  (existing), `app.categories.a07_auth_failures.seed.SEED_ACCOUNTS`
  (existing seeded accounts `dana`/`welcome1`, `morgan`/`Summer2023!`).
- Produces: a new `AuthSession.pending_mfa_code` column (nullable
  `String(6)`) — a generic, reusable per-session "pending MFA code"
  slot that later MFA examples (Tasks 7-8) should reuse rather than
  inventing their own column. **Known consequence:** this app uses
  `db.create_all()`, which does not retrofit new columns onto an
  already-existing Postgres dev volume (the same limitation already hit
  and documented for the scoring+hints project) — after this task lands,
  a local Docker dev environment needs `docker compose down -v && docker
  compose up -d` to pick up the new column. Nothing to fix here, just
  noted so it isn't rediscovered as a surprise.
- Produces routes: `a07_auth_failures.mfa_leaked_login` (`GET/POST
  /a07/mfa-leaked-code/login`), `a07_auth_failures.mfa_leaked_send_code_api`
  (`POST /a07/mfa-leaked-code/api/send-code`),
  `a07_auth_failures.mfa_leaked_verify` (`GET/POST
  /a07/mfa-leaked-code/verify`), `a07_auth_failures.mfa_leaked_dashboard`
  (`GET /a07/mfa-leaked-code/dashboard`), `a07_auth_failures.mfa_reusable_login`
  (`GET/POST /a07/mfa-reusable-code/login`),
  `a07_auth_failures.mfa_reusable_verify` (`GET/POST
  /a07/mfa-reusable-code/verify`), `a07_auth_failures.mfa_reusable_dashboard`
  (`GET /a07/mfa-reusable-code/dashboard`). Nothing later depends on these
  specific routes, but Tasks 7-8 will follow this same
  login→verify→dashboard route-triple shape and reuse `pending_mfa_code`.

- [ ] **Step 1: Add the `pending_mfa_code` column**

Modify `app/categories/a07_auth_failures/models.py`. Current `AuthSession`:

```python
class AuthSession(db.Model):
    __tablename__ = "a07_auth_sessions"

    id = db.Column(db.String(32), primary_key=True)
    username = db.Column(db.String(80), nullable=True)
    mfa_verified = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
```

Replace with:

```python
class AuthSession(db.Model):
    __tablename__ = "a07_auth_sessions"

    id = db.Column(db.String(32), primary_key=True)
    username = db.Column(db.String(80), nullable=True)
    mfa_verified = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # Generic per-session "pending MFA code" slot, set at login time and
    # checked at verify time by any MFA example that needs one. Reused
    # across multiple examples rather than each inventing its own column.
    pending_mfa_code = db.Column(db.String(6), nullable=True)
```

- [ ] **Step 2: Write the failing tests**

Create `tests/test_a07_mfa_leaked_code.py`:

```python
def _login(client, username, password):
    return client.post(
        "/a07/mfa-leaked-code/login", data={"username": username, "password": password}
    )


def test_mfa_leaked_login_page_renders(client):
    response = client.get("/a07/mfa-leaked-code/login")
    assert response.status_code == 200
    assert b"MFA Code Leaked to Client" in response.data


def test_verify_page_does_not_show_code_on_page(client):
    _login(client, "dana", "welcome1")
    response = client.get("/a07/mfa-leaked-code/verify")
    assert response.status_code == 200
    assert b"shown here" not in response.data


def test_send_code_api_leaks_real_code_in_json(client):
    _login(client, "dana", "welcome1")
    response = client.post("/a07/mfa-leaked-code/api/send-code")
    assert response.status_code == 200
    data = response.get_json()
    assert "debug_code" in data
    assert len(data["debug_code"]) == 6
    assert data["debug_code"].isdigit()


def test_leaked_code_from_api_completes_mfa(client):
    _login(client, "dana", "welcome1")
    send_response = client.post("/a07/mfa-leaked-code/api/send-code")
    leaked_code = send_response.get_json()["debug_code"]

    verify_response = client.post(
        "/a07/mfa-leaked-code/verify", data={"code": leaked_code}, follow_redirects=True
    )
    assert verify_response.status_code == 200
    assert b"dana" in verify_response.data
```

Create `tests/test_a07_mfa_reusable_code.py`:

```python
import re


def _login(client, username, password):
    return client.post(
        "/a07/mfa-reusable-code/login", data={"username": username, "password": password}
    )


def test_mfa_reusable_login_page_renders(client):
    response = client.get("/a07/mfa-reusable-code/login")
    assert response.status_code == 200
    assert b"MFA Code Reusability" in response.data


def test_verify_page_shows_demo_code(client):
    _login(client, "morgan", "Summer2023!")
    response = client.get("/a07/mfa-reusable-code/verify")
    assert response.status_code == 200
    assert b"shown here since this lab doesn't send real SMS/email" in response.data


def test_same_code_can_be_submitted_twice(client):
    _login(client, "morgan", "Summer2023!")
    verify_page = client.get("/a07/mfa-reusable-code/verify")
    match = re.search(rb"<strong>(\d{6})</strong>", verify_page.data)
    assert match is not None
    code = match.group(1).decode()

    first = client.post(
        "/a07/mfa-reusable-code/verify", data={"code": code}, follow_redirects=True
    )
    assert first.status_code == 200
    assert b"morgan" in first.data

    # VULNERABLE: the exact same code, submitted again, is still accepted --
    # nothing invalidates it after its first successful use.
    second = client.post(
        "/a07/mfa-reusable-code/verify", data={"code": code}, follow_redirects=True
    )
    assert second.status_code == 200
    assert b"Incorrect code" not in second.data
    assert b"morgan" in second.data
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_a07_mfa_leaked_code.py tests/test_a07_mfa_reusable_code.py -v`
Expected: FAIL — routes don't exist yet (404s).

- [ ] **Step 4: Add the routes**

Modify `app/categories/a07_auth_failures/routes.py`. Current import line:

```python
from flask import make_response, redirect, render_template, request, url_for
```

Replace with (adds `jsonify`):

```python
import secrets

from flask import jsonify, make_response, redirect, render_template, request, url_for
```

Append these routes at the end of the file (after `mfa_dashboard`):

```python


@a07_bp.route("/mfa-leaked-code/login", methods=["GET", "POST"])
def mfa_leaked_login():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        account_row = A07Account.query.filter_by(username=username).first()
        if account_row and check_password_hash(account_row.password_hash, password):
            session_row.username = account_row.username
            session_row.mfa_verified = False
            session_row.pending_mfa_code = f"{secrets.randbelow(1_000_000):06d}"
            db.session.commit()
            return _redirect("a07_auth_failures.mfa_leaked_verify", session_row)
        error = "Invalid username or password."
    return _render("a07_auth_failures/mfa_leaked_login.html", session_row, error=error)


@a07_bp.route("/mfa-leaked-code/api/send-code", methods=["POST"])
def mfa_leaked_send_code_api():
    session_row = get_or_create_session()
    # VULNERABLE: this API exists to trigger sending the code via a real
    # SMS/email provider server-side -- but a leftover debug field echoes
    # the real code straight back in the JSON response. Any client that can
    # call this endpoint (no proof of phone/email ownership required at
    # all, just an in-progress session) gets the code directly, with no
    # need to intercept an SMS or email at all.
    resp = jsonify({"status": "sent", "debug_code": session_row.pending_mfa_code})
    resp.set_cookie(SID_COOKIE, session_row.id)
    return resp


@a07_bp.route("/mfa-leaked-code/verify", methods=["GET", "POST"])
def mfa_leaked_verify():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        code = request.form.get("code", "")
        if code and code == session_row.pending_mfa_code:
            session_row.mfa_verified = True
            session_row.pending_mfa_code = None
            db.session.commit()
            return _redirect("a07_auth_failures.mfa_leaked_dashboard", session_row)
        error = "Incorrect code."
    return _render("a07_auth_failures/mfa_leaked_verify.html", session_row, error=error)


@a07_bp.route("/mfa-leaked-code/dashboard")
def mfa_leaked_dashboard():
    session_row = get_or_create_session()
    if not session_row.username or not session_row.mfa_verified:
        return _redirect("a07_auth_failures.mfa_leaked_login", session_row)
    return _render("a07_auth_failures/mfa_leaked_dashboard.html", session_row)


@a07_bp.route("/mfa-reusable-code/login", methods=["GET", "POST"])
def mfa_reusable_login():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        account_row = A07Account.query.filter_by(username=username).first()
        if account_row and check_password_hash(account_row.password_hash, password):
            session_row.username = account_row.username
            session_row.mfa_verified = False
            session_row.pending_mfa_code = f"{secrets.randbelow(1_000_000):06d}"
            db.session.commit()
            return _redirect("a07_auth_failures.mfa_reusable_verify", session_row)
        error = "Invalid username or password."
    return _render("a07_auth_failures/mfa_reusable_login.html", session_row, error=error)


@a07_bp.route("/mfa-reusable-code/verify", methods=["GET", "POST"])
def mfa_reusable_verify():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        code = request.form.get("code", "")
        # VULNERABLE: checks the code but never invalidates it afterward --
        # pending_mfa_code is left in place even after a successful
        # verification, so the exact same code keeps working for every
        # future verification attempt on this session, indefinitely.
        if code and code == session_row.pending_mfa_code:
            session_row.mfa_verified = True
            db.session.commit()
            return _redirect("a07_auth_failures.mfa_reusable_dashboard", session_row)
        error = "Incorrect code."
    return _render(
        "a07_auth_failures/mfa_reusable_verify.html",
        session_row,
        error=error,
        demo_code=session_row.pending_mfa_code,
    )


@a07_bp.route("/mfa-reusable-code/dashboard")
def mfa_reusable_dashboard():
    session_row = get_or_create_session()
    if not session_row.username or not session_row.mfa_verified:
        return _redirect("a07_auth_failures.mfa_reusable_login", session_row)
    return _render("a07_auth_failures/mfa_reusable_dashboard.html", session_row)
```

- [ ] **Step 5: Create the "MFA Code Leaked to Client" templates**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_leaked_login.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "MFA Code Leaked to Client" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A07{% endblock %}

{% block explanation %}
<p>
  This login has a real second factor, and — unlike this lab's other MFA
  examples — the verification code is <strong>not</strong> shown anywhere
  on the code-entry page itself. That's actually the correct design: a
  real code should only ever reach the user's own phone or inbox. The bug
  is elsewhere: a JSON API meant only to trigger sending the code
  server-side leaves a leftover debug field in its response that echoes
  the real code straight back to whoever called it.
</p>
{% endblock %}

{% block detect %}
<p>
  Log in, then inspect every network request the flow makes — specifically
  a "send code" style API call. Read its <em>full</em> JSON response body,
  not just whether it returned success.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Log in below with <code>dana</code> / <code>welcome1</code>.</li>
  <li>Without entering anything on the verification page, call:
    <pre><code class="language-bash">curl -X POST http://127.0.0.1:5001/a07/mfa-leaked-code/api/send-code \
  -b "a07_session_id=<your session cookie>"</code></pre>
  </li>
  <li>The JSON response is
    <code>{"status": "sent", "debug_code": "482913"}</code> — the real,
    currently-valid code, handed directly to whoever called this API.</li>
  <li>Submit that <code>debug_code</code> value at the verify step —
    MFA completes, with no access to <code>dana</code>'s real phone or
    inbox ever required.</li>
</ol>
{% endblock %}

{% block vulnerable_code %}@app.route("/mfa/api/send-code", methods=["POST"])
def send_code_api():
    session_row = get_or_create_session()
    send_sms(session_row.username, session_row.pending_mfa_code)  # real send
    # VULNERABLE: leftover debug field echoes the real code back
    return jsonify({"status": "sent", "debug_code": session_row.pending_mfa_code})
{% endblock %}

{% block secure_code %}@app.route("/mfa/api/send-code", methods=["POST"])
def send_code_api():
    session_row = get_or_create_session()
    send_sms(session_row.username, session_row.pending_mfa_code)
    return jsonify({"status": "sent"})  # code never enters the response
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Username</label>
    <input class="form-control" type="text" name="username" value="dana">
  </div>
  <div class="mb-2">
    <label class="form-label">Password</label>
    <input class="form-control" type="password" name="password">
  </div>
  <button type="submit" class="btn btn-primary">Log in</button>
</form>
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_leaked_verify.html`:

```html
{% extends "core/base.html" %}
{% block title %}Enter Verification Code — A07{% endblock %}

{% block content %}
<h1>Enter Verification Code</h1>
<p class="text-muted">
  A real code was sent to your registered phone/email for this account.
  (It is intentionally not shown on this page — see whether some other
  part of this flow leaks it anyway.)
</p>
<form method="post">
  <div class="mb-2">
    <label class="form-label">6-digit code</label>
    <input class="form-control" type="text" name="code">
  </div>
  <button type="submit" class="btn btn-primary">Verify</button>
</form>
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_leaked_dashboard.html`:

```html
{% extends "core/base.html" %}
{% block title %}Dashboard — A07{% endblock %}

{% block content %}
<h1>Dashboard</h1>
<p>Welcome, {{ session_row.username }}.</p>
<p>MFA verified on this session: <strong>{{ session_row.mfa_verified }}</strong></p>
{% endblock %}
```

- [ ] **Step 6: Create the "MFA Code Reusability" templates**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_reusable_login.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "MFA Code Reusability" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A07{% endblock %}

{% block explanation %}
<p>
  This login's verification step checks your code correctly against a
  real, per-session generated value. The bug is what happens
  <em>after</em> a successful check: the code is never invalidated, so
  the exact same code keeps working for every future verification
  attempt on this session, indefinitely — a one-time code that was never
  actually made one-time.
</p>
{% endblock %}

{% block detect %}
<p>
  Complete this login's MFA step once, successfully. Then try submitting
  that exact same code again — does the server remember it was already
  used?
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Log in below with <code>morgan</code> / <code>Summer2023!</code>.</li>
  <li>Note the code shown on the verification page and submit it — MFA
      completes normally.</li>
  <li>POST to <code>/a07/mfa-reusable-code/verify</code> again with that
      exact same code:
    <pre><code class="language-bash">curl -X POST http://127.0.0.1:5001/a07/mfa-reusable-code/verify \
  -b "a07_session_id=<your session cookie>" \
  -d "code=<the same code>"</code></pre>
  </li>
  <li>It's accepted again, with no "already used" error at all.</li>
</ol>
<p>
  In a real deployment this means anyone who captures a single valid
  code once — shoulder-surfing, a compromised SMS gateway log, or a
  leaked API response like this category's "MFA Code Leaked to Client"
  example — can keep using it to re-authenticate indefinitely, not just
  for the one login it was meant to protect.
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/mfa/verify", methods=["POST"])
def mfa_verify():
    session_row = get_or_create_session()
    code = request.form["code"]
    if code == session_row.pending_mfa_code:
        # VULNERABLE: never clears pending_mfa_code -- it stays valid forever
        session_row.mfa_verified = True
        db.session.commit()
        return redirect(url_for("dashboard"))
{% endblock %}

{% block secure_code %}@app.route("/mfa/verify", methods=["POST"])
def mfa_verify():
    session_row = get_or_create_session()
    code = request.form["code"]
    if code == session_row.pending_mfa_code:
        session_row.mfa_verified = True
        session_row.pending_mfa_code = None  # single-use: invalidate immediately
        db.session.commit()
        return redirect(url_for("dashboard"))
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Username</label>
    <input class="form-control" type="text" name="username" value="morgan">
  </div>
  <div class="mb-2">
    <label class="form-label">Password</label>
    <input class="form-control" type="password" name="password">
  </div>
  <button type="submit" class="btn btn-primary">Log in</button>
</form>
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_reusable_verify.html`:

```html
{% extends "core/base.html" %}
{% block title %}Enter Verification Code — A07{% endblock %}

{% block content %}
<h1>Enter Verification Code</h1>
<p>
  Your code is <strong>{{ demo_code }}</strong> — shown here since this
  lab doesn't send real SMS/email.
</p>
<form method="post">
  <div class="mb-2">
    <label class="form-label">6-digit code</label>
    <input class="form-control" type="text" name="code">
  </div>
  <button type="submit" class="btn btn-primary">Verify</button>
</form>
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_reusable_dashboard.html`:

```html
{% extends "core/base.html" %}
{% block title %}Dashboard — A07{% endblock %}

{% block content %}
<h1>Dashboard</h1>
<p>Welcome, {{ session_row.username }}.</p>
<p>MFA verified on this session: <strong>{{ session_row.mfa_verified }}</strong></p>
{% endblock %}
```

- [ ] **Step 7: Add both `ExampleNav` entries**

Modify `app/categories/a07_auth_failures/__init__.py`. Find the
`mfa-bypass` entry (the last entry in `examples=[...]`, in the
"Multi-Factor Authentication Bypass" group):

```python
            ExampleNav(
                id="mfa-bypass",
                title="Bypassable Multi-Factor Authentication",
                group="Multi-Factor Authentication Bypass",
                difficulty="Hard",
                endpoint="a07_auth_failures.mfa_login",
                hints=[
                    "This login has two steps: password, then a verification code. Once you've completed just the FIRST step, what does the server actually know about your session?",
                    "After a successful password check, the session is updated with your username but mfa_verified is explicitly set to False — the app clearly intends you to complete step two before being treated as logged in.",
                    "Look at what the dashboard route actually checks before granting access — does it verify mfa_verified, or only that a username is present on the session at all?",
                    "Log in with a valid username/password at /a07/mfa-login (this sets your session's username but not mfa_verified), then skip the code-entry step entirely and navigate directly to /a07/mfa-dashboard — the dashboard only checks that a username is set, never that MFA was actually completed, so you're in.",
                ],
            ),
        ],
        seed_fn=seed_a07_accounts,
    )
)
```

Replace with (inserting the two new entries **before** `mfa-bypass`, since
they're Easy/Medium and `mfa-bypass` is Hard — Easy→Hard order within the
group):

```python
            ExampleNav(
                id="mfa-leaked-code",
                title="MFA Code Leaked to Client",
                group="Multi-Factor Authentication Bypass",
                difficulty="Easy",
                endpoint="a07_auth_failures.mfa_leaked_login",
                hints=[
                    "This login flow doesn't show the verification code anywhere on the page itself — so how would you ever learn it? Look at what other requests get made after you log in (your browser's dev tools network tab, or the app's own JSON API endpoints).",
                    "There's a JSON API at /mfa-leaked-code/api/send-code that a real app's JavaScript would call to trigger sending the code via SMS/email. Check its full response body, not just whether it says success.",
                    "POST to /a07/mfa-leaked-code/api/send-code (just your session cookie from having logged in, no body needed) and look at the JSON response — it includes a debug_code field containing the real, currently-valid verification code in plaintext.",
                    "Exact reproduction: log in at /a07/mfa-leaked-code/login with dana/welcome1, then curl -X POST http://127.0.0.1:5000/a07/mfa-leaked-code/api/send-code with your session cookie attached — copy the debug_code value from the response and submit it at /a07/mfa-leaked-code/verify to complete MFA, with no access to dana's real phone or inbox ever required.",
                ],
            ),
            ExampleNav(
                id="mfa-reusable-code",
                title="MFA Code Reusability",
                group="Multi-Factor Authentication Bypass",
                difficulty="Medium",
                endpoint="a07_auth_failures.mfa_reusable_login",
                hints=[
                    "Complete this login's MFA step once, successfully. Now try submitting that exact same code again — does the server remember it was already used?",
                    "The verify endpoint checks your submitted code against the session's stored pending code, but never clears or invalidates that stored code after a successful check — the same code keeps working indefinitely.",
                    "Log in at /a07/mfa-reusable-code/login with morgan/Summer2023!, note the code shown on the verify page, submit it once to complete MFA, then POST to /a07/mfa-reusable-code/verify again with that exact same code — it's accepted again, with no 'already used' error.",
                    "In a real deployment this means anyone who captures a single valid code once — shoulder-surfing, a compromised SMS gateway log, or a leaked API response like this category's 'MFA Code Leaked to Client' example — can keep using it to re-authenticate indefinitely, not just for the one login it was meant to protect.",
                ],
            ),
            ExampleNav(
                id="mfa-bypass",
                title="Bypassable Multi-Factor Authentication",
                group="Multi-Factor Authentication Bypass",
                difficulty="Hard",
                endpoint="a07_auth_failures.mfa_login",
                hints=[
                    "This login has two steps: password, then a verification code. Once you've completed just the FIRST step, what does the server actually know about your session?",
                    "After a successful password check, the session is updated with your username but mfa_verified is explicitly set to False — the app clearly intends you to complete step two before being treated as logged in.",
                    "Look at what the dashboard route actually checks before granting access — does it verify mfa_verified, or only that a username is present on the session at all?",
                    "Log in with a valid username/password at /a07/mfa-login (this sets your session's username but not mfa_verified), then skip the code-entry step entirely and navigate directly to /a07/mfa-dashboard — the dashboard only checks that a username is set, never that MFA was actually completed, so you're in.",
                ],
            ),
        ],
        seed_fn=seed_a07_accounts,
    )
)
```

- [ ] **Step 8: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a07_mfa_leaked_code.py tests/test_a07_mfa_reusable_code.py -v`
Expected: PASS (7 passed)

- [ ] **Step 9: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass (exact running total to be reconciled in Task 9, since
other A07 tasks add examples in parallel).

- [ ] **Step 10: Commit**

```bash
git add app/categories/a07_auth_failures tests/test_a07_mfa_leaked_code.py tests/test_a07_mfa_reusable_code.py
git commit -m "feat(a07): add MFA code-leaked-via-API and code-reusability examples

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 7: A07 Additions — MFA Brute-Force + MFA Code Not Bound to Session

**Files:**
- Modify: `app/categories/a07_auth_failures/routes.py`
- Modify: `app/categories/a07_auth_failures/__init__.py`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_login_bruteforce.html`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_verify_bruteforce.html`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_login_unbound.html`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_verify_unbound.html`
- Test: `tests/test_a07_mfa_brute_force.py`
- Test: `tests/test_a07_mfa_not_bound_to_session.py`

**Interfaces:**
- Consumes: `AuthSession.pending_mfa_code` (nullable `String(6)` column, added
  by Task 6 — if executed out of order, verify the column exists in
  `app/categories/a07_auth_failures/models.py` before writing routes here;
  add it if missing, exactly as Task 6 defines it).
- Produces: a new module-level `PENDING_MFA_CODES_BY_USERNAME: dict[str, str]`
  in `routes.py`, keyed by username (NOT by session id or any per-browser
  identifier) — this is what makes the "MFA Code Not Bound to Session"
  example genuinely exploitable: the pending code for a username is
  visible to whichever session asks for it, regardless of which session
  generated it. Routes: `a07_auth_failures.mfa_login_bruteforce`
  (`GET/POST /a07/mfa-login-bruteforce`), `a07_auth_failures.mfa_verify_bruteforce`
  (`GET/POST /a07/mfa-verify-bruteforce`), `a07_auth_failures.mfa_login_unbound`
  (`GET/POST /a07/mfa-login-unbound`), `a07_auth_failures.mfa_verify_unbound`
  (`GET/POST /a07/mfa-verify-unbound`). Nothing later depends on these.

**Known caveat:** `PENDING_MFA_CODES_BY_USERNAME` is a plain process-wide
module global, not per-test-app state — it persists across tests in the
same pytest process since `routes.py` is imported once. This is the
correct design for the vulnerability (the code must be visible across
sessions/apps that don't share cookies), but the module dict is never
reset between tests. Both new tests always overwrite
`PENDING_MFA_CODES_BY_USERNAME["dana"]` at the start of their own login
step before asserting anything, so this is safe in practice.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a07_mfa_brute_force.py`:

```python
from app.categories.a07_auth_failures.models import AuthSession


def test_login_page_renders(client):
    response = client.get("/a07/mfa-login-bruteforce")
    assert response.status_code == 200
    assert b"MFA Brute-Force" in response.data


def test_verify_page_does_not_display_the_code(client):
    client.post(
        "/a07/mfa-login-bruteforce", data={"username": "dana", "password": "welcome1"}
    )
    response = client.get("/a07/mfa-verify-bruteforce")
    assert response.status_code == 200
    assert b"Your code is" not in response.data


def test_no_lockout_after_many_wrong_attempts_then_correct_code_still_works(app, client):
    client.post(
        "/a07/mfa-login-bruteforce", data={"username": "dana", "password": "welcome1"}
    )

    for _ in range(20):
        response = client.post("/a07/mfa-verify-bruteforce", data={"code": "000000"})
        assert response.status_code == 200
        assert b"Incorrect code" in response.data

    with app.app_context():
        session_row = (
            AuthSession.query.filter_by(username="dana")
            .order_by(AuthSession.created_at.desc())
            .first()
        )
        real_code = session_row.pending_mfa_code

    response = client.post(
        "/a07/mfa-verify-bruteforce", data={"code": real_code}, follow_redirects=True
    )
    assert response.status_code == 200
    assert b"Welcome, dana" in response.data
```

Create `tests/test_a07_mfa_not_bound_to_session.py`:

```python
from app.categories.a07_auth_failures.routes import PENDING_MFA_CODES_BY_USERNAME


def test_login_page_renders(client):
    response = client.get("/a07/mfa-login-unbound")
    assert response.status_code == 200
    assert b"MFA Code Not Bound to Session" in response.data


def test_code_generated_for_one_session_works_through_a_totally_different_session(app):
    victim_client = app.test_client()
    attacker_client = app.test_client()

    victim_client.post(
        "/a07/mfa-login-unbound", data={"username": "dana", "password": "welcome1"}
    )

    with app.app_context():
        real_code = PENDING_MFA_CODES_BY_USERNAME["dana"]

    # attacker_client shares no cookies with victim_client and never
    # entered dana's password anywhere -- it's a completely separate,
    # unrelated session.
    response = attacker_client.post(
        "/a07/mfa-verify-unbound",
        data={"username": "dana", "code": real_code},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Welcome, dana" in response.data


def test_wrong_code_for_the_right_username_still_fails(app):
    client = app.test_client()
    client.post(
        "/a07/mfa-login-unbound", data={"username": "dana", "password": "welcome1"}
    )
    response = client.post(
        "/a07/mfa-verify-unbound", data={"username": "dana", "code": "000000"}
    )
    assert response.status_code == 200
    assert b"Incorrect code" in response.data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_a07_mfa_brute_force.py tests/test_a07_mfa_not_bound_to_session.py -v`
Expected: FAIL — routes don't exist yet (404s), and `PENDING_MFA_CODES_BY_USERNAME` doesn't exist yet.

- [ ] **Step 3: Verify (or add) the `pending_mfa_code` column**

Check `app/categories/a07_auth_failures/models.py`. Task 6 adds this
column to `AuthSession`; if for any reason it isn't present yet, add it:

```python
class AuthSession(db.Model):
    __tablename__ = "a07_auth_sessions"

    id = db.Column(db.String(32), primary_key=True)
    username = db.Column(db.String(80), nullable=True)
    mfa_verified = db.Column(db.Boolean, nullable=False, default=False)
    pending_mfa_code = db.Column(db.String(6), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
```

- [ ] **Step 4: Add the four new routes and the module-level store**

Modify `app/categories/a07_auth_failures/routes.py`. Current top-of-file
imports (post-Task-6):

```python
import secrets

from flask import jsonify, make_response, redirect, render_template, request, url_for
from werkzeug.security import check_password_hash

from app.categories.a07_auth_failures import a07_bp
from app.categories.a07_auth_failures.models import A07Account
from app.categories.a07_auth_failures.session_store import SID_COOKIE, get_or_create_session
from app.extensions import db
```

`secrets` is already imported by Task 6 — no import changes needed here.

Add the module-level store right after the `MFA_DEMO_CODE = "482913"` line:

```python
MFA_DEMO_CODE = "482913"

# Keyed by username, NOT by session id or any per-browser identifier --
# this is what makes the "MFA Code Not Bound to Session" example below
# genuinely exploitable: the pending code for a username is visible to
# whichever session asks for it, regardless of which session generated it.
PENDING_MFA_CODES_BY_USERNAME = {}
```

Append these four routes at the end of the file (after Task 6's
`mfa_reusable_dashboard`, or after `mfa_dashboard` if Task 6 hasn't
landed):

```python


@a07_bp.route("/mfa-login-bruteforce", methods=["GET", "POST"])
def mfa_login_bruteforce():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        account_row = A07Account.query.filter_by(username=username).first()
        if account_row and check_password_hash(account_row.password_hash, password):
            session_row.username = account_row.username
            session_row.mfa_verified = False
            # A fresh 6-digit code per login, exactly like a real
            # deployment -- the flaw isn't in code generation, it's that
            # nothing throttles how many guesses the verify step accepts.
            session_row.pending_mfa_code = f"{secrets.randbelow(1000000):06d}"
            db.session.commit()
            return _redirect("a07_auth_failures.mfa_verify_bruteforce", session_row)
        error = "Invalid username or password."
    return _render("a07_auth_failures/mfa_login_bruteforce.html", session_row, error=error)


@a07_bp.route("/mfa-verify-bruteforce", methods=["GET", "POST"])
def mfa_verify_bruteforce():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        code = request.form.get("code", "")
        # VULNERABLE: no attempt counter, no lockout, no delay, no
        # CAPTCHA -- this endpoint accepts unlimited guesses against a
        # 6-digit numeric code (1-in-1,000,000 odds per guess, trivially
        # brute-forceable with zero throttling in front of it).
        if code and code == session_row.pending_mfa_code:
            session_row.mfa_verified = True
            db.session.commit()
            return _redirect("a07_auth_failures.mfa_dashboard", session_row)
        error = "Incorrect code."
    return _render("a07_auth_failures/mfa_verify_bruteforce.html", session_row, error=error)


@a07_bp.route("/mfa-login-unbound", methods=["GET", "POST"])
def mfa_login_unbound():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        account_row = A07Account.query.filter_by(username=username).first()
        if account_row and check_password_hash(account_row.password_hash, password):
            session_row.username = account_row.username
            session_row.mfa_verified = False
            db.session.commit()
            # VULNERABLE: the pending code is stored in a plain global
            # keyed only by username -- not scoped to this session_row or
            # this browser's cookie in any way. Any other session that
            # later learns this username+code pair can use it too.
            PENDING_MFA_CODES_BY_USERNAME[username] = f"{secrets.randbelow(1000000):06d}"
            return _redirect("a07_auth_failures.mfa_verify_unbound", session_row)
        error = "Invalid username or password."
    return _render("a07_auth_failures/mfa_login_unbound.html", session_row, error=error)


@a07_bp.route("/mfa-verify-unbound", methods=["GET", "POST"])
def mfa_verify_unbound():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        # VULNERABLE: trusts a client-supplied username field instead of
        # using session_row.username (the identity THIS session actually
        # proved ownership of via the password step earlier), and looks
        # the pending code up in a store keyed by that submitted
        # username -- not scoped to this session at all.
        submitted_username = request.form.get("username", "")
        code = request.form.get("code", "")
        if code and PENDING_MFA_CODES_BY_USERNAME.get(submitted_username) == code:
            session_row.username = submitted_username
            session_row.mfa_verified = True
            db.session.commit()
            return _redirect("a07_auth_failures.mfa_dashboard", session_row)
        error = "Incorrect code."
    demo_code = PENDING_MFA_CODES_BY_USERNAME.get(session_row.username)
    return _render(
        "a07_auth_failures/mfa_verify_unbound.html",
        session_row,
        error=error,
        demo_code=demo_code,
        prefill_username=session_row.username or "",
    )
```

- [ ] **Step 5: Create `mfa_login_bruteforce.html`**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_login_bruteforce.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "MFA Brute-Force (No Rate Limiting)" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A07{% endblock %}

{% block explanation %}
<p>
  This login has a real second factor: after your password, you're sent
  to a 6-digit code-entry page. Unlike this category's other MFA
  examples, the code generation and check are both correct — the flaw is
  that the verify endpoint places no limit at all on how many codes you
  can try. There's no lockout, no delay, no CAPTCHA, and no attempt
  counter anywhere in front of it.
</p>
{% endblock %}

{% block detect %}
<p>
  Log in, then submit a handful of deliberately wrong codes in a row to
  the verify page. If every attempt behaves identically — no warning, no
  slowdown, no lockout message — the endpoint has no rate limiting.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Log in with a correct username/password below (<code>dana</code> /
      <code>welcome1</code>).</li>
  <li>On the verify page, submit any wrong 6-digit code — notice you're
      simply told "Incorrect code" and can try again immediately.</li>
  <li>Nothing stops you from repeating this indefinitely. A 6-digit
      numeric code has only 1,000,000 possible values — with zero
      throttling, a real attacker scripting a few hundred requests per
      second against <code>/a07/mfa-verify-bruteforce</code> would find
      the correct code in well under a minute.</li>
</ol>
<p>
  This is the same missing-rate-limiting flaw as this category's
  brute-force-login example, applied to the second factor instead of the
  password — a real second factor is only as strong as the protections
  guarding the endpoint that checks it.
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/mfa-verify-bruteforce", methods=["POST"])
def mfa_verify_bruteforce():
    code = request.form["code"]
    # VULNERABLE: no attempt counter, no lockout, no delay, no CAPTCHA
    if code == session_row.pending_mfa_code:
        session_row.mfa_verified = True
        db.session.commit()
        return redirect(url_for("mfa_dashboard"))
    return render_template("mfa_verify_bruteforce.html", error="Incorrect code.")
{% endblock %}

{% block secure_code %}@app.route("/mfa-verify-bruteforce", methods=["POST"])
def mfa_verify_bruteforce():
    code = request.form["code"]
    attempts = increment_failed_attempts(session_row)  # tracked server-side
    if attempts > 5:
        lock_out_session(session_row, minutes=15)
        abort(429)
    if code == session_row.pending_mfa_code:
        session_row.mfa_verified = True
        db.session.commit()
        return redirect(url_for("mfa_dashboard"))
    return render_template("mfa_verify_bruteforce.html", error="Incorrect code.")
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Username</label>
    <input class="form-control" type="text" name="username" value="dana">
  </div>
  <div class="mb-2">
    <label class="form-label">Password</label>
    <input class="form-control" type="password" name="password">
  </div>
  <button type="submit" class="btn btn-primary">Log in</button>
</form>
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Create `mfa_verify_bruteforce.html`**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_verify_bruteforce.html`:

```html
{% extends "core/base.html" %}
{% block title %}Enter Verification Code — A07{% endblock %}

{% block content %}
<h1>Enter Verification Code</h1>
<p>
  Enter the 6-digit code sent to your device. (Unlike some other examples
  in this lab, the code is intentionally NOT shown here — this example is
  about proving the verify endpoint has no rate limiting, so guessing
  should behave like a real attacker who doesn't already know the code.)
</p>
<form method="post">
  <div class="mb-2">
    <label class="form-label">6-digit code</label>
    <input class="form-control" type="text" name="code">
  </div>
  <button type="submit" class="btn btn-primary">Verify</button>
</form>
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 7: Create `mfa_login_unbound.html`**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_login_unbound.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "MFA Code Not Bound to Session" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A07{% endblock %}

{% block explanation %}
<p>
  This login also has a password step followed by a code-entry step. The
  bug is subtle: the pending verification code is stored keyed only by
  <em>username</em>, not by the specific session/browser that requested
  it. The verify page even asks you to re-enter your username alongside
  the code — a small but telling sign that it isn't relying on your
  session's own identity at all.
</p>
{% endblock %}

{% block detect %}
<p>
  Compare this verify page to a normal one: does it ask for a username
  field at all, given you're already in an authenticated-ish session at
  this point? If the server needs you to tell it who you are again on
  the verify step, it may not actually be checking that the code belongs
  to <em>your</em> session.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>In one browser (or this tab), log in as <code>dana</code> /
      <code>welcome1</code> below — a real code is generated and shown
      on the following page, keyed to the username <code>dana</code>.</li>
  <li>In a <strong>completely separate</strong> browser session (a
      different browser, an incognito window, or any session that never
      entered dana's password anywhere), visit
      <a href="{{ url_for('a07_auth_failures.mfa_verify_unbound') }}">the
      verify page</a> and submit username <code>dana</code> together with
      that same code.</li>
</ol>
<p>
  The second, completely unrelated session is authenticated as dana
  anyway. The code was only ever bound to a username string — never to
  the specific session that actually proved it knew dana's password in
  the first place.
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/mfa-verify-unbound", methods=["POST"])
def mfa_verify_unbound():
    # VULNERABLE: trusts a client-supplied username instead of the
    # caller's own session identity
    submitted_username = request.form["username"]
    code = request.form["code"]
    if PENDING_MFA_CODES_BY_USERNAME.get(submitted_username) == code:
        session_row.username = submitted_username
        session_row.mfa_verified = True
        db.session.commit()
        return redirect(url_for("mfa_dashboard"))
{% endblock %}

{% block secure_code %}@app.route("/mfa-verify-unbound", methods=["POST"])
def mfa_verify_unbound():
    code = request.form["code"]
    # Only ever checked against THIS session's own pending code -- no
    # client-supplied username involved at all
    if session_row.pending_mfa_code and code == session_row.pending_mfa_code:
        session_row.mfa_verified = True
        db.session.commit()
        return redirect(url_for("mfa_dashboard"))
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Username</label>
    <input class="form-control" type="text" name="username" value="dana">
  </div>
  <div class="mb-2">
    <label class="form-label">Password</label>
    <input class="form-control" type="password" name="password">
  </div>
  <button type="submit" class="btn btn-primary">Log in</button>
</form>
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 8: Create `mfa_verify_unbound.html`**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_verify_unbound.html`:

```html
{% extends "core/base.html" %}
{% block title %}Enter Verification Code — A07{% endblock %}

{% block content %}
<h1>Enter Verification Code</h1>
{% if demo_code %}
<p>
  Your code is <strong>{{ demo_code }}</strong> — shown here since this
  lab doesn't send real SMS/email.
</p>
{% endif %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Username</label>
    <input class="form-control" type="text" name="username" value="{{ prefill_username }}">
  </div>
  <div class="mb-2">
    <label class="form-label">6-digit code</label>
    <input class="form-control" type="text" name="code">
  </div>
  <button type="submit" class="btn btn-primary">Verify</button>
</form>
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 9: Add both `ExampleNav` entries**

Insert into the existing `"Multi-Factor Authentication Bypass"` group in
`app/categories/a07_auth_failures/__init__.py`, respecting Easy→Hard
sortedness: `mfa-brute-force` is Medium and must sort strictly before the
existing `mfa-bypass` (Hard); `mfa-not-bound-to-session` is also Hard and
its order relative to `mfa-bypass` doesn't matter (tied difficulty). If
Task 6's Easy/Medium entries (`mfa-leaked-code`, `mfa-reusable-code`) have
already landed in this group, `mfa-brute-force` (Medium) sorts alongside
`mfa-reusable-code` (also Medium) — their relative order doesn't matter
either.

Insert `mfa-brute-force` immediately before the `mfa-bypass` entry, and
`mfa-not-bound-to-session` immediately after it:

```python
            ExampleNav(
                id="mfa-brute-force",
                title="MFA Brute-Force (No Rate Limiting)",
                group="Multi-Factor Authentication Bypass",
                difficulty="Medium",
                endpoint="a07_auth_failures.mfa_login_bruteforce",
                hints=[
                    "This login also has a code-entry step — but this time, the page never tells you the code. Try guessing it: submit any 6-digit number and see what happens on a wrong guess.",
                    "There's no lockout, no delay, no CAPTCHA, and no attempt counter anywhere on this verify endpoint — every wrong guess returns instantly, ready for another try, exactly like this category's brute-force-login example but for the second factor instead of the password.",
                    "A 6-digit numeric code has only 1,000,000 possible values. With zero rate limiting, scripting a few hundred or thousand requests per second against /a07/mfa-verify-bruteforce (after logging in at /a07/mfa-login-bruteforce as dana/welcome1) would find the real code in well under a minute in a real deployment.",
                    "Reproduction without a full brute-force script: log in at /a07/mfa-login-bruteforce, then POST as many wrong codes as you like to /a07/mfa-verify-bruteforce — notice every attempt behaves identically, with nothing ever blocking, slowing, or flagging repeated failures.",
                ],
            ),
            ExampleNav(
                id="mfa-bypass",
                title="Bypassable Multi-Factor Authentication",
                group="Multi-Factor Authentication Bypass",
                difficulty="Hard",
                endpoint="a07_auth_failures.mfa_login",
                hints=[
                    "This login has two steps: password, then a verification code. Once you've completed just the FIRST step, what does the server actually know about your session?",
                    "After a successful password check, the session is updated with your username but mfa_verified is explicitly set to False — the app clearly intends you to complete step two before being treated as logged in.",
                    "Look at what the dashboard route actually checks before granting access — does it verify mfa_verified, or only that a username is present on the session at all?",
                    "Log in with a valid username/password at /a07/mfa-login (this sets your session's username but not mfa_verified), then skip the code-entry step entirely and navigate directly to /a07/mfa-dashboard — the dashboard only checks that a username is set, never that MFA was actually completed, so you're in.",
                ],
            ),
            ExampleNav(
                id="mfa-not-bound-to-session",
                title="MFA Code Not Bound to Session",
                group="Multi-Factor Authentication Bypass",
                difficulty="Hard",
                endpoint="a07_auth_failures.mfa_login_unbound",
                hints=[
                    "This verify page asks for both a username and a code. Why would a verify step need you to tell it your username again — doesn't it already know who you are from your session?",
                    "The verify endpoint looks up the pending code by the USERNAME FIELD YOU SUBMIT in the form, not by anything tied to your own session — the code was never actually bound to the session that requested it in the first place.",
                    "Log in as dana at /a07/mfa-login-unbound in one browser/session to generate a real pending code for dana. In a COMPLETELY SEPARATE session (a different browser, an incognito window, or simply clearing your cookies) that never entered dana's password anywhere, submit dana's username together with that same code to /a07/mfa-verify-unbound.",
                    "The second, unrelated session is authenticated as dana anyway — proving the code was only ever bound to a username string, never to the specific session/browser that actually proved it knew dana's password.",
                ],
            ),
```

- [ ] **Step 10: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a07_mfa_brute_force.py tests/test_a07_mfa_not_bound_to_session.py -v`
Expected: PASS (6 passed)

- [ ] **Step 11: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass.

- [ ] **Step 12: Commit**

```bash
git add app/categories/a07_auth_failures tests/test_a07_mfa_brute_force.py tests/test_a07_mfa_not_bound_to_session.py
git commit -m "feat(a07): add MFA brute-force and code-not-bound-to-session examples

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 8: A07 Additions — MFA Bypass via Magic/Null Value + CSRF on Disabling 2FA

**Files:**
- Modify: `app/categories/a07_auth_failures/routes.py`
- Modify: `app/categories/a07_auth_failures/__init__.py`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_login_magic_value.html`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_verify_magic_value.html`
- Create: `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_settings.html`
- Test: `tests/test_a07_mfa_magic_value.py`
- Test: `tests/test_a07_csrf_disable_2fa.py`

**Interfaces:**
- Consumes: `AuthSession.pending_mfa_code` (nullable `String(6)` column,
  added by Task 6 — if executed out of order, verify the column exists in
  `app/categories/a07_auth_failures/models.py` before writing routes
  here; add it exactly as Task 6 defines it if missing).
  Also consumes the EXISTING, unmodified `mfa_login`/`mfa_verify`/
  `MFA_DEMO_CODE` flow (this app's original `mfa-bypass` example) for
  the CSRF example — no new login/verify pair is needed for that one,
  it acts on a session that has already genuinely completed the real
  MFA flow.
- Produces: routes `a07_auth_failures.mfa_login_magic_value` (`GET/POST
  /a07/mfa-login-magic-value`), `a07_auth_failures.mfa_verify_magic_value`
  (`GET/POST /a07/mfa-verify-magic-value`), `a07_auth_failures.mfa_settings`
  (`GET /a07/mfa-settings`), `a07_auth_failures.mfa_disable` (`POST
  /a07/mfa/disable`). Nothing later depends on these — this is the last
  A07 task.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a07_mfa_magic_value.py`:

```python
def test_login_page_renders(client):
    response = client.get("/a07/mfa-login-magic-value")
    assert response.status_code == 200
    assert b"MFA Bypass via Magic" in response.data


def test_verify_page_does_not_display_the_code(client):
    client.post(
        "/a07/mfa-login-magic-value", data={"username": "dana", "password": "welcome1"}
    )
    response = client.get("/a07/mfa-verify-magic-value")
    assert response.status_code == 200
    assert b"Your code is" not in response.data


def test_magic_value_000000_bypasses_without_knowing_real_code(client):
    client.post(
        "/a07/mfa-login-magic-value", data={"username": "dana", "password": "welcome1"}
    )
    response = client.post(
        "/a07/mfa-verify-magic-value", data={"code": "000000"}, follow_redirects=True
    )
    assert response.status_code == 200
    assert b"Welcome, dana" in response.data


def test_magic_value_null_string_also_bypasses(client):
    client.post(
        "/a07/mfa-login-magic-value", data={"username": "dana", "password": "welcome1"}
    )
    response = client.post(
        "/a07/mfa-verify-magic-value", data={"code": "null"}, follow_redirects=True
    )
    assert response.status_code == 200
    assert b"Welcome, dana" in response.data


def test_wrong_non_magic_code_still_fails(client):
    client.post(
        "/a07/mfa-login-magic-value", data={"username": "dana", "password": "welcome1"}
    )
    response = client.post("/a07/mfa-verify-magic-value", data={"code": "123123"})
    assert response.status_code == 200
    assert b"Incorrect code" in response.data
```

Create `tests/test_a07_csrf_disable_2fa.py`:

```python
def _complete_real_mfa_login(client):
    client.post("/a07/mfa-login", data={"username": "dana", "password": "welcome1"})
    client.post("/a07/mfa-verify", data={"code": "482913"})


def test_mfa_settings_page_renders(client):
    response = client.get("/a07/mfa-settings")
    assert response.status_code == 200
    assert b"CSRF on Disabling 2FA" in response.data


def test_settings_shows_enabled_after_real_mfa_flow(client):
    _complete_real_mfa_login(client)
    response = client.get("/a07/mfa-settings")
    assert b"currently enabled" in response.data.lower()


def test_disable_form_has_no_csrf_token(client):
    _complete_real_mfa_login(client)
    response = client.get("/a07/mfa-settings")
    assert b"csrf_token" not in response.data
    assert b'name="csrf"' not in response.data


def test_forged_post_disables_2fa_with_no_token_or_reauth(client):
    _complete_real_mfa_login(client)

    # Simulates a forged cross-site POST: no CSRF token field at all, no
    # password/code re-confirmation -- just the victim's existing session
    # cookie, which a browser attaches automatically to same-origin AND
    # cross-origin form submissions alike.
    response = client.post("/a07/mfa/disable", follow_redirects=True)
    assert response.status_code == 200

    settings_after = client.get("/a07/mfa-settings")
    assert b"currently enabled" not in settings_after.data.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_a07_mfa_magic_value.py tests/test_a07_csrf_disable_2fa.py -v`
Expected: FAIL — routes don't exist yet (404s).

- [ ] **Step 3: Verify (or add) the `pending_mfa_code` column**

Check `app/categories/a07_auth_failures/models.py`. Task 6 adds this
column to `AuthSession`; if for any reason it isn't present yet, add it
exactly as shown in Task 6/7.

- [ ] **Step 4: Add the four new routes**

Modify `app/categories/a07_auth_failures/routes.py`. `secrets` and
`jsonify` are already imported by Task 6 — no import changes needed.

Append these four routes at the end of the file (after Task 7's
`mfa_verify_unbound`, or after the last A07 route present if Tasks 6-7
haven't landed):

```python


MFA_MAGIC_VALUES = {"000000", "null"}


@a07_bp.route("/mfa-login-magic-value", methods=["GET", "POST"])
def mfa_login_magic_value():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        account_row = A07Account.query.filter_by(username=username).first()
        if account_row and check_password_hash(account_row.password_hash, password):
            session_row.username = account_row.username
            session_row.mfa_verified = False
            session_row.pending_mfa_code = f"{secrets.randbelow(1000000):06d}"
            db.session.commit()
            return _redirect("a07_auth_failures.mfa_verify_magic_value", session_row)
        error = "Invalid username or password."
    return _render("a07_auth_failures/mfa_login_magic_value.html", session_row, error=error)


@a07_bp.route("/mfa-verify-magic-value", methods=["GET", "POST"])
def mfa_verify_magic_value():
    session_row = get_or_create_session()
    error = None
    if request.method == "POST":
        code = request.form.get("code", "")
        # VULNERABLE: a leftover developer/testing backdoor -- either the
        # real per-login code OR one of a small set of hardcoded magic
        # values is accepted, regardless of what the real code actually
        # is.
        if code and (code == session_row.pending_mfa_code or code in MFA_MAGIC_VALUES):
            session_row.mfa_verified = True
            db.session.commit()
            return _redirect("a07_auth_failures.mfa_dashboard", session_row)
        error = "Incorrect code."
    return _render("a07_auth_failures/mfa_verify_magic_value.html", session_row, error=error)


@a07_bp.route("/mfa-settings")
def mfa_settings():
    session_row = get_or_create_session()
    return _render("a07_auth_failures/mfa_settings.html", session_row)


@a07_bp.route("/mfa/disable", methods=["POST"])
def mfa_disable():
    session_row = get_or_create_session()
    # VULNERABLE: no CSRF token, no re-authentication or password/code
    # confirmation -- any POST carrying the victim's existing session
    # cookie succeeds, including one triggered by an auto-submitting form
    # hosted on a completely different, attacker-controlled site.
    session_row.mfa_verified = False
    db.session.commit()
    return _redirect("a07_auth_failures.mfa_settings", session_row)
```

- [ ] **Step 5: Create the magic-value templates**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_login_magic_value.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "MFA Bypass via Magic/Null Value" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A07{% endblock %}

{% block explanation %}
<p>
  This login has a real second factor with a real, per-login generated
  code — hidden from you, same as this category's brute-force example.
  The flaw is a leftover developer/testing shortcut: the verify endpoint
  accepts a small set of hardcoded "magic" values as ALWAYS valid,
  regardless of what the real code actually is. Backdoors like this are
  meant to be removed before shipping and, in this lab, weren't.
</p>
{% endblock %}

{% block detect %}
<p>
  Before trying to guess or intercept the real code, try a handful of
  suspiciously common "test" values first — <code>000000</code>,
  <code>111111</code>, the literal string <code>null</code> — many
  internal test/QA bypasses use exactly these.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Log in with a valid account below (<code>dana</code> / <code>welcome1</code>).</li>
  <li>On the code-entry page — without ever learning the real code —
      submit <code>000000</code>.</li>
</ol>
<p>
  It's accepted. The verify endpoint checks the submitted code against
  the real per-login code OR a small hardcoded set of magic values —
  <code>000000</code> and the literal string <code>null</code> both
  work — completely independent of what the real code is.
</p>
{% endblock %}

{% block vulnerable_code %}MFA_MAGIC_VALUES = {"000000", "null"}  # leftover dev/QA backdoor

@app.route("/mfa-verify-magic-value", methods=["POST"])
def mfa_verify_magic_value():
    code = request.form["code"]
    # VULNERABLE: accepts the backdoor values regardless of the real code
    if code == session_row.pending_mfa_code or code in MFA_MAGIC_VALUES:
        session_row.mfa_verified = True
        db.session.commit()
        return redirect(url_for("mfa_dashboard"))
{% endblock %}

{% block secure_code %}@app.route("/mfa-verify-magic-value", methods=["POST"])
def mfa_verify_magic_value():
    code = request.form["code"]
    # No backdoor values -- only the real, per-login code is ever valid
    if code == session_row.pending_mfa_code:
        session_row.mfa_verified = True
        db.session.commit()
        return redirect(url_for("mfa_dashboard"))
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Username</label>
    <input class="form-control" type="text" name="username" value="dana">
  </div>
  <div class="mb-2">
    <label class="form-label">Password</label>
    <input class="form-control" type="password" name="password">
  </div>
  <button type="submit" class="btn btn-primary">Log in</button>
</form>
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_verify_magic_value.html`:

```html
{% extends "core/base.html" %}
{% block title %}Enter Verification Code — A07{% endblock %}

{% block content %}
<h1>Enter Verification Code</h1>
<p>
  Enter the 6-digit code sent to your device. (The code is intentionally
  not shown on this page.)
</p>
<form method="post">
  <div class="mb-2">
    <label class="form-label">6-digit code</label>
    <input class="form-control" type="text" name="code">
  </div>
  <button type="submit" class="btn btn-primary">Verify</button>
</form>
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Create `mfa_settings.html`**

Create `app/categories/a07_auth_failures/templates/a07_auth_failures/mfa_settings.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "CSRF on Disabling 2FA" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A07{% endblock %}

{% block explanation %}
<p>
  This settings page shows whether two-factor authentication is currently
  enabled for your session and offers a "Disable 2FA" button once it is.
  The form that button submits has no CSRF token, and the endpoint it
  posts to requires no re-authentication (no password, no verification
  code) before acting — the only thing that "protects" it is a valid
  session cookie, which a forged cross-site request carries automatically
  too.
</p>
{% endblock %}

{% block detect %}
<p>
  Complete this app's real MFA login flow first, then view this settings
  page's HTML source and look for a hidden <code>csrf_token</code> field
  on the disable form — there isn't one.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Complete the real MFA flow at
      <a href="{{ url_for('a07_auth_failures.mfa_login') }}">/a07/mfa-login</a>
      with <code>dana</code> / <code>welcome1</code>, then enter the code
      shown on the following page.</li>
  <li>Return to this page — it now shows "2FA is currently enabled."</li>
  <li>Instead of clicking the real button, imagine this HTML hosted on a
      completely different, attacker-controlled site:</li>
</ol>
<pre><code class="language-html">&lt;form action="http://127.0.0.1:5001/a07/mfa/disable" method="POST" id="f"&gt;&lt;/form&gt;
&lt;script&gt;document.getElementById('f').submit();&lt;/script&gt;</code></pre>
<p>
  A logged-in, MFA-verified victim who merely visits that attacker page
  has their session cookie sent along automatically — the request looks
  completely legitimate to the server, and their account's 2FA is
  silently disabled with zero confirmation, exactly matching this
  category's own PayloadsAllTheThings source material: "No CSRF
  Protection on disabling 2FA, also there is no auth confirmation."
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/mfa/disable", methods=["POST"])
def mfa_disable():
    session_row = get_or_create_session()
    # VULNERABLE: no CSRF token, no password/code re-confirmation
    session_row.mfa_verified = False
    db.session.commit()
{% endblock %}

{% block secure_code %}@app.route("/mfa/disable", methods=["POST"])
def mfa_disable():
    session_row = get_or_create_session()
    validate_csrf_token(request.form.get("csrf_token"))  # rejects if missing/wrong
    if not verify_mfa_code(session_row, request.form.get("confirm_code", "")):
        abort(403)
    session_row.mfa_verified = False
    db.session.commit()
{% endblock %}

{% block live_example %}
{% if session_row.username and session_row.mfa_verified %}
<p>2FA is currently <strong>enabled</strong> for this session ({{ session_row.username }}).</p>
<form method="post" action="{{ url_for('a07_auth_failures.mfa_disable') }}">
  <button type="submit" class="btn btn-danger">Disable 2FA</button>
</form>
{% elif session_row.username %}
<p>2FA is currently <strong>disabled</strong> for this session ({{ session_row.username }}).</p>
{% else %}
<p>
  You need to complete the real MFA login flow first — log in at
  <a href="{{ url_for('a07_auth_failures.mfa_login') }}">/a07/mfa-login</a>
  with <code>dana</code> / <code>welcome1</code>.
</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 7: Add both `ExampleNav` entries**

Modify `app/categories/a07_auth_failures/__init__.py`.

First, insert `mfa-bypass-magic-value` as the new first entry in the
`"Multi-Factor Authentication Bypass"` group (Easy — sorts alongside
Task 6's `mfa-leaked-code`, also Easy; relative order between the two
doesn't matter). Find `mfa-leaked-code` (added by Task 6; if Task 6
hasn't landed yet, insert this immediately before whatever the group's
first entry currently is):

```python
            ExampleNav(
                id="mfa-leaked-code",
```

Insert immediately before it:

```python
            ExampleNav(
                id="mfa-bypass-magic-value",
                title="MFA Bypass via Magic/Null Value",
                group="Multi-Factor Authentication Bypass",
                difficulty="Easy",
                endpoint="a07_auth_failures.mfa_login_magic_value",
                hints=[
                    "This login's code-entry page hides the real code from you, same as this category's brute-force example. Before trying to intercept or guess the real code, consider: leftover developer/testing shortcuts sometimes get left in by accident. What suspiciously simple values might one of those look like?",
                    "Try a handful of common 'test bypass' values without ever learning the real code — 000000 is a classic one.",
                    "The verify endpoint accepts EITHER your real per-login code OR one of a small set of hardcoded magic values — 000000 and the literal string null both work — regardless of what the real code is.",
                    "Exact reproduction: log in at /a07/mfa-login-magic-value with dana/welcome1, then on the code-entry page submit code=000000 — you're granted full access with no knowledge of the real code at all.",
                ],
            ),
            ExampleNav(
                id="mfa-leaked-code",
```

Second, add the new `"Cross-Site Request Forgery"` group as the LAST
group in A07's `examples=[...]` list — after every other group,
including whatever Task 7 last inserted. Find the closing of the list
(the exact tail depends on what Tasks 6-7 already inserted; locate the
final `),` before `],` / `seed_fn=seed_a07_accounts,` and insert before
the list's closing `]`):

```python
        ],
        seed_fn=seed_a07_accounts,
    )
)
```

Replace with:

```python
            ExampleNav(
                id="csrf-disable-2fa",
                title="CSRF on Disabling 2FA",
                group="Cross-Site Request Forgery",
                difficulty="Medium",
                endpoint="a07_auth_failures.mfa_settings",
                hints=[
                    "This settings page shows a 'Disable 2FA' button once you've completed the real login+verify flow. Look at the disable form's HTML source — is there anything that would stop a completely different website from submitting that same request on your behalf?",
                    "There's no CSRF token anywhere in that form, and the server never checks where the POST came from — only that a valid session cookie was attached, which browsers send automatically on cross-origin form submissions too.",
                    "Complete the real MFA flow first (dana / welcome1 at /a07/mfa-login, then the code shown at /a07/mfa-verify) so your session is genuinely mfa_verified. Then, from a separate auto-submitting HTML form hosted anywhere else, POST to /a07/mfa/disable with no body required at all — your session's mfa_verified flag flips back to false with zero confirmation.",
                    "This matches a real, well-documented MFA-bypass technique: 2FA-disable endpoints are exactly the kind of sensitive, state-changing action that most needs CSRF protection and a re-authentication step (re-enter your password, or the code itself) before executing — this one has neither.",
                ],
            ),
        ],
        seed_fn=seed_a07_accounts,
    )
)
```

**Note for the implementer:** if Tasks 6-7 have already landed, the
`],` / `seed_fn=seed_a07_accounts,` tail you actually find will already
contain their entries (`mfa-reusable-code`, `mfa-bypass`,
`mfa-not-bound-to-session`, etc.) before this closing — append the new
`csrf-disable-2fa` entry immediately before that same `],` regardless of
exactly what precedes it; do not reorder or remove anything already
there.

- [ ] **Step 8: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a07_mfa_magic_value.py tests/test_a07_csrf_disable_2fa.py -v`
Expected: PASS (9 passed)

- [ ] **Step 9: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass.

- [ ] **Step 10: Commit**

```bash
git add app/categories/a07_auth_failures tests/test_a07_mfa_magic_value.py tests/test_a07_csrf_disable_2fa.py
git commit -m "feat(a07): add MFA magic-value bypass and CSRF-on-disable-2FA examples

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 9: Final Integration — Nav/Grouping Tests, Hints-Count Total, README

**Files:**
- Modify: `tests/test_a01_overview.py`
- Modify: `tests/test_a02_overview.py`
- Modify: `tests/test_a04_overview.py`
- Modify: `tests/test_a05_overview.py`
- Modify: `tests/test_a07_overview.py`
- Modify: `tests/test_all_examples_have_hints.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: the final `ExampleNav` lists produced by Tasks 1-8 (this task
  makes no code changes to any category — it only updates tests and docs
  to match what Tasks 1-8 actually registered).
- Produces: nothing new. This is the last task in the plan.

This task assumes Tasks 1-8 landed in order and produced exactly the
following final states. If any earlier task's actual landed result
differs from what its own plan text specified (e.g. a fix-round changed
an `id` or an insertion order), reconcile these assertions against the
real `app/core/nav.py` `CATEGORIES` contents rather than the numbers
below — the numbers below are derived from Tasks 1-8's plan text and
must match reality, not the other way around.

- [ ] **Step 1: Update `tests/test_a01_overview.py`**

Current file:

```python
def test_a01_overview_renders(client):
    response = client.get("/a01/")
    assert response.status_code == 200
    assert b"Broken Access Control" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a01_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a01 = next(c for c in CATEGORIES if c.id == "a01_access_control")
    assert a01.short_id == "A01"
    assert [e.difficulty for e in a01.examples] == ["Easy", "Medium", "Hard"]


def test_a01_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a01 = next(c for c in CATEGORIES if c.id == "a01_access_control")
    grouped = a01.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Insecure Direct Object References (IDOR)",
        "Missing Function-Level Access Control",
        "Mass Assignment",
    ]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a01_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a01/")
    body = response.data.decode()
    assert "Insecure Direct Object References (IDOR)" in body
    assert "Missing Function-Level Access Control" in body
    assert "Mass Assignment" in body
```

Replace with:

```python
def test_a01_overview_renders(client):
    response = client.get("/a01/")
    assert response.status_code == 200
    assert b"Broken Access Control" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a01_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a01 = next(c for c in CATEGORIES if c.id == "a01_access_control")
    assert a01.short_id == "A01"
    assert [e.difficulty for e in a01.examples] == [
        "Easy",
        "Medium",
        "Medium",
        "Hard",
        "Medium",
    ]


def test_a01_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a01 = next(c for c in CATEGORIES if c.id == "a01_access_control")
    grouped = a01.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Insecure Direct Object References (IDOR)",
        "Missing Function-Level Access Control",
        "Mass Assignment",
        "Cross-Site Request Forgery",
    ]
    assert [e.id for e in grouped[0][1]] == ["idor", "password-change-idor"]
    assert [e.id for e in grouped[3][1]] == ["csrf-email-change"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a01_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a01/")
    body = response.data.decode()
    assert "Insecure Direct Object References (IDOR)" in body
    assert "Missing Function-Level Access Control" in body
    assert "Mass Assignment" in body
    assert "Cross-Site Request Forgery" in body
```

- [ ] **Step 2: Update `tests/test_a02_overview.py`**

Current file (final three functions):

```python
def test_a02_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a02 = next(c for c in CATEGORIES if c.id == "a02_crypto_failures")
    assert a02.short_id == "A02"
    assert [e.difficulty for e in a02.examples] == ["Easy", "Medium", "Hard"]


def test_a02_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a02 = next(c for c in CATEGORIES if c.id == "a02_crypto_failures")
    grouped = a02.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Weak Hashing",
        "Weak Encryption",
        "Predictable Tokens",
    ]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a02_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a02/")
    body = response.data.decode()
    assert '<h3 class="h6 mt-3">Weak Hashing</h3>' in body
    assert '<h3 class="h6 mt-3">Weak Encryption</h3>' in body
    assert '<h3 class="h6 mt-3">Predictable Tokens</h3>' in body
```

Replace with:

```python
def test_a02_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a02 = next(c for c in CATEGORIES if c.id == "a02_crypto_failures")
    assert a02.short_id == "A02"
    assert [e.difficulty for e in a02.examples] == [
        "Easy",
        "Medium",
        "Hard",
        "Easy",
        "Medium",
    ]


def test_a02_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a02 = next(c for c in CATEGORIES if c.id == "a02_crypto_failures")
    grouped = a02.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Weak Hashing",
        "Weak Encryption",
        "Predictable Tokens",
        "Token Leakage",
    ]
    assert [e.id for e in grouped[3][1]] == ["reset-token-api-leak", "reset-token-referrer-leak"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a02_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a02/")
    body = response.data.decode()
    assert '<h3 class="h6 mt-3">Weak Hashing</h3>' in body
    assert '<h3 class="h6 mt-3">Weak Encryption</h3>' in body
    assert '<h3 class="h6 mt-3">Predictable Tokens</h3>' in body
    assert '<h3 class="h6 mt-3">Token Leakage</h3>' in body
```

- [ ] **Step 3: Update `tests/test_a04_overview.py`**

Current file (final three functions):

```python
def test_a04_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a04 = next(c for c in CATEGORIES if c.id == "a04_insecure_design")
    assert a04.short_id == "A04"
    assert [e.difficulty for e in a04.examples] == ["Easy", "Medium", "Hard"]


def test_a04_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a04 = next(c for c in CATEGORIES if c.id == "a04_insecure_design")
    grouped = a04.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Business Logic Abuse",
        "Workflow Bypass",
    ]
    assert [e.id for e in grouped[0][1]] == ["unlimited-coupon", "negative-quantity"]
    assert [e.id for e in grouped[1][1]] == ["checkout-bypass"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a04_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a04/")
    body = response.data.decode()
    assert "Business Logic Abuse" in body
    assert "Workflow Bypass" in body
```

Replace with:

```python
def test_a04_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a04 = next(c for c in CATEGORIES if c.id == "a04_insecure_design")
    assert a04.short_id == "A04"
    assert [e.difficulty for e in a04.examples] == ["Easy", "Medium", "Hard", "Hard"]


def test_a04_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a04 = next(c for c in CATEGORIES if c.id == "a04_insecure_design")
    grouped = a04.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Business Logic Abuse",
        "Workflow Bypass",
        "Password Reset Design Flaws",
    ]
    assert [e.id for e in grouped[0][1]] == ["unlimited-coupon", "negative-quantity"]
    assert [e.id for e in grouped[1][1]] == ["checkout-bypass"]
    assert [e.id for e in grouped[2][1]] == ["host-header-reset-poisoning"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a04_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a04/")
    body = response.data.decode()
    assert "Business Logic Abuse" in body
    assert "Workflow Bypass" in body
    assert "Password Reset Design Flaws" in body
```

- [ ] **Step 4: Update `tests/test_a05_overview.py`**

Current file (final three functions):

```python
def test_a05_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a05 = next(c for c in CATEGORIES if c.id == "a05_security_misconfiguration")
    assert a05.short_id == "A05"
    assert [e.difficulty for e in a05.examples] == [
        "Easy",
        "Easy",
        "Medium",
        "Medium",
        "Hard",
        "Hard",
    ]


def test_a05_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a05 = next(c for c in CATEGORIES if c.id == "a05_security_misconfiguration")
    grouped = a05.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Exposed Files & Directories",
        "Insecure Response Configuration",
        "Exposed Debug & Admin Interfaces",
    ]
    assert [e.id for e in grouped[0][1]] == ["exposed-backup", "directory-listing"]
    assert [e.id for e in grouped[1][1]] == ["verbose-errors", "cors-credentials"]
    assert [e.id for e in grouped[2][1]] == ["debug-console-rce", "default-admin-creds"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a05_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a05/")
    body = response.data.decode()
    # Group names contain "&", which Jinja2's default HTML autoescaping
    # (Flask's standard, secure behavior for .html templates) renders as
    # "&amp;" -- assert against the actual escaped output.
    assert "Exposed Files &amp; Directories" in body
    assert "Insecure Response Configuration" in body
    assert "Exposed Debug &amp; Admin Interfaces" in body
```

Replace with:

```python
def test_a05_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a05 = next(c for c in CATEGORIES if c.id == "a05_security_misconfiguration")
    assert a05.short_id == "A05"
    assert [e.difficulty for e in a05.examples] == [
        "Easy",
        "Easy",
        "Medium",
        "Medium",
        "Hard",
        "Hard",
        "Easy",
    ]


def test_a05_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a05 = next(c for c in CATEGORIES if c.id == "a05_security_misconfiguration")
    grouped = a05.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Exposed Files & Directories",
        "Insecure Response Configuration",
        "Exposed Debug & Admin Interfaces",
        "Missing Security Headers",
    ]
    assert [e.id for e in grouped[0][1]] == ["exposed-backup", "directory-listing"]
    assert [e.id for e in grouped[1][1]] == ["verbose-errors", "cors-credentials"]
    assert [e.id for e in grouped[2][1]] == ["debug-console-rce", "default-admin-creds"]
    assert [e.id for e in grouped[3][1]] == ["clickjacking-delete-account"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a05_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a05/")
    body = response.data.decode()
    # Group names contain "&", which Jinja2's default HTML autoescaping
    # (Flask's standard, secure behavior for .html templates) renders as
    # "&amp;" -- assert against the actual escaped output.
    assert "Exposed Files &amp; Directories" in body
    assert "Insecure Response Configuration" in body
    assert "Exposed Debug &amp; Admin Interfaces" in body
    assert "Missing Security Headers" in body
```

- [ ] **Step 5: Update `tests/test_a07_overview.py`**

Current file (final three functions):

```python
def test_a07_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a07 = next(c for c in CATEGORIES if c.id == "a07_auth_failures")
    assert a07.short_id == "A07"
    assert [e.difficulty for e in a07.examples] == [
        "Easy",
        "Medium",
        "Easy",
        "Medium",
        "Hard",
        "Hard",
    ]


def test_a07_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a07 = next(c for c in CATEGORIES if c.id == "a07_auth_failures")
    grouped = a07.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Brute Force & Credential Stuffing",
        "Session Identity & Lifecycle",
        "Multi-Factor Authentication Bypass",
    ]
    assert [e.id for e in grouped[0][1]] == ["brute-force-login", "credential-stuffing"]
    assert [e.id for e in grouped[1][1]] == [
        "session-in-url",
        "session-survives-logout",
        "session-fixation",
    ]
    assert [e.id for e in grouped[2][1]] == ["mfa-bypass"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a07_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a07/")
    body = response.data.decode()
    assert "Brute Force &amp; Credential Stuffing" in body
    assert "Session Identity &amp; Lifecycle" in body
    assert "Multi-Factor Authentication Bypass" in body
```

Replace with:

```python
def test_a07_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a07 = next(c for c in CATEGORIES if c.id == "a07_auth_failures")
    assert a07.short_id == "A07"
    assert [e.difficulty for e in a07.examples] == [
        "Easy",
        "Medium",
        "Easy",
        "Medium",
        "Hard",
        "Easy",
        "Easy",
        "Medium",
        "Medium",
        "Hard",
        "Hard",
        "Medium",
        "Hard",
        "Hard",
        "Medium",
    ]


def test_a07_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a07 = next(c for c in CATEGORIES if c.id == "a07_auth_failures")
    grouped = a07.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Brute Force & Credential Stuffing",
        "Session Identity & Lifecycle",
        "Multi-Factor Authentication Bypass",
        "Account Recovery Abuse",
        "Cross-Site Request Forgery",
    ]
    assert [e.id for e in grouped[0][1]] == ["brute-force-login", "credential-stuffing"]
    assert [e.id for e in grouped[1][1]] == [
        "session-in-url",
        "session-survives-logout",
        "session-fixation",
    ]
    assert [e.id for e in grouped[2][1]] == [
        "mfa-bypass-magic-value",
        "mfa-leaked-code",
        "mfa-reusable-code",
        "mfa-brute-force",
        "mfa-bypass",
        "mfa-not-bound-to-session",
    ]
    assert [e.id for e in grouped[3][1]] == [
        "password-reset-disables-mfa",
        "username-collision-reset",
        "unicode-normalization-takeover",
    ]
    assert [e.id for e in grouped[4][1]] == ["csrf-disable-2fa"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a07_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a07/")
    body = response.data.decode()
    assert "Brute Force &amp; Credential Stuffing" in body
    assert "Session Identity &amp; Lifecycle" in body
    assert "Multi-Factor Authentication Bypass" in body
    assert "Account Recovery Abuse" in body
    assert "Cross-Site Request Forgery" in body
```

**If the actual landed order from Tasks 5-8 differs from the sequence
above** (e.g. because a fix round changed an insertion point), update
these two assertions to match the real `CATEGORIES` contents rather than
force the code to match this test — the test exists to document and
lock in whatever order the routes actually register in, and internal
group Easy→Hard sortedness (verified by the `difficulty_rank` loop) is
the actual hard requirement, not this exact literal id sequence.

- [ ] **Step 6: Update `tests/test_all_examples_have_hints.py`**

Current file:

```python
from app.core.nav import CATEGORIES


def test_every_example_across_every_category_has_a_well_formed_hint_sequence():
    total = 0
    for category in CATEGORIES:
        for example in category.examples:
            total += 1
            assert 3 <= len(example.hints) <= 5, (
                f"{category.short_id}/{example.id} has {len(example.hints)} hints"
            )
            assert all(hint.strip() for hint in example.hints), (
                f"{category.short_id}/{example.id} has an empty hint"
            )
            assert len(set(example.hints)) == len(example.hints), (
                f"{category.short_id}/{example.id} has duplicate hints"
            )
    assert total == 63
```

Replace the final assertion:

```python
    assert total == 78
```

(63 existing + 2 A01 + 2 A02 + 1 A04 + 1 A05 + 9 A07 = 78.)

- [ ] **Step 7: Update `README.md`'s intro paragraph**

Modify the "Currently implemented" paragraph. Find (A01 clause):

```
Currently implemented: **A01 Broken Access Control** (IDOR, missing function-level
authorization, mass assignment / role escalation), **A02 Cryptographic Failures**
(leaked credential dump, weak ECB encryption, predictable password-reset token),
```

Replace with:

```
Currently implemented: **A01 Broken Access Control** (IDOR, missing function-level
authorization, mass assignment / role escalation, IDOR on a password-change API,
CSRF-based email-address takeover), **A02 Cryptographic Failures**
(leaked credential dump, weak ECB encryption, predictable password-reset token,
reset token leaked via the Referer header, reset token leaked in an API response),
```

Find (A04/A05 clause):

```
**A04 Insecure Design** (unlimited coupon reuse, negative-quantity price manipulation,
multi-step checkout bypass), **A05 Security Misconfiguration** (exposed database backup,
directory listing, verbose error disclosure, permissive CORS with credentials, exposed
debug console, forgotten admin panel with default credentials), **A06 Vulnerable
```

Replace with:

```
**A04 Insecure Design** (unlimited coupon reuse, negative-quantity price manipulation,
multi-step checkout bypass, password-reset poisoning via the Host header),
**A05 Security Misconfiguration** (exposed database backup,
directory listing, verbose error disclosure, permissive CORS with credentials, exposed
debug console, forgotten admin panel with default credentials, clickjacking on a
sensitive action page), **A06 Vulnerable
```

Find (A07 clause):

```
**A07 Identification and Authentication Failures** (no rate limiting
enables brute force, credential stuffing across multiple accounts, session
identifier exposed in a URL, session not invalidated on logout, full
session fixation, bypassable multi-factor authentication), **A08
```

Replace with:

```
**A07 Identification and Authentication Failures** (no rate limiting
enables brute force, credential stuffing across multiple accounts, session
identifier exposed in a URL, session not invalidated on logout, full
session fixation, bypassable multi-factor authentication, an MFA
backdoor magic value, an MFA code leaked through a debug API field, MFA
code reuse, MFA code not bound to its session, MFA brute force with no
rate limiting, password reset via username-whitespace collision,
account takeover via Unicode normalization, password reset silently
disabling 2FA, CSRF on disabling 2FA), **A08
```

- [ ] **Step 8: Update `README.md`'s category summary table**

Modify the table rows for A01, A02, A04, A05, A07. Find:

```
| A01 Broken Access Control | Implemented | IDOR (Easy), Hidden Admin Panel (Medium), Mass Assignment Role Escalation (Hard) |
| A02 Cryptographic Failures | Implemented | Leaked Credential Dump (Easy), Weak Encryption / ECB Mode (Medium), Predictable Password Reset Token (Hard) |
```

Replace with:

```
| A01 Broken Access Control | Implemented | IDOR (Easy), IDOR on Password-Change API (Medium), Hidden Admin Panel (Medium), Mass Assignment Role Escalation (Hard), Account Takeover via CSRF (Email Change) (Medium) |
| A02 Cryptographic Failures | Implemented | Leaked Credential Dump (Easy), Weak Encryption / ECB Mode (Medium), Predictable Password Reset Token (Hard), Reset Token Leaked in API Response (Easy), Reset Token Leaked via Referrer Header (Medium) |
```

Find:

```
| A04 Insecure Design | Implemented | Unlimited Coupon Reuse (Easy), Negative Quantity Price Manipulation (Medium), Multi-Step Checkout Bypass (Hard) |
| A05 Security Misconfiguration | Implemented | Exposed Database Backup File (Easy), Directory Listing Exposed (Easy), Verbose Error Message Disclosure (Medium), Permissive CORS with Credentials (Medium), Exposed Debug Console (Hard), Forgotten Admin Panel with Default Credentials (Hard) |
```

Replace with:

```
| A04 Insecure Design | Implemented | Unlimited Coupon Reuse (Easy), Negative Quantity Price Manipulation (Medium), Multi-Step Checkout Bypass (Hard), Password Reset Poisoning via Host Header (Hard) |
| A05 Security Misconfiguration | Implemented | Exposed Database Backup File (Easy), Directory Listing Exposed (Easy), Verbose Error Message Disclosure (Medium), Permissive CORS with Credentials (Medium), Exposed Debug Console (Hard), Forgotten Admin Panel with Default Credentials (Hard), Clickjacking on a Sensitive Action Page (Easy) |
```

Find:

```
| A07 Identification and Authentication Failures | Implemented | No Rate Limiting Enables Brute Force (Easy), Credential Stuffing Across Multiple Accounts (Medium), Session Identifier Exposed in URL (Easy), Session Not Invalidated on Logout (Medium), Session Fixation (Hard), Bypassable Multi-Factor Authentication (Hard) |
```

Replace with:

```
| A07 Identification and Authentication Failures | Implemented | No Rate Limiting Enables Brute Force (Easy), Credential Stuffing Across Multiple Accounts (Medium), Session Identifier Exposed in URL (Easy), Session Not Invalidated on Logout (Medium), Session Fixation (Hard), MFA Bypass via Magic/Null Value (Easy), MFA Code Leaked to Client (Easy), MFA Code Reusability (Medium), MFA Brute-Force (Medium), Bypassable Multi-Factor Authentication (Hard), MFA Code Not Bound to Session (Hard), Password Reset Silently Disables 2FA (Medium), Password Reset via Username Collision (Hard), Account Takeover via Unicode Normalization (Hard), CSRF on Disabling 2FA (Medium) |
```

- [ ] **Step 9: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass, 471 (running total through Task 4) + counts from Tasks
5-8 (11 + 7 + 6 + 9 = 33 new tests) = 504 total. (Reconcile this number
against the actual collected count — `.venv/bin/pytest tests/ -q --collect-only 2>&1 | tail -1`
— if any earlier task's implementer added or removed a test during a fix
round; the exact number is a sanity check, not a hard requirement.)

- [ ] **Step 10: Verify the app still boots and the nav renders end-to-end**

Run: `.venv/bin/python -c "from app import create_app; app = create_app(); client = app.test_client(); [print(r.status_code, r.request.path) for r in [client.get('/a01/'), client.get('/a02/'), client.get('/a04/'), client.get('/a05/'), client.get('/a07/')]]"`
Expected: all five print `200 /aNN/`.

- [ ] **Step 11: Commit**

```bash
git add tests/test_a01_overview.py tests/test_a02_overview.py tests/test_a04_overview.py tests/test_a05_overview.py tests/test_a07_overview.py tests/test_all_examples_have_hints.py README.md
git commit -m "test(nav): update grouping/hints-count tests and README for 15 new PayloadsAllTheThings-derived examples

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---
