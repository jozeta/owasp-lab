# Content Retrofit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Detect section and a Vulnerable vs. Secure code panel to every one of the 15 existing A01–A04 example pages, and expand each example's Exploitation section with a real-world-impact narrative — establishing the four-part structure (Explanation / Detect / Exploitation / Vulnerable vs. Secure) as the standard for A05–A10 and the upcoming A03 expansion.

**Architecture:** `core/example_page_base.html` gains two new blocks (`detect`, gated under `show_exploit_instructions` alongside `exploitation`) and two more (`vulnerable_code`/`secure_code`, always visible, no toggle). Each of the 15 example templates supplies content for these new blocks and expands its existing `exploitation` block. No route, model, or vulnerable-logic changes anywhere in this plan — every fix shown in a "Secure" panel is illustrative teaching content, not applied to the actual (intentionally vulnerable) route.

**Tech Stack:** Flask, Jinja2, pytest. No new dependencies.

**Spec:** docs/superpowers/specs/2026-09-18-owasp-lab-content-retrofit-design.md

## Global Constraints

- No route, model, seed, or vulnerable-logic changes — every example's actual behavior stays byte-identical. This plan only adds template content and tests.
- `detect` gates under `settings.show_exploit_instructions` (same toggle as `exploitation`) — never a new toggle.
- `vulnerable_code`/`secure_code` render unconditionally, no toggle, matching the category Overview page's existing pattern.
- Every example keeps working with both toggles off (existing convention) — the new Vulnerable vs. Secure panel specifically must still render with both toggles off, and the new Detect content must be hidden exactly like Exploitation is.
- Code shown in "Secure" panels is teaching-only illustration — it is never applied to the actual route in this plan.

---

### Task 1: Add Detect and Vulnerable vs. Secure sections to the shared example template

**Files:**
- Modify: `app/core/templates/core/example_page_base.html`
- Test: `tests/test_example_page_base.py` (new file)

**Interfaces:**
- Consumes: nothing new.
- Produces: two new Jinja blocks every example template can override — `detect` (gated under `show_exploit_instructions`) and `vulnerable_code`/`secure_code` (always visible). Tasks 2–6 fill these in for all 15 examples.

- [ ] **Step 1: Write the failing test**

Create `tests/test_example_page_base.py`:

```python
from app.core.models import Settings
from app.extensions import db


def test_example_page_shows_vulnerable_vs_secure_with_both_toggles_off(app, client, login):
    login("alice")
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get("/a01/profile/1")
    assert response.status_code == 200
    body = response.data.decode()
    assert "Vulnerable vs. Secure" in body
    assert "Vulnerable" in body
    assert "Secure" in body


def test_example_page_hides_detect_with_exploit_instructions_off(app, client, login):
    login("alice")
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = True
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get("/a01/profile/1")
    assert response.status_code == 200
    assert b"Detect" not in response.data


def test_example_page_shows_detect_with_exploit_instructions_on(app, client, login):
    login("alice")
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = True
        settings.show_exploit_instructions = True
        db.session.commit()

    response = client.get("/a01/profile/1")
    assert response.status_code == 200
    assert b"Detect" in response.data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_example_page_base.py -v`
Expected: `test_example_page_shows_vulnerable_vs_secure_with_both_toggles_off` FAILs (no "Vulnerable vs. Secure" text yet); `test_example_page_hides_detect_with_exploit_instructions_off` PASSes trivially (no Detect text exists at all yet, so it's already absent — this is expected, not a bug); `test_example_page_shows_detect_with_exploit_instructions_on` FAILs (no Detect block yet).

- [ ] **Step 3: Update the shared template**

In `app/core/templates/core/example_page_base.html`, the current file reads:

```html
{% extends "core/base.html" %}

{% block content %}
{% set badge_classes = {"Easy": "text-bg-success", "Medium": "text-bg-warning", "Hard": "text-bg-danger"} %}
<div class="d-flex justify-content-between align-items-center mb-3">
  <h1>{{ example_title }}</h1>
  <span class="badge {{ badge_classes[example_difficulty] }}">{{ example_difficulty }}</span>
</div>

{% if settings.show_explanations %}
<section class="card mb-4">
  <div class="card-header">Explanation</div>
  <div class="card-body">
    {% block explanation %}{% endblock %}
  </div>
</section>
{% endif %}

{% if settings.show_exploit_instructions %}
<section class="card mb-4 border-danger">
  <div class="card-header bg-danger text-white">Exploitation</div>
  <div class="card-body">
    {% block exploitation %}{% endblock %}
  </div>
</section>
{% endif %}

<section class="card">
  <div class="card-header">Try It</div>
  <div class="card-body">
    {% block live_example %}{% endblock %}
  </div>
</section>
{% endblock %}
```

Replace it with:

```html
{% extends "core/base.html" %}

{% block content %}
{% set badge_classes = {"Easy": "text-bg-success", "Medium": "text-bg-warning", "Hard": "text-bg-danger"} %}
<div class="d-flex justify-content-between align-items-center mb-3">
  <h1>{{ example_title }}</h1>
  <span class="badge {{ badge_classes[example_difficulty] }}">{{ example_difficulty }}</span>
</div>

{% if settings.show_explanations %}
<section class="card mb-4">
  <div class="card-header">Explanation</div>
  <div class="card-body">
    {% block explanation %}{% endblock %}
  </div>
</section>
{% endif %}

{% if settings.show_exploit_instructions %}
<section class="card mb-4">
  <div class="card-header">Detect</div>
  <div class="card-body">
    {% block detect %}{% endblock %}
  </div>
</section>

<section class="card mb-4 border-danger">
  <div class="card-header bg-danger text-white">Exploitation</div>
  <div class="card-body">
    {% block exploitation %}{% endblock %}
  </div>
</section>
{% endif %}

<section class="card mb-4">
  <div class="card-header">Vulnerable vs. Secure</div>
  <div class="card-body">
    <div class="row">
      <div class="col-md-6">
        <h6>Vulnerable</h6>
        <pre><code class="language-{{ code_language|default('python') }}">{% block vulnerable_code %}{% endblock %}</code></pre>
      </div>
      <div class="col-md-6">
        <h6>Secure</h6>
        <pre><code class="language-{{ code_language|default('python') }}">{% block secure_code %}{% endblock %}</code></pre>
      </div>
    </div>
  </div>
</section>

<section class="card">
  <div class="card-header">Try It</div>
  <div class="card-body">
    {% block live_example %}{% endblock %}
  </div>
</section>
{% endblock %}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/test_example_page_base.py -v`
Expected: all 3 PASS. (`/a01/profile/1` still works even though `idor.html` hasn't been updated yet — the new blocks just render empty, which is enough to prove the shared template's structure and toggle behavior are correct in isolation before any example fills them in.)

- [ ] **Step 5: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (123 existing + 3 new = 126). No existing example test should break — every example's current `explanation`/`exploitation`/`live_example` blocks are untouched by this step.

- [ ] **Step 6: Commit**

```bash
git add app/core/templates/core/example_page_base.html tests/test_example_page_base.py
git commit -m "feat: add Detect and Vulnerable vs. Secure sections to example page template"
```

---

### Task 2: A01 — fill in Detect and Vulnerable vs. Secure for all 3 examples

**Files:**
- Modify: `app/categories/a01_access_control/templates/a01_access_control/idor.html`
- Modify: `app/categories/a01_access_control/templates/a01_access_control/admin_users.html`
- Modify: `app/categories/a01_access_control/templates/a01_access_control/account_update.html`
- Modify: `tests/test_a01_idor.py`
- Modify: `tests/test_a01_admin_users.py`
- Modify: `tests/test_a01_account_update.py`

**Interfaces:**
- Consumes: `detect`/`vulnerable_code`/`secure_code` blocks from Task 1.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: `idor.html` — add Detect and Vulnerable vs. Secure**

In `app/categories/a01_access_control/templates/a01_access_control/idor.html`, the file currently ends its `exploitation` block and begins `live_example` like this:

```html
{% block exploitation %}
<ol>
  <li>Log in as <strong>alice</strong> using the login page.</li>
  <li>Visit <code>/a01/profile/1</code> — this is your own profile.</li>
  <li>Change the URL to a different id, e.g. <code>/a01/profile/2</code> or
      <code>/a01/profile/4</code>, and reload.</li>
  <li>The page renders that user's private notes even though you never authenticated as them.</li>
</ol>
{% endblock %}

{% block live_example %}
```

Change it to (adds a real-world-impact paragraph to `exploitation`, inserts `detect` and the two code blocks before `live_example`):

```html
{% block detect %}
<p>
  Log in, note your own id in the URL (e.g. <code>/a01/profile/1</code>), then change just
  that number by one (<code>/a01/profile/2</code>) and reload. You don't need to read
  anything on the page to detect the bug — the mere fact that you get a <code>200 OK</code>
  with <em>someone else's</em> profile at all, instead of a <code>403</code> or a redirect
  back to your own, already confirms there's no ownership check. That's the whole probe: no
  data extraction required to prove the bug exists.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Log in as <strong>alice</strong> using the login page.</li>
  <li>Visit <code>/a01/profile/1</code> — this is your own profile.</li>
  <li>Change the URL to a different id, e.g. <code>/a01/profile/2</code> or
      <code>/a01/profile/4</code>, and reload.</li>
  <li>The page renders that user's private notes even though you never authenticated as them.</li>
</ol>
<p>
  IDOR is one of the most common findings in real-world bug bounty reports precisely
  because it scales trivially: once you know the check is missing, there's no reason to
  stop at one record. A short loop turns a single leaked private note into the entire
  user table:
</p>
<pre><code class="language-bash">for id in $(seq 1 50); do
  curl -s -b "session=&lt;your session cookie&gt;" \
    http://127.0.0.1:5001/a01/profile/$id \
    | grep -o 'Private notes:[^&lt;]*'
done</code></pre>
<p>
  Run against a real production app instead of this lab, that same loop is a full
  customer-data breach — the technique behind several large-scale IDOR disclosures has
  been exactly this: iterate a numeric ID, harvest whatever comes back.
</p>
{% endblock %}

{% block vulnerable_code %}def idor(user_id=1):
    viewer = get_current_user()
    profile = db.get_or_404(User, user_id)
    return render_template("idor.html", profile=profile, viewer=viewer)
{% endblock %}

{% block secure_code %}def idor(user_id=1):
    viewer = get_current_user()
    if user_id != viewer.id and not viewer.is_admin:
        abort(403)
    profile = db.get_or_404(User, user_id)
    return render_template("idor.html", profile=profile, viewer=viewer)
{% endblock %}

{% block live_example %}
```

- [ ] **Step 2: `admin_users.html` — add Detect and Vulnerable vs. Secure**

In `app/categories/a01_access_control/templates/a01_access_control/admin_users.html`, the file currently ends its `exploitation` block and begins `live_example` like this:

```html
{% block exploitation %}
<ol>
  <li>Log in as <strong>alice</strong> (a regular, non-admin user).</li>
  <li>Navigate directly to <code>/a01/admin/users</code> — there is no link to it, but it loads anyway.</li>
  <li>Pick any user in the table and submit "admin" as their new role.</li>
  <li>That user now has admin privileges, granted by a non-admin session.</li>
</ol>
{% endblock %}

{% block live_example %}
```

Change it to:

```html
{% block detect %}
<p>
  Log in as any non-admin user (e.g. <strong>alice</strong>) and navigate directly to
  <code>/a01/admin/users</code> — there's no link to it anywhere in the UI. If the page
  loads at all instead of redirecting or showing a 403, that alone confirms the route has
  no role check — you haven't changed anyone's role yet, just confirmed the door is
  unlocked.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Log in as <strong>alice</strong> (a regular, non-admin user).</li>
  <li>Navigate directly to <code>/a01/admin/users</code> — there is no link to it, but it loads anyway.</li>
  <li>Pick any user in the table and submit "admin" as their new role.</li>
  <li>That user now has admin privileges, granted by a non-admin session.</li>
</ol>
<p>
  Missing function-level access control is exactly the class of bug that automated
  scanners and directory-brute-forcers are built to find — tools like <code>ffuf</code> or
  <code>gobuster</code> can enumerate hundreds of guessable admin-style paths
  (<code>/admin</code>, <code>/admin/users</code>, <code>/manage</code>,
  <code>/internal</code>) in seconds against a target, and every one that returns 200
  instead of 403/404 is a candidate for exactly this kind of unauthorized privilege
  escalation.
</p>
{% endblock %}

{% block vulnerable_code %}def admin_users():
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=request.path))
    if request.method == "POST":
        target = db.get_or_404(User, int(request.form["user_id"]))
        target.role = request.form["role"]
        db.session.commit()
    ...
{% endblock %}

{% block secure_code %}def admin_users():
    viewer = get_current_user()
    if viewer is None:
        return redirect(url_for("core.switch_user", next=request.path))
    if viewer.role != "admin":
        abort(403)
    if request.method == "POST":
        target = db.get_or_404(User, int(request.form["user_id"]))
        target.role = request.form["role"]
        db.session.commit()
    ...
{% endblock %}

{% block live_example %}
```

- [ ] **Step 3: `account_update.html` — add Detect and Vulnerable vs. Secure**

In `app/categories/a01_access_control/templates/a01_access_control/account_update.html`, the file currently ends its `exploitation` block and begins `live_example` like this:

```html
{% block exploitation %}
<p>Log in as <strong>alice</strong>, then submit the form below with an extra field.
  The browser form only submits the visible fields, so use curl to add
  <code>role=admin</code> to the request (copy your session cookie from the browser's
  dev tools first):</p>
<pre><code class="language-bash">curl -i '{{ request.host_url }}a01/account/update' \
  -b 'session=&lt;your session cookie&gt;' \
  -d 'display_name=Alice' \
  -d 'bio=hiking' \
  -d 'role=admin'</code></pre>
<p>Reload this page afterward — your role now reads <strong>admin</strong>.</p>
{% endblock %}

{% block live_example %}
```

Change it to:

```html
{% block detect %}
<p>
  Submit the visible form normally (display name + bio) — nothing looks wrong, the page
  just confirms your profile updated. The bug isn't visible in the UI at all; it only
  shows up when you check what fields the <em>server</em> actually accepts versus what the
  <em>form</em> exposes. Add one harmless extra field the form doesn't include, e.g.
  <code>nickname=test</code>, via curl, and confirm your profile object now reflects it
  even though the browser form never offered that field — that's the detection step: the
  server applies <em>any</em> submitted field, not just the ones the UI shows you.
</p>
{% endblock %}

{% block exploitation %}
<p>Log in as <strong>alice</strong>, then submit the form below with an extra field.
  The browser form only submits the visible fields, so use curl to add
  <code>role=admin</code> to the request (copy your session cookie from the browser's
  dev tools first):</p>
<pre><code class="language-bash">curl -i '{{ request.host_url }}a01/account/update' \
  -b 'session=&lt;your session cookie&gt;' \
  -d 'display_name=Alice' \
  -d 'bio=hiking' \
  -d 'role=admin'</code></pre>
<p>Reload this page afterward — your role now reads <strong>admin</strong>.</p>
<p>
  Mass assignment is a well-documented, repeatedly-disclosed bug class — frameworks that
  blindly bind form data onto model attributes have caused real privilege-escalation
  incidents when a "hidden" or internal-only field (<code>role</code>,
  <code>is_admin</code>, <code>account_balance</code>) turns out to be settable by anyone
  who knows the field name, which is often guessable directly from the model itself or
  leaked API documentation.
</p>
{% endblock %}

{% block vulnerable_code %}if request.method == "POST":
    for key, value in request.form.items():
        if key == "id":
            continue
        setattr(viewer, key, value)
    db.session.commit()
{% endblock %}

{% block secure_code %}ALLOWED_FIELDS = {"display_name", "bio"}

if request.method == "POST":
    for key, value in request.form.items():
        if key in ALLOWED_FIELDS:
            setattr(viewer, key, value)
    db.session.commit()
{% endblock %}

{% block live_example %}
```

- [ ] **Step 4: Update `tests/test_a01_idor.py`**

Append to `tests/test_a01_idor.py`:

```python


def test_idor_shows_vulnerable_vs_secure_with_teaching_text_hidden(app, client, login):
    from app.core.models import Settings

    login("alice")
    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get("/a01/profile/1")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"abort(403)" in response.data
```

- [ ] **Step 5: Update `tests/test_a01_admin_users.py`**

Append to `tests/test_a01_admin_users.py`:

```python


def test_admin_users_shows_vulnerable_vs_secure_code(client, login):
    login("alice")
    response = client.get("/a01/admin/users")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b'viewer.role != "admin"' in response.data
```

- [ ] **Step 6: Update `tests/test_a01_account_update.py`**

Append to `tests/test_a01_account_update.py`:

```python


def test_account_update_shows_vulnerable_vs_secure_code(client, login):
    login("alice")
    response = client.get("/a01/account/update")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"ALLOWED_FIELDS" in response.data
```

- [ ] **Step 7: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (126 + 3 = 129)

- [ ] **Step 8: Commit**

```bash
git add app/categories/a01_access_control/templates/a01_access_control/idor.html \
  app/categories/a01_access_control/templates/a01_access_control/admin_users.html \
  app/categories/a01_access_control/templates/a01_access_control/account_update.html \
  tests/test_a01_idor.py tests/test_a01_admin_users.py tests/test_a01_account_update.py
git commit -m "feat: add Detect and Vulnerable vs. Secure content to A01 examples"
```

---

### Task 3: A02 — fill in Detect and Vulnerable vs. Secure for all 3 examples

**Files:**
- Modify: `app/categories/a02_crypto_failures/templates/a02_crypto_failures/credential_dump.html`
- Modify: `app/categories/a02_crypto_failures/templates/a02_crypto_failures/encrypted_notes.html`
- Modify: `app/categories/a02_crypto_failures/templates/a02_crypto_failures/forgot_password.html`
- Modify: `tests/test_a02_credential_dump.py`
- Modify: `tests/test_a02_encrypted_notes.py`
- Modify: `tests/test_a02_reset_token.py`

**Interfaces:**
- Consumes: `detect`/`vulnerable_code`/`secure_code` blocks from Task 1.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: `credential_dump.html` — add Detect and Vulnerable vs. Secure**

In `app/categories/a02_crypto_failures/templates/a02_crypto_failures/credential_dump.html`, the file currently ends its `exploitation` block and begins `live_example` like this:

```html
{% block exploitation %}
<ol>
  <li>Copy one of the <code>weak_password_hash</code> values below.</li>
  <li>Paste it into any online MD5 lookup / rainbow-table site (search
      "md5 decrypt" and paste the hash).</li>
  <li>The plaintext password comes back instantly — MD5 offers no protection here.</li>
  <li>Try logging in with the recovered password at
      <a href="{{ url_for('a02_crypto_failures.legacy_login') }}">the legacy login page</a>.</li>
</ol>
{% endblock %}

{% block live_example %}
```

Change it to:

```html
{% block detect %}
<p>
  Look at the <code>weak_password_hash</code> column below — each value is exactly 32 hex
  characters. That length and character set is the signature of raw MD5. A properly hashed
  password (bcrypt, scrypt, Argon2) looks nothing like this — it's prefixed with an
  algorithm tag and includes an embedded salt (e.g. <code>$2b$12$...</code>). Recognizing
  that signature <em>is</em> the detection step here: no cracking needed yet, just noticing
  the storage format itself is the vulnerability.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Copy one of the <code>weak_password_hash</code> values below.</li>
  <li>Paste it into any online MD5 lookup / rainbow-table site (search
      "md5 decrypt" and paste the hash).</li>
  <li>The plaintext password comes back instantly — MD5 offers no protection here.</li>
  <li>Try logging in with the recovered password at
      <a href="{{ url_for('a02_crypto_failures.legacy_login') }}">the legacy login page</a>.</li>
</ol>
<p>
  Unsalted MD5 password dumps are a recurring theme in real breach disclosures — because
  MD5 has no per-user salt, one precomputed rainbow table (a static, downloadable dataset
  mapping billions of common password hashes back to plaintext) cracks every affected
  account at once, not just one at a time. This is exactly why the industry moved to
  purpose-built slow hashes (bcrypt/scrypt/Argon2) that make even a single guess
  computationally expensive, let alone billions.
</p>
{% endblock %}

{% block vulnerable_code %}weak_password_hash = hashlib.md5(password.encode()).hexdigest()
{% endblock %}

{% block secure_code %}from werkzeug.security import generate_password_hash

password_hash = generate_password_hash(password)  # bcrypt/scrypt under the hood, salted
{% endblock %}

{% block live_example %}
```

- [ ] **Step 2: `encrypted_notes.html` — add Detect and Vulnerable vs. Secure**

In `app/categories/a02_crypto_failures/templates/a02_crypto_failures/encrypted_notes.html`, the file currently ends its `exploitation` block and begins `live_example` like this:

```html
{% block exploitation %}
<ol>
  <li>Compare the ciphertext values in the table below — two rows are byte-for-byte
      identical, meaning those two users gave the exact same answer, without decrypting
      anything at all.</li>
  <li>Since the key is hardcoded and disclosed above, paste any ciphertext (hex) into the
      decrypt tool below to recover the plaintext directly.</li>
</ol>
{% endblock %}

{% block live_example %}
```

Change it to:

```html
{% block detect %}
<p>
  Scan the ciphertext column below for any two identical values before decrypting
  anything. Finding a repeat is the detection step: with a properly randomized cipher
  mode (e.g. AES-GCM or AES-CBC with a fresh IV per encryption), even identical plaintexts
  produce completely different ciphertexts every time — so a repeat here proves the
  encryption is deterministic per-block, which is the ECB-mode weakness, before you've
  decrypted a single byte.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Compare the ciphertext values in the table below — two rows are byte-for-byte
      identical, meaning those two users gave the exact same answer, without decrypting
      anything at all.</li>
  <li>Since the key is hardcoded and disclosed above, paste any ciphertext (hex) into the
      decrypt tool below to recover the plaintext directly.</li>
</ol>
<p>
  ECB-mode pattern leakage is a textbook cryptography failure precisely because it's
  visible without ever recovering the key — the classic illustration is encrypting an
  image in ECB mode and still being able to make out its outline in the ciphertext, purely
  from repeated blocks. Combined with a hardcoded key (recoverable from any source leak,
  decompiled binary, or misconfigured backup), this pattern has been the root cause of
  real incidents where "encrypted" data turned out to be decryptable by anyone who ever
  had access to the application's source.
</p>
{% endblock %}

{% block vulnerable_code %}AES_KEY = b"0123456789abcdef"  # hardcoded

def encrypt_ecb(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded = pad(plaintext.encode(), AES.block_size)
    return cipher.encrypt(padded).hex()
{% endblock %}

{% block secure_code %}import os

def encrypt_gcm(plaintext, key):  # key from a secrets manager, never hardcoded
    nonce = os.urandom(12)  # fresh, random per encryption
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return nonce + ciphertext + tag
{% endblock %}

{% block live_example %}
```

- [ ] **Step 3: `forgot_password.html` — add Detect and Vulnerable vs. Secure**

In `app/categories/a02_crypto_failures/templates/a02_crypto_failures/forgot_password.html`, the file currently ends its `exploitation` block and begins `live_example` like this:

```html
{% block exploitation %}
<ol>
  <li>Compute the token for the <code>admin</code> account yourself:
      <code>md5("admin:resetSalt2024")[:10]</code>.
      In Python: <code>import hashlib; hashlib.md5(b"admin:resetSalt2024").hexdigest()[:10]</code>.</li>
  <li>Visit <code>/a02/reset-password/&lt;that token&gt;</code> and set a new password for
      the admin account — the app never verified you own that account, only that you knew
      the token.</li>
  <li>Prove the takeover at
      <a href="{{ url_for('a02_crypto_failures.legacy_login') }}">the legacy login page</a>
      using <code>admin</code> and your new password.</li>
</ol>
{% endblock %}

{% block live_example %}
```

Change it to:

```html
{% block detect %}
<p>
  Request a password reset for any known username (e.g. <code>alice</code>) — the response
  just says a reset link has been sent, with no token shown. That refusal to display the
  token is itself worth noticing: if the token were a properly randomized, unguessable
  secret, there'd be no need to hide the algorithm behind it at all. The real detection
  step is checking whether the token is <em>deterministic</em> — with the algorithm and
  salt disclosed above, you can compute today's token for any username yourself, entirely
  offline, without ever receiving an email.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Compute the token for the <code>admin</code> account yourself:
      <code>md5("admin:resetSalt2024")[:10]</code>.
      In Python: <code>import hashlib; hashlib.md5(b"admin:resetSalt2024").hexdigest()[:10]</code>.</li>
  <li>Visit <code>/a02/reset-password/&lt;that token&gt;</code> and set a new password for
      the admin account — the app never verified you own that account, only that you knew
      the token.</li>
  <li>Prove the takeover at
      <a href="{{ url_for('a02_crypto_failures.legacy_login') }}">the legacy login page</a>
      using <code>admin</code> and your new password.</li>
</ol>
<p>
  Predictable password-reset tokens are a classic authentication bypass that shows up
  repeatedly in real disclosed vulnerabilities — whenever a token is derived only from
  public or guessable inputs (a username, a timestamp, a sequential ID) plus a static
  secret, an attacker who obtains the algorithm (via a source leak, decompilation, or
  simply guessing a common pattern like <code>MD5(username+salt)</code>) can take over any
  account without ever intercepting a real email or SMS message, defeating the entire
  purpose of an out-of-band reset flow.
</p>
{% endblock %}

{% block vulnerable_code %}RESET_TOKEN_SALT = "resetSalt2024"

def generate_reset_token(username):
    return hashlib.md5(f"{username}:{RESET_TOKEN_SALT}".encode()).hexdigest()[:10]
{% endblock %}

{% block secure_code %}import secrets

def generate_reset_token(username):
    token = secrets.token_urlsafe(32)  # cryptographically random, unique per request
    store_reset_token(username, token, expires_in_minutes=15)  # single-use, time-limited
    return token
{% endblock %}

{% block live_example %}
```

- [ ] **Step 4: Update `tests/test_a02_credential_dump.py`**

Append to `tests/test_a02_credential_dump.py`:

```python


def test_credential_dump_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a02/credential-dump")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"generate_password_hash" in response.data
```

- [ ] **Step 5: Update `tests/test_a02_encrypted_notes.py`**

Append to `tests/test_a02_encrypted_notes.py`:

```python


def test_encrypted_notes_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a02/encrypted-notes")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"MODE_GCM" in response.data
```

- [ ] **Step 6: Update `tests/test_a02_reset_token.py`**

Append to `tests/test_a02_reset_token.py`:

```python


def test_forgot_password_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a02/forgot-password")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"secrets.token_urlsafe" in response.data
```

- [ ] **Step 7: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (129 + 3 = 132)

- [ ] **Step 8: Commit**

```bash
git add app/categories/a02_crypto_failures/templates/a02_crypto_failures/credential_dump.html \
  app/categories/a02_crypto_failures/templates/a02_crypto_failures/encrypted_notes.html \
  app/categories/a02_crypto_failures/templates/a02_crypto_failures/forgot_password.html \
  tests/test_a02_credential_dump.py tests/test_a02_encrypted_notes.py tests/test_a02_reset_token.py
git commit -m "feat: add Detect and Vulnerable vs. Secure content to A02 examples"
```

---

### Task 4: A03 SQL injection trio — fill in Detect and Vulnerable vs. Secure

**Files:**
- Modify: `app/categories/a03_injection/templates/a03_injection/login.html`
- Modify: `app/categories/a03_injection/templates/a03_injection/search.html`
- Modify: `app/categories/a03_injection/templates/a03_injection/check_username.html`
- Modify: `tests/test_a03_login.py`
- Modify: `tests/test_a03_search.py`
- Modify: `tests/test_a03_check_username.py`

**Interfaces:**
- Consumes: `detect`/`vulnerable_code`/`secure_code` blocks from Task 1.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: `login.html` — add Detect and Vulnerable vs. Secure**

In `app/categories/a03_injection/templates/a03_injection/login.html`, the file currently ends its `exploitation` block and begins `live_example` like this:

```html
{% block exploitation %}
<ol>
  <li>In the username field, enter: <code>' OR '1'='1' -- </code></li>
  <li>Leave the password field blank (or put anything — it's commented out).</li>
  <li>The injected <code>OR '1'='1'</code> makes the WHERE clause true for every row, and
      <code>--</code> comments out the rest of the query, so the password check never
      happens. You're logged in as whichever account the database returns first.</li>
  <li>To log in specifically as <code>admin</code> without knowing the password, try
      <code>admin' -- </code> as the username instead.</li>
</ol>
{% endblock %}

{% block live_example %}
```

Change it to:

```html
{% block detect %}
<p>
  Try logging in with a username containing a single quote, e.g. <code>o'brien</code>, and
  any password. A properly parameterized query treats the quote as a literal character and
  just fails the login normally. This one throws a database syntax error instead (or
  behaves unexpectedly) — a single quote is enough to prove your input reaches raw SQL, no
  bypass required yet.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>In the username field, enter: <code>' OR '1'='1' -- </code></li>
  <li>Leave the password field blank (or put anything — it's commented out).</li>
  <li>The injected <code>OR '1'='1'</code> makes the WHERE clause true for every row, and
      <code>--</code> comments out the rest of the query, so the password check never
      happens. You're logged in as whichever account the database returns first.</li>
  <li>To log in specifically as <code>admin</code> without knowing the password, try
      <code>admin' -- </code> as the username instead.</li>
</ol>
<p>
  Authentication bypass via SQL injection is one of the most consequential injection
  outcomes because it skips credential verification entirely — real-world incidents using
  this exact <code>' OR '1'='1'</code> class of payload have led to full administrative
  access on production systems with no valid credentials at all, and the payload is so
  well-known it's one of the first things automated scanners and bots try against any
  login form they find.
</p>
{% endblock %}

{% block vulnerable_code %}query = (
    f"SELECT * FROM injection_accounts "
    f"WHERE username = '{username}' AND password = '{password}'"
)
row = db.session.execute(text(query)).mappings().first()
{% endblock %}

{% block secure_code %}query = text(
    "SELECT * FROM injection_accounts WHERE username = :username AND password = :password"
)
row = db.session.execute(query, {"username": username, "password": password}).mappings().first()
{% endblock %}

{% block live_example %}
```

- [ ] **Step 2: `search.html` — add Detect and Vulnerable vs. Secure**

In `app/categories/a03_injection/templates/a03_injection/search.html`, the file currently ends its `exploitation` block and begins `live_example` like this:

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
{% endblock %}

{% block live_example %}
```

Change it to:

```html
{% block detect %}
<p>
  Search for a term containing a single quote, e.g. <code>o'brien</code>. A properly
  parameterized <code>LIKE</code> query just returns zero matches for that literal string;
  this one throws a syntax error because your quote breaks out of the string literal —
  confirming the search term reaches raw SQL before you ever attempt a UNION.
</p>
{% endblock %}

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

{% block vulnerable_code %}query = f"SELECT id, username FROM injection_accounts WHERE username LIKE '%{q}%'"
results = db.session.execute(text(query)).all()
{% endblock %}

{% block secure_code %}query = text("SELECT id, username FROM injection_accounts WHERE username LIKE :pattern")
results = db.session.execute(query, {"pattern": f"%{q}%"}).all()
{% endblock %}

{% block live_example %}
```

- [ ] **Step 3: `check_username.html` — add Detect and Vulnerable vs. Secure**

In `app/categories/a03_injection/templates/a03_injection/check_username.html`, the file currently ends its `exploitation` block (including the SQLite-portability note) and begins `live_example` like this:

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
{% endblock %}

{% block live_example %}
```

Change it to:

```html
{% block detect %}
<p>
  Enter a single quote on its own, <code>'</code>, and submit. A parameterized query would
  just search for a username containing a literal quote and find nothing unusual; this one
  throws a database error (or misbehaves) because the quote breaks out of the string
  literal in the raw SQL. That single character — no payload, no timing, no data read — is
  enough to confirm the input reaches the query unescaped.
</p>
{% endblock %}

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

{% block vulnerable_code %}query = f"SELECT COUNT(*) FROM injection_accounts WHERE username = '{username}'"
count = db.session.execute(text(query)).scalar()
{% endblock %}

{% block secure_code %}query = text("SELECT COUNT(*) FROM injection_accounts WHERE username = :username")
count = db.session.execute(query, {"username": username}).scalar()
{% endblock %}

{% block live_example %}
```

- [ ] **Step 4: Update `tests/test_a03_login.py`**

Append to `tests/test_a03_login.py`:

```python


def test_login_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a03/login")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b":username AND password = :password" in response.data
```

- [ ] **Step 5: Update `tests/test_a03_search.py`**

Append to `tests/test_a03_search.py`:

```python


def test_search_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a03/search")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b":pattern" in response.data
```

- [ ] **Step 6: Update `tests/test_a03_check_username.py`**

Append to `tests/test_a03_check_username.py`:

```python


def test_check_username_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a03/check-username")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b":username" in response.data
```

- [ ] **Step 7: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (132 + 3 = 135)

- [ ] **Step 8: Commit**

```bash
git add app/categories/a03_injection/templates/a03_injection/login.html \
  app/categories/a03_injection/templates/a03_injection/search.html \
  app/categories/a03_injection/templates/a03_injection/check_username.html \
  tests/test_a03_login.py tests/test_a03_search.py tests/test_a03_check_username.py
git commit -m "feat: add Detect and Vulnerable vs. Secure content to A03 SQL injection examples"
```

---

### Task 5: A03 XSS + command injection trio — fill in Detect and Vulnerable vs. Secure

**Files:**
- Modify: `app/categories/a03_injection/templates/a03_injection/greet.html`
- Modify: `app/categories/a03_injection/templates/a03_injection/comments.html`
- Modify: `app/categories/a03_injection/templates/a03_injection/host_lookup.html`
- Modify: `tests/test_a03_greet.py`
- Modify: `tests/test_a03_comments.py`
- Modify: `tests/test_a03_host_lookup.py`

**Interfaces:**
- Consumes: `detect`/`vulnerable_code`/`secure_code` blocks from Task 1.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: `greet.html` — add Detect and Vulnerable vs. Secure**

In `app/categories/a03_injection/templates/a03_injection/greet.html`, the file currently ends its `exploitation` block and begins `live_example` like this:

```html
{% block exploitation %}
<ol>
  <li>Visit this page with
      <code>?name=&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code>
      appended to the URL.</li>
  <li>The script executes in your browser as soon as the page loads — this is a
      <em>reflected</em> XSS because the payload comes straight from the URL and is
      never stored.</li>
  <li>In a real attack, a victim would click a link crafted by the attacker (e.g. in a
      phishing email) containing this payload, executing arbitrary JavaScript in the
      victim's authenticated session.</li>
</ol>
{% endblock %}

{% block live_example %}
```

Change it to:

```html
{% block detect %}
<p>
  Visit the page with <code>?name=&lt;b&gt;test&lt;/b&gt;</code> in the URL. If the word
  "test" renders bold instead of showing the literal text <code>&lt;b&gt;test&lt;/b&gt;</code>,
  your input is being interpreted as HTML rather than escaped — that alone confirms the
  injection point, before ever running JavaScript.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Visit this page with
      <code>?name=&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code>
      appended to the URL.</li>
  <li>The script executes in your browser as soon as the page loads — this is a
      <em>reflected</em> XSS because the payload comes straight from the URL and is
      never stored.</li>
  <li>In a real attack, a victim would click a link crafted by the attacker (e.g. in a
      phishing email) containing this payload, executing arbitrary JavaScript in the
      victim's authenticated session.</li>
</ol>
<p>
  Reflected XSS is a favorite in real phishing campaigns precisely because the malicious
  code lives entirely in a URL, not on the server — an attacker crafts a link, distributes
  it via email, social media, or a shortened URL, and the victim's own browser executes
  the payload the moment they click, inside their own authenticated session. This has been
  used in the wild to steal session cookies, silently perform actions as the victim, and
  pivot into full account takeover, all without ever compromising the server itself.
</p>
{% endblock %}

{% block vulnerable_code %}greeting_html = f"<p>Hello, {name}! Welcome back.</p>"
return render_template("greet.html", greeting_html=greeting_html, name=name)
# template: {% raw %}{{ greeting_html|safe }}{% endraw %}
{% endblock %}

{% block secure_code %}# Let Jinja's autoescaping do its job -- never build HTML by hand,
# never use |safe on user input
return render_template("greet.html", name=name)
# template: &lt;p&gt;Hello, {% raw %}{{ name }}{% endraw %}! Welcome back.&lt;/p&gt;
{% endblock %}

{% block live_example %}
```

- [ ] **Step 2: `comments.html` — add Detect and Vulnerable vs. Secure**

This example's fix is template-level (Jinja/HTML), not Python, so its code panels need `language-html` highlighting instead of the base template's `language-python` default. In `app/categories/a03_injection/templates/a03_injection/comments.html`, the top of the file currently reads:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Stored XSS in Comments" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A03{% endblock %}
```

Add a `code_language` override right after `example_difficulty`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Stored XSS in Comments" %}
{% set example_difficulty = "Hard" %}
{% set code_language = "html" %}
{% block title %}{{ example_title }} — A03{% endblock %}
```

Then, the file's `exploitation` block ends and `live_example` begins like this:

```html
{% block exploitation %}
<ol>
  <li>Submit a comment with the body:
      <code>&lt;script&gt;alert('stored XSS')&lt;/script&gt;</code></li>
  <li>Reload the page — the script executes immediately, with no link-clicking required.</li>
  <li>Every other visitor who loads this page from now on runs your script too, until
      "Reset lab" clears the comments table. A real attacker would use this to steal
      session cookies or perform actions as any visitor who views the page.</li>
</ol>
{% endblock %}

{% block live_example %}
```

Change it to:

```html
{% block detect %}
<p>
  Post a comment with the body <code>&lt;b&gt;test&lt;/b&gt;</code>. If it renders bold on
  the page instead of showing the literal tags, the comment body is being interpreted as
  HTML — and because it's stored, that confirmation persists for every future visitor, not
  just you.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Submit a comment with the body:
      <code>&lt;script&gt;alert('stored XSS')&lt;/script&gt;</code></li>
  <li>Reload the page — the script executes immediately, with no link-clicking required.</li>
  <li>Every other visitor who loads this page from now on runs your script too, until
      "Reset lab" clears the comments table. A real attacker would use this to steal
      session cookies or perform actions as any visitor who views the page.</li>
</ol>
<p>
  Stored XSS is considered more severe than reflected XSS precisely because it requires no
  social engineering at all — once the payload is saved, it fires automatically for every
  single visitor who loads the page, indefinitely. Real-world stored-XSS incidents have
  been used to build self-propagating worms (a payload that, when it runs, posts a copy of
  itself as a new comment or post, infecting every subsequent viewer) and to harvest
  session cookies at scale from an entire user base with zero further attacker interaction
  after the initial post.
</p>
{% endblock %}

{% block vulnerable_code %}{% raw %}<div>{{ comment.body|safe }}</div>{% endraw %}
{% endblock %}

{% block secure_code %}{% raw %}<div>{{ comment.body }}</div>{% endraw %}
{% endblock %}

{% block live_example %}
```

- [ ] **Step 3: `host_lookup.html` — add Detect and Vulnerable vs. Secure**

In `app/categories/a03_injection/templates/a03_injection/host_lookup.html`, the file currently ends its `exploitation` block and begins `live_example` like this:

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
{% endblock %}

{% block live_example %}
```

Change it to:

```html
{% block detect %}
<p>
  Try a lookup with a semicolon appended to a harmless hostname, e.g.
  <code>localhost;echo test</code>. If the output includes the word "test" anywhere, your
  input reached a real shell — the semicolon terminated the intended
  <code>getent</code> command and started a second one, which is all it takes to confirm
  command injection without running anything destructive.
</p>
{% endblock %}

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

{% block vulnerable_code %}result = subprocess.run(
    f"getent hosts {host}",
    shell=True,
    capture_output=True,
    text=True,
    timeout=10,
)
{% endblock %}

{% block secure_code %}result = subprocess.run(
    ["getent", "hosts", host],
    shell=False,
    capture_output=True,
    text=True,
    timeout=10,
)
{% endblock %}

{% block live_example %}
```

- [ ] **Step 4: Update `tests/test_a03_greet.py`**

Append to `tests/test_a03_greet.py`:

```python


def test_greet_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a03/greet")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"autoescaping" in response.data
```

- [ ] **Step 5: Update `tests/test_a03_comments.py`**

Append to `tests/test_a03_comments.py`:

```python


def test_comments_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a03/comments")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"comment.body|safe" in response.data
```

- [ ] **Step 6: Update `tests/test_a03_host_lookup.py`**

Append to `tests/test_a03_host_lookup.py`:

```python


def test_host_lookup_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a03/host-lookup")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"shell=False" in response.data
```

- [ ] **Step 7: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (135 + 3 = 138)

- [ ] **Step 8: Commit**

```bash
git add app/categories/a03_injection/templates/a03_injection/greet.html \
  app/categories/a03_injection/templates/a03_injection/comments.html \
  app/categories/a03_injection/templates/a03_injection/host_lookup.html \
  tests/test_a03_greet.py tests/test_a03_comments.py tests/test_a03_host_lookup.py
git commit -m "feat: add Detect and Vulnerable vs. Secure content to A03 XSS/command injection examples"
```

---

### Task 6: A04 — fill in Detect and Vulnerable vs. Secure for all 3 examples

**Files:**
- Modify: `app/categories/a04_insecure_design/templates/a04_insecure_design/coupon_cart.html`
- Modify: `app/categories/a04_insecure_design/templates/a04_insecure_design/quantity_cart.html`
- Modify: `app/categories/a04_insecure_design/templates/a04_insecure_design/checkout_shipping.html`
- Modify: `tests/test_a04_coupon_cart.py`
- Modify: `tests/test_a04_quantity_cart.py`
- Modify: `tests/test_a04_checkout.py`

**Interfaces:**
- Consumes: `detect`/`vulnerable_code`/`secure_code` blocks from Task 1.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: `coupon_cart.html` — add Detect and Vulnerable vs. Secure**

In `app/categories/a04_insecure_design/templates/a04_insecure_design/coupon_cart.html`, the file currently ends its `exploitation` block and begins `live_example` like this:

```html
{% block exploitation %}
<ol>
  <li>Enter the coupon code <code>WELCOME10</code> and submit it.</li>
  <li>Submit the exact same code again. And again.</li>
  <li>Each submission knocks another $5.00 off the price — keep going and the
      $29.99 mouse becomes free.</li>
</ol>
{% endblock %}

{% block live_example %}
```

Change it to:

```html
{% block detect %}
<p>
  Apply the <code>WELCOME10</code> code once and note the total. Apply it a second time.
  If the total drops again instead of the app rejecting the code as "already used," that's
  the whole detection step — no need to go further to confirm the missing usage check
  exists.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Enter the coupon code <code>WELCOME10</code> and submit it.</li>
  <li>Submit the exact same code again. And again.</li>
  <li>Each submission knocks another $5.00 off the price — keep going and the
      $29.99 mouse becomes free.</li>
</ol>
<p>
  Business-logic flaws like unlimited coupon or promo-code reuse are a well-documented
  category of real-world e-commerce abuse — automated scripts that just replay the same
  request in a loop have been used to drive real transactions to $0 or even negative
  totals. Unlike injection bugs, this class of flaw is often invisible to traditional
  vulnerability scanners: every individual request is perfectly well-formed, and the flaw
  is purely in the missing state tracking.
</p>
{% endblock %}

{% block vulnerable_code %}if submitted_code == COUPON_CODE:
    session["a04_coupon_uses"] = session.get("a04_coupon_uses", 0) + 1
{% endblock %}

{% block secure_code %}if submitted_code == COUPON_CODE and not session.get("a04_coupon_applied"):
    session["a04_coupon_applied"] = True
    discount_cents = COUPON_DISCOUNT_CENTS
# a real system also tracks this server-side per account/order, not just in a
# client-trusted session, so clearing cookies can't reset the usage count
{% endblock %}

{% block live_example %}
```

- [ ] **Step 2: `quantity_cart.html` — add Detect and Vulnerable vs. Secure**

In `app/categories/a04_insecure_design/templates/a04_insecure_design/quantity_cart.html`, the file currently ends its `exploitation` block and begins `live_example` like this:

```html
{% block exploitation %}
<ol>
  <li>Set the quantity field to <code>-1</code> and submit.</li>
  <li>The total now reads <code>-$29.99</code> — a negative charge that a real payment
      processor might interpret as a refund.</li>
</ol>
{% endblock %}

{% block live_example %}
```

Change it to:

```html
{% block detect %}
<p>
  Set the quantity field to <code>-1</code> and submit. If the total goes negative instead
  of the app rejecting a nonsensical quantity, that confirms there's no bounds validation
  — no need to go further to prove the bug exists.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Set the quantity field to <code>-1</code> and submit.</li>
  <li>The total now reads <code>-$29.99</code> — a negative charge that a real payment
      processor might interpret as a refund.</li>
</ol>
<p>
  Missing bounds validation on quantity or price-affecting fields is a recurring
  real-world e-commerce bug class — a negative quantity that a downstream payment
  processor interprets literally can trigger an actual refund or credit instead of a
  charge, and this exact category of flaw has resulted in real financial loss in
  production systems that trusted client-submitted numeric fields without server-side
  range checks.
</p>
{% endblock %}

{% block vulnerable_code %}try:
    quantity = int(request.form.get("quantity", "1"))
except (ValueError, OverflowError):
    quantity = 1
session["a04_quantity"] = quantity
{% endblock %}

{% block secure_code %}try:
    quantity = int(request.form.get("quantity", "1"))
except (ValueError, OverflowError):
    quantity = 1
quantity = max(1, min(quantity, 99))  # clamp to a sane, positive range
session["a04_quantity"] = quantity
{% endblock %}

{% block live_example %}
```

- [ ] **Step 3: `checkout_shipping.html` — add Detect and Vulnerable vs. Secure**

In `app/categories/a04_insecure_design/templates/a04_insecure_design/checkout_shipping.html`, the file currently ends its `exploitation` block and begins `live_example` like this:

```html
{% block exploitation %}
<ol>
  <li>You could go through the normal flow below: Shipping → Payment → Confirm.</li>
  <li>Or skip straight to
      <a href="{{ url_for('a04_insecure_design.checkout_confirm') }}">the confirmation page</a>
      without ever visiting shipping or payment.</li>
  <li>Either way, you land on a "confirmed" order — but only the first path actually
      charged anything. The skipped order is created with <code>paid = False</code>.</li>
</ol>
{% endblock %}

{% block live_example %}
```

Change it to:

```html
{% block detect %}
<p>
  Without going through shipping or payment at all, navigate directly to
  <a href="{{ url_for('a04_insecure_design.checkout_confirm') }}">the confirmation page</a>.
  If you land on a "Thank you for your order!" page anyway, that confirms the server never
  checks that the earlier steps happened — you don't need to look at the order's paid
  status yet to know the flow itself is unenforced.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>You could go through the normal flow below: Shipping → Payment → Confirm.</li>
  <li>Or skip straight to
      <a href="{{ url_for('a04_insecure_design.checkout_confirm') }}">the confirmation page</a>
      without ever visiting shipping or payment.</li>
  <li>Either way, you land on a "confirmed" order — but only the first path actually
      charged anything. The skipped order is created with <code>paid = False</code>.</li>
</ol>
<p>
  Workflow/state bypass is a hallmark A04 finding precisely because each individual step
  is implemented correctly in isolation — the payment page really does charge correctly
  when used normally. The flaw is that no step actually depends on the previous one having
  happened. In real checkout, booking, or approval flows, this class of bug has let
  attackers skip payment steps entirely, jump straight to a "confirmed" or "approved"
  state, or bypass required verification/moderation steps by simply requesting the
  final-state URL directly.
</p>
{% endblock %}

{% block vulnerable_code %}@a04_bp.route("/checkout/confirm")
def checkout_confirm():
    order_id = session.get("a04_order_id")
    order = db.session.get(Order, order_id) if order_id else None
    if order is None:
        order = Order(total_cents=DEMO_PRODUCT_PRICE_CENTS, paid=False)
        db.session.add(order)
        db.session.commit()
        session["a04_order_id"] = order.id
    ...
{% endblock %}

{% block secure_code %}@a04_bp.route("/checkout/confirm")
def checkout_confirm():
    order_id = session.get("a04_order_id")
    order = db.session.get(Order, order_id) if order_id else None
    if order is None or not order.paid:
        abort(400)  # no valid, paid order in this session -- can't confirm
    ...
{% endblock %}

{% block live_example %}
```

- [ ] **Step 4: Update `tests/test_a04_coupon_cart.py`**

Append to `tests/test_a04_coupon_cart.py`:

```python


def test_coupon_cart_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a04/coupon-cart")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"a04_coupon_applied" in response.data
```

- [ ] **Step 5: Update `tests/test_a04_quantity_cart.py`**

Append to `tests/test_a04_quantity_cart.py`:

```python


def test_quantity_cart_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a04/quantity-cart")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"min(quantity, 99)" in response.data
```

- [ ] **Step 6: Update `tests/test_a04_checkout.py`**

Append to `tests/test_a04_checkout.py`:

```python


def test_checkout_shipping_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a04/checkout/shipping")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"not order.paid" in response.data
```

- [ ] **Step 7: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (138 + 3 = 141)

- [ ] **Step 8: Commit**

```bash
git add app/categories/a04_insecure_design/templates/a04_insecure_design/coupon_cart.html \
  app/categories/a04_insecure_design/templates/a04_insecure_design/quantity_cart.html \
  app/categories/a04_insecure_design/templates/a04_insecure_design/checkout_shipping.html \
  tests/test_a04_coupon_cart.py tests/test_a04_quantity_cart.py tests/test_a04_checkout.py
git commit -m "feat: add Detect and Vulnerable vs. Secure content to A04 examples"
```

---

### Task 7: Full regression + Docker verification

**Files:**
- None (verification-only task; no code changes expected).

**Interfaces:**
- Consumes: nothing new (verifies Tasks 1–6's combined output).
- Produces: nothing — this is the final task.

- [ ] **Step 1: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (141 tests)

- [ ] **Step 2: Docker end-to-end verification**

```bash
docker compose up --build -d
```

Then, via curl against the live container (`http://127.0.0.1:5001`), for a representative sample across all 4 categories (not all 15 — spot-check is sufficient given every example follows an identical mechanical pattern verified by the task-level tests):

- `/a01/profile/1`, `/a02/credential-dump`, `/a03/login`, `/a04/coupon-cart` each return 200 and contain `Vulnerable vs. Secure` in the raw HTML.
- With `show_exploit_instructions` toggled off via `/settings`, re-fetch `/a01/profile/1` and confirm `Detect` is absent but `Vulnerable vs. Secure` is still present.
- Toggle `show_exploit_instructions` back on and confirm `Detect` reappears.
- `/force-reset` still resets cleanly with all the new content in place.

If you have a browser tool available, additionally visit two or three example pages across different categories and visually confirm: the Detect section reads as a distinct, lighter-weight step before Exploitation (not a duplicate of it), the Vulnerable vs. Secure code panel renders with the same line-numbered, dark-mode-aware highlighting as the Overview pages' code panels (verifying Task 1's new block reuses the existing highlight.js/line-numbers pipeline correctly, since it wasn't explicitly re-tested at the task level), and nothing looks visually broken with both toggles off. If no browser tool is available, note that as a known gap in your report rather than skipping the curl-based checks above.

Tear down cleanly afterward:

```bash
docker compose down
```

- [ ] **Step 3: Commit**

No code changes are expected from this task. If the Docker/curl verification finds nothing to fix, there is nothing to commit — report DONE with the verification evidence in your report file rather than an empty commit.
