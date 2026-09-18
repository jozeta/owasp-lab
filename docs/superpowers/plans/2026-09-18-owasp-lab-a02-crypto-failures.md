# A02 Cryptographic Failures Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the second OWASP category — A02 Cryptographic Failures — to the training lab: an Overview page plus three graduated, genuinely exploitable examples (unsalted MD5 credential dump, hardcoded-key AES-ECB weak encryption, predictable password-reset token) built on a shared, category-owned `LegacyCredential` scenario.

**Architecture:** A new Flask Blueprint (`app/categories/a02_crypto_failures`) following the exact reference pattern A01 established: a `__init__.py` that creates the blueprint and appends a `CategoryNav` entry (all 3 examples pre-registered, letting the existing `registered_endpoints` nav guard self-resolve links as routes land task-by-task), a category-owned model (`LegacyCredential`) seeded via the existing `CategoryNav.seed_fn` hook (already dispatched by `app/core/seed.py` — no core changes needed), and example pages extending the existing `core/example_page_base.html`/`core/overview_base.html` shared templates. Unlike A01, none of A02's example routes require a login — the vulnerabilities here are about data-at-rest/in-transit weakness, not access control, so they're publicly reachable, mirroring realistic "leaked backup" / "public reset endpoint" scenarios.

**Tech Stack:** Same as the existing app (Flask 3, Flask-SQLAlchemy, pytest) plus one new dependency: `pycryptodome` for the AES-ECB example.

**Spec:** `docs/superpowers/specs/2026-09-18-owasp-lab-design.md`

**Prior work this builds on:** `docs/superpowers/plans/2026-09-18-owasp-lab-scaffold-core-a01.md` (merged to `main`) — read `app/categories/a01_access_control/` for the reference pattern this plan mirrors exactly.

## Global Constraints

- App must bind only to `127.0.0.1` on the host (already true — no docker-compose/Dockerfile changes in this plan).
- Only synthetic/dummy data — `LegacyCredential` reuses the existing seeded users' usernames/passwords (already synthetic, `@example.test` accounts), just hashed differently.
- The app container runs as a non-root user (already true — no changes).
- Settings toggles (`show_explanations`, `show_exploit_instructions`) apply to every example page — every A02 example must extend `app/core/templates/core/example_page_base.html`, exactly like A01's three examples do.
- Each example's Explanation/Exploitation sections must be independently toggle-gated, and hiding them must never disable the underlying vulnerability.
- Static assets stay vendored/offline — this plan adds a Python dependency (`pycryptodome`), not a frontend asset, so no vendoring changes needed.
- No shared fictional brand across categories — A02's three examples share an internal scenario (the same `LegacyCredential` data) with each other, but nothing crosses over from A01.
- The shared core `User`/`SEED_USERS` data may be read (not modified) by category code that needs identity data — A02's seed function imports `SEED_USERS` from `app.core.seed` read-only.
- `app/core` must never contain vulnerable logic — all of A02's vulnerable code lives in `app/categories/a02_crypto_failures`.

---

### Task 1: A02 blueprint scaffold + Overview page

**Files:**
- Create: `app/categories/a02_crypto_failures/__init__.py`
- Create: `app/categories/a02_crypto_failures/routes.py`
- Create: `app/categories/a02_crypto_failures/templates/a02_crypto_failures/overview.html`
- Modify: `app/__init__.py`
- Create: `tests/test_a02_overview.py`

**Interfaces:**
- Consumes: `CATEGORIES`, `CategoryNav`, `ExampleNav` (`app/core/nav.py`); `core/overview_base.html`.
- Produces: `a02_bp` Blueprint mounted at `/a02` with route `a02_crypto_failures.overview` (GET `/a02/`); appends A02's `CategoryNav` (3 examples, endpoints referencing routes added in Tasks 3–5 — `a02_crypto_failures.credential_dump`, `a02_crypto_failures.encrypted_notes`, `a02_crypto_failures.forgot_password`, none of which take URL parameters, so no A01-`idor`-style zero-arg routing fix is needed here) to `CATEGORIES` on import.

- [ ] **Step 1: Write the failing test**

`tests/test_a02_overview.py`:
```python
def test_a02_overview_renders(client):
    response = client.get("/a02/")
    assert response.status_code == 200
    assert b"Cryptographic Failures" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a02_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a02 = next(c for c in CATEGORIES if c.id == "a02_crypto_failures")
    assert a02.short_id == "A02"
    assert [e.difficulty for e in a02.examples] == ["Easy", "Medium", "Hard"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a02_overview.py -v`
Expected: FAIL with 404 on `/a02/`.

- [ ] **Step 3: Write `app/categories/a02_crypto_failures/__init__.py`**

```python
from flask import Blueprint

a02_bp = Blueprint(
    "a02_crypto_failures", __name__, template_folder="templates", url_prefix="/a02"
)

from app.categories.a02_crypto_failures import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a02_crypto_failures",
        short_id="A02",
        title="Cryptographic Failures",
        blueprint_name="a02_crypto_failures",
        overview_endpoint="a02_crypto_failures.overview",
        examples=[
            ExampleNav(
                id="credential-dump",
                title="Leaked Credential Dump",
                difficulty="Easy",
                endpoint="a02_crypto_failures.credential_dump",
            ),
            ExampleNav(
                id="encrypted-notes",
                title="Weak Encryption (ECB Mode)",
                difficulty="Medium",
                endpoint="a02_crypto_failures.encrypted_notes",
            ),
            ExampleNav(
                id="reset-token",
                title="Predictable Password Reset Token",
                difficulty="Hard",
                endpoint="a02_crypto_failures.forgot_password",
            ),
        ],
    )
)
```

- [ ] **Step 4: Write `app/categories/a02_crypto_failures/routes.py`**

```python
from flask import render_template

from app.categories.a02_crypto_failures import a02_bp


@a02_bp.route("/")
def overview():
    return render_template("a02_crypto_failures/overview.html")
```

(routes for `credential_dump`, `encrypted_notes`, `forgot_password`/`reset_password`/`legacy_login` are added in Tasks 3–5)

- [ ] **Step 5: Write `app/categories/a02_crypto_failures/templates/a02_crypto_failures/overview.html`**

```html
{% extends "core/overview_base.html" %}
{% set category_short_id = "A02" %}
{% set category_title = "Cryptographic Failures" %}
{% block title %}A02: Cryptographic Failures{% endblock %}

{% block what_it_is %}
<p>
  Cryptographic Failures happen when sensitive data isn't protected the way it should be —
  passwords stored in plaintext or weak unsalted hashes, encryption done with hardcoded
  keys or modes that leak patterns, and tokens generated by predictable algorithms instead
  of a secure random source.
</p>
{% endblock %}

{% block why_it_matters %}
<p>
  A single weak cryptographic choice can undo every other security control in an app.
  It doesn't matter how well access control is enforced if the data itself is trivially
  recoverable once an attacker gets hold of it — a database backup, a config file, or a
  predictable token is often all they need.
</p>
{% endblock %}

{% block how_exploited %}
<p>
  Attackers rarely need to "break" real cryptography. They look for shortcuts: unsalted
  hashes crackable with a rainbow table in seconds, encryption keys hardcoded in source
  code or config files, and tokens generated from predictable inputs (a username, a
  timestamp, a fixed secret) that can be recomputed offline without ever touching the
  real system.
</p>
{% endblock %}

{% block attack_flow_diagram %}
sequenceDiagram
    participant Attacker
    participant App as Vulnerable App
    participant DB as Database
    Attacker->>App: Obtain a leaked credential dump or config file
    App-->>Attacker: Unsalted MD5 hashes / hardcoded AES key
    Attacker->>Attacker: Crack hash with a rainbow table, or decrypt with the known key
    Attacker->>App: Log in with the recovered plaintext credential
    App->>DB: Authenticate as the victim
    DB-->>App: Access granted
{% endblock %}

{% block real_world_impact %}
<p>
  Real incidents in this category include mass credential-stuffing campaigns built on
  cracked unsalted password dumps, and encrypted-data breaches where a hardcoded key
  found in a public repository or decompiled binary unlocked years of "encrypted" backups
  in minutes.
</p>
{% endblock %}

{% block vulnerable_code %}password_hash = hashlib.md5(password.encode()).hexdigest()
# Fast, unsalted, crackable in seconds with a rainbow table.
{% endblock %}

{% block secure_code %}from werkzeug.security import generate_password_hash

password_hash = generate_password_hash(password)
# Salted, slow, resistant to offline cracking.
{% endblock %}
```

- [ ] **Step 6: Modify `app/__init__.py`** — register the A02 blueprint after the A01 registration

```python
    from app.categories.a01_access_control import a01_bp

    app.register_blueprint(a01_bp)

    from app.categories.a02_crypto_failures import a02_bp

    app.register_blueprint(a02_bp)

    @app.route("/healthz")
```

- [ ] **Step 7: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass (including the two new A02 tests), 0 warnings, and the full previous suite (A01 + framework) stays green.

- [ ] **Step 8: Commit**

```bash
git add app/categories/a02_crypto_failures app/__init__.py tests/test_a02_overview.py
git commit -m "feat: add A02 blueprint scaffold and overview page"
```

---

### Task 2: LegacyCredential model + seed wiring

**Files:**
- Create: `app/categories/a02_crypto_failures/models.py`
- Create: `app/categories/a02_crypto_failures/seed.py`
- Modify: `app/categories/a02_crypto_failures/__init__.py`
- Create: `tests/test_a02_credentials.py`

**Interfaces:**
- Consumes: `db` (`app.extensions`); `SEED_USERS`, `seed_database`, `reset_database` (`app.core.seed`).
- Produces: `LegacyCredential` model (`id`, `username` unique, `weak_password_hash` — 32-char MD5 hex) in `app.categories.a02_crypto_failures.models`; `seed_legacy_credentials() -> None` in `app.categories.a02_crypto_failures.seed`, wired as `CategoryNav.seed_fn` so `app/core/seed.py`'s existing `seed_database()`/`reset_database()` loop seeds and resets it automatically — no core code changes. Consumed by Tasks 3–5's routes.

- [ ] **Step 1: Write the failing test**

`tests/test_a02_credentials.py`:
```python
import hashlib

from app.categories.a02_crypto_failures.models import LegacyCredential
from app.core.seed import SEED_USERS, reset_database, seed_database
from app.extensions import db


def test_seed_legacy_credentials_creates_md5_hashes(app):
    seed_database(app)
    with app.app_context():
        credentials = {c.username: c.weak_password_hash for c in LegacyCredential.query.all()}
        assert set(credentials) == {u["username"] for u in SEED_USERS}
        for entry in SEED_USERS:
            expected = hashlib.md5(entry["password"].encode()).hexdigest()
            assert credentials[entry["username"]] == expected


def test_seed_legacy_credentials_is_idempotent(app):
    seed_database(app)
    seed_database(app)
    with app.app_context():
        assert LegacyCredential.query.count() == 4


def test_reset_database_restores_legacy_credentials(app):
    seed_database(app)
    with app.app_context():
        alice = LegacyCredential.query.filter_by(username="alice").first()
        alice.weak_password_hash = "tampered"
        db.session.commit()

    reset_database(app)

    with app.app_context():
        alice = LegacyCredential.query.filter_by(username="alice").first()
        expected_password = next(u for u in SEED_USERS if u["username"] == "alice")["password"]
        assert alice.weak_password_hash == hashlib.md5(expected_password.encode()).hexdigest()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a02_credentials.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.categories.a02_crypto_failures.models'`.

- [ ] **Step 3: Write `app/categories/a02_crypto_failures/models.py`**

```python
from app.extensions import db


class LegacyCredential(db.Model):
    __tablename__ = "legacy_credentials"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    weak_password_hash = db.Column(db.String(32), nullable=False)
```

- [ ] **Step 4: Write `app/categories/a02_crypto_failures/seed.py`**

```python
import hashlib

from app.categories.a02_crypto_failures.models import LegacyCredential
from app.core.seed import SEED_USERS
from app.extensions import db


def seed_legacy_credentials():
    if LegacyCredential.query.count() == 0:
        for entry in SEED_USERS:
            db.session.add(
                LegacyCredential(
                    username=entry["username"],
                    weak_password_hash=hashlib.md5(entry["password"].encode()).hexdigest(),
                )
            )
        db.session.commit()
```

- [ ] **Step 5: Modify `app/categories/a02_crypto_failures/__init__.py`** — wire the seed function into the `CategoryNav` entry

Add this import alongside the existing nav import:
```python
from app.categories.a02_crypto_failures.seed import seed_legacy_credentials  # noqa: E402
```
Then add `seed_fn=seed_legacy_credentials,` as the last argument to the `CategoryNav(...)` call (after the `examples=[...]` block), so the constructor call reads:
```python
CATEGORIES.append(
    CategoryNav(
        id="a02_crypto_failures",
        short_id="A02",
        title="Cryptographic Failures",
        blueprint_name="a02_crypto_failures",
        overview_endpoint="a02_crypto_failures.overview",
        examples=[
            # ... unchanged from Task 1 ...
        ],
        seed_fn=seed_legacy_credentials,
    )
)
```

- [ ] **Step 6: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass, 0 warnings.

- [ ] **Step 7: Commit**

```bash
git add app/categories/a02_crypto_failures/models.py app/categories/a02_crypto_failures/seed.py \
  app/categories/a02_crypto_failures/__init__.py tests/test_a02_credentials.py
git commit -m "feat: add LegacyCredential model and seed wiring for A02"
```

---

### Task 3: A02 Easy — Leaked Credential Dump

**Files:**
- Modify: `app/categories/a02_crypto_failures/routes.py`
- Create: `app/categories/a02_crypto_failures/templates/a02_crypto_failures/credential_dump.html`
- Create: `tests/test_a02_credential_dump.py`

**Interfaces:**
- Consumes: `LegacyCredential` (Task 2).
- Produces: route `a02_crypto_failures.credential_dump` (GET `/a02/credential-dump`, no login required).

- [ ] **Step 1: Write the failing test**

`tests/test_a02_credential_dump.py`:
```python
from app.core.seed import seed_database


def test_credential_dump_lists_all_legacy_credentials(app, client):
    seed_database(app)

    response = client.get("/a02/credential-dump")
    assert response.status_code == 200
    assert b"alice" in response.data
    assert b"admin" in response.data


def test_credential_dump_link_appears_in_overview_once_registered(client):
    response = client.get("/a02/")
    assert response.status_code == 200
    assert b"Leaked Credential Dump" in response.data
    assert b'href="/a02/credential-dump"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a02_credential_dump.py -v`
Expected: FAIL with 404 on `/a02/credential-dump`.

- [ ] **Step 3: Modify `app/categories/a02_crypto_failures/routes.py`** — add the import and the route

```python
from flask import render_template

from app.categories.a02_crypto_failures import a02_bp
from app.categories.a02_crypto_failures.models import LegacyCredential


@a02_bp.route("/")
def overview():
    return render_template("a02_crypto_failures/overview.html")


@a02_bp.route("/credential-dump")
def credential_dump():
    credentials = LegacyCredential.query.order_by(LegacyCredential.username).all()
    return render_template("a02_crypto_failures/credential_dump.html", credentials=credentials)
```

- [ ] **Step 4: Write `app/categories/a02_crypto_failures/templates/a02_crypto_failures/credential_dump.html`**

Note: do NOT link to `/a02/legacy-login` in this file yet — that route doesn't exist until Task 5. Task 5 will modify this file to add that link once it's safe to reference.

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Leaked Credential Dump" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A02{% endblock %}

{% block explanation %}
<p>
  This page simulates a leaked database backup — a legacy export that was never
  properly secured. Passwords in it are stored as unsalted MD5 hashes, a format that's
  been considered broken for password storage for well over a decade: no salt means two
  identical passwords produce identical hashes, and MD5 is fast enough that a modern GPU
  can try billions of guesses per second.
</p>
<p>Impact here: anyone who can reach this page can crack every password in seconds using
  a public rainbow table.</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Copy one of the <code>weak_password_hash</code> values below.</li>
  <li>Paste it into any online MD5 lookup / rainbow-table site (search
      "md5 decrypt" and paste the hash).</li>
  <li>The plaintext password comes back instantly — MD5 offers no protection here.</li>
</ol>
{% endblock %}

{% block live_example %}
<table class="table">
  <thead><tr><th>Username</th><th>weak_password_hash (MD5)</th></tr></thead>
  <tbody>
    {% for credential in credentials %}
    <tr>
      <td>{{ credential.username }}</td>
      <td><code>{{ credential.weak_password_hash }}</code></td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endblock %}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add app/categories/a02_crypto_failures/routes.py \
  app/categories/a02_crypto_failures/templates/a02_crypto_failures/credential_dump.html \
  tests/test_a02_credential_dump.py
git commit -m "feat: add A02 Easy credential dump example"
```

---

### Task 4: A02 Medium — Weak Encryption (ECB Mode)

**Files:**
- Create: `app/categories/a02_crypto_failures/crypto.py`
- Modify: `app/categories/a02_crypto_failures/routes.py`
- Create: `app/categories/a02_crypto_failures/templates/a02_crypto_failures/encrypted_notes.html`
- Modify: `requirements.txt`
- Create: `tests/test_a02_encrypted_notes.py`

**Interfaces:**
- Produces: `encrypt_ecb(plaintext: str) -> str` and `decrypt_ecb(ciphertext_hex: str) -> str` in `app.categories.a02_crypto_failures.crypto` (hex-encoded AES-128-ECB with a hardcoded key, PKCS7 padding); route `a02_crypto_failures.encrypted_notes` (GET/POST `/a02/encrypted-notes`, no login required). No persisted model — ciphertext is computed at request time from a static, in-code `SECURITY_ANSWERS` list (deterministic ECB output needs no storage).

- [ ] **Step 1: Write the failing test**

`tests/test_a02_encrypted_notes.py`:
```python
from app.core.seed import seed_database


def test_encrypted_notes_shows_identical_ciphertext_for_shared_answer(app, client):
    seed_database(app)

    response = client.get("/a02/encrypted-notes")
    assert response.status_code == 200

    from app.categories.a02_crypto_failures.crypto import encrypt_ecb

    shared_ciphertext = encrypt_ecb("Rex")
    assert response.data.count(shared_ciphertext.encode()) == 2


def test_encrypted_notes_decrypt_tool_recovers_plaintext(client):
    from app.categories.a02_crypto_failures.crypto import encrypt_ecb

    ciphertext_hex = encrypt_ecb("Rex")

    response = client.post("/a02/encrypted-notes", data={"ciphertext_hex": ciphertext_hex})
    assert response.status_code == 200
    assert b"Rex" in response.data


def test_encrypted_notes_link_appears_in_overview_once_registered(client):
    response = client.get("/a02/")
    assert response.status_code == 200
    assert b"Weak Encryption (ECB Mode)" in response.data
    assert b'href="/a02/encrypted-notes"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a02_encrypted_notes.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.categories.a02_crypto_failures.crypto'`.

- [ ] **Step 3: Add `pycryptodome` to `requirements.txt`**

```
Flask==3.0.3
Flask-SQLAlchemy==3.1.1
psycopg[binary]==3.2.1
gunicorn==22.0.0
python-dotenv==1.0.1
pytest==8.2.2
pycryptodome==3.20.0
```

Then install it into the existing dev venv: `.venv/bin/pip install pycryptodome==3.20.0` (or `pip install -r requirements.txt` again — idempotent).

- [ ] **Step 4: Write `app/categories/a02_crypto_failures/crypto.py`**

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

AES_KEY = b"0123456789abcdef"  # 16 bytes -- hardcoded on purpose, this IS the vulnerability


def encrypt_ecb(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded = pad(plaintext.encode(), AES.block_size)
    return cipher.encrypt(padded).hex()


def decrypt_ecb(ciphertext_hex):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded = cipher.decrypt(bytes.fromhex(ciphertext_hex))
    return unpad(padded, AES.block_size).decode()
```

- [ ] **Step 5: Modify `app/categories/a02_crypto_failures/routes.py`** — add imports, the seeded answer list, and the route

```python
from flask import render_template, request

from app.categories.a02_crypto_failures import a02_bp
from app.categories.a02_crypto_failures.crypto import decrypt_ecb, encrypt_ecb
from app.categories.a02_crypto_failures.models import LegacyCredential

SECURITY_ANSWERS = [
    ("alice", "Rex"),
    ("bob", "Milo"),
    ("carol", "Rex"),
    ("admin", "Shadow"),
]


@a02_bp.route("/encrypted-notes", methods=["GET", "POST"])
def encrypted_notes():
    encrypted_rows = [(username, encrypt_ecb(answer)) for username, answer in SECURITY_ANSWERS]
    decrypted_result = None
    decrypt_error = None
    if request.method == "POST":
        ciphertext_hex = request.form.get("ciphertext_hex", "").strip()
        try:
            decrypted_result = decrypt_ecb(ciphertext_hex)
        except Exception:
            decrypt_error = "Could not decrypt that value — check the hex string."
    return render_template(
        "a02_crypto_failures/encrypted_notes.html",
        encrypted_rows=encrypted_rows,
        decrypted_result=decrypted_result,
        decrypt_error=decrypt_error,
    )
```

(the `overview` and `credential_dump` routes above this stay unchanged)

- [ ] **Step 6: Write `app/categories/a02_crypto_failures/templates/a02_crypto_failures/encrypted_notes.html`**

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Weak Encryption (ECB Mode)" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A02{% endblock %}

{% block explanation %}
<p>
  Each user's security-question answer below is "encrypted" with AES in ECB mode using a
  key hardcoded directly in the application's source code: <code>b"0123456789abcdef"</code>.
  ECB mode encrypts each 16-byte block independently, so identical plaintext blocks always
  produce identical ciphertext blocks — patterns in the plaintext leak straight through to
  the ciphertext. And because the key is hardcoded, anyone with access to the source code
  (a leaked repo, a decompiled binary, a misconfigured backup) can decrypt everything
  instantly, no cryptanalysis required.
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
{% endblock %}

{% block live_example %}
<table class="table">
  <thead><tr><th>Username</th><th>Encrypted answer (hex)</th></tr></thead>
  <tbody>
    {% for username, ciphertext_hex in encrypted_rows %}
    <tr>
      <td>{{ username }}</td>
      <td><code>{{ ciphertext_hex }}</code></td>
    </tr>
    {% endfor %}
  </tbody>
</table>

<hr>

<h6>Decrypt tool</h6>
<form method="post">
  <div class="mb-2">
    <label class="form-label">Ciphertext (hex)</label>
    <input type="text" class="form-control" name="ciphertext_hex" placeholder="paste a hex value from the table above">
  </div>
  <button type="submit" class="btn btn-primary">Decrypt</button>
</form>
{% if decrypted_result %}
<p class="mt-3">Decrypted plaintext: <strong>{{ decrypted_result }}</strong></p>
{% endif %}
{% if decrypt_error %}
<p class="mt-3 text-danger">{{ decrypt_error }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 7: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass, 0 warnings.

- [ ] **Step 8: Commit**

```bash
git add app/categories/a02_crypto_failures/crypto.py app/categories/a02_crypto_failures/routes.py \
  app/categories/a02_crypto_failures/templates/a02_crypto_failures/encrypted_notes.html \
  requirements.txt tests/test_a02_encrypted_notes.py
git commit -m "feat: add A02 Medium weak-encryption (ECB) example"
```

---

### Task 5: A02 Hard — Predictable Password Reset Token (+ legacy login)

**Files:**
- Modify: `app/categories/a02_crypto_failures/routes.py`
- Create: `app/categories/a02_crypto_failures/templates/a02_crypto_failures/forgot_password.html`
- Create: `app/categories/a02_crypto_failures/templates/a02_crypto_failures/reset_password.html`
- Create: `app/categories/a02_crypto_failures/templates/a02_crypto_failures/legacy_login.html`
- Modify: `app/categories/a02_crypto_failures/templates/a02_crypto_failures/credential_dump.html`
- Create: `tests/test_a02_reset_token.py`

**Interfaces:**
- Consumes: `LegacyCredential`, `db` (Task 2).
- Produces: `RESET_TOKEN_SALT` (module constant) and `generate_reset_token(username: str) -> str` in `app.categories.a02_crypto_failures.routes`; routes `a02_crypto_failures.forgot_password` (GET/POST `/a02/forgot-password`), `a02_crypto_failures.reset_password` (GET/POST `/a02/reset-password/<token>`), `a02_crypto_failures.legacy_login` (GET/POST `/a02/legacy-login`, no login required, not registered in `CATEGORIES` — a shared utility route, not a graduated example itself).

- [ ] **Step 1: Write the failing test**

`tests/test_a02_reset_token.py`:
```python
import hashlib

from app.core.seed import seed_database


def _token_for(username):
    from app.categories.a02_crypto_failures.routes import RESET_TOKEN_SALT

    return hashlib.md5(f"{username}:{RESET_TOKEN_SALT}".encode()).hexdigest()[:10]


def test_forgot_password_does_not_reveal_token(app, client):
    seed_database(app)

    response = client.post("/a02/forgot-password", data={"username": "admin"})
    assert response.status_code == 200
    assert _token_for("admin").encode() not in response.data


def test_predictable_token_allows_password_reset_and_takeover(app, client):
    seed_database(app)

    token = _token_for("admin")
    reset_response = client.post(
        f"/a02/reset-password/{token}",
        data={"new_password": "hacked123"},
    )
    assert reset_response.status_code == 200
    assert b"Password updated" in reset_response.data

    login_response = client.post(
        "/a02/legacy-login",
        data={"username": "admin", "password": "hacked123"},
    )
    assert b"takeover confirmed" in login_response.data


def test_reset_password_rejects_invalid_token(app, client):
    seed_database(app)

    response = client.post(
        "/a02/reset-password/not-a-real-token",
        data={"new_password": "whatever"},
    )
    assert response.status_code == 200
    assert b"invalid or expired" in response.data


def test_reset_token_link_appears_in_overview_once_registered(client):
    response = client.get("/a02/")
    assert response.status_code == 200
    assert b"Predictable Password Reset Token" in response.data
    assert b'href="/a02/forgot-password"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a02_reset_token.py -v`
Expected: FAIL with `ImportError` (no `RESET_TOKEN_SALT` in routes.py yet) / 404s.

- [ ] **Step 3: Modify `app/categories/a02_crypto_failures/routes.py`** — add imports, token helper, and the three routes

```python
import hashlib

from app.extensions import db

RESET_TOKEN_SALT = "resetSalt2024"


def generate_reset_token(username):
    return hashlib.md5(f"{username}:{RESET_TOKEN_SALT}".encode()).hexdigest()[:10]


@a02_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    submitted = request.method == "POST"
    return render_template("a02_crypto_failures/forgot_password.html", submitted=submitted)


@a02_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
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
    return render_template(
        "a02_crypto_failures/reset_password.html", token=token, error=error, success=success
    )


@a02_bp.route("/legacy-login", methods=["GET", "POST"])
def legacy_login():
    result = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        credential = LegacyCredential.query.filter_by(username=username).first()
        if credential and hashlib.md5(password.encode()).hexdigest() == credential.weak_password_hash:
            result = "success"
        else:
            result = "failure"
    return render_template("a02_crypto_failures/legacy_login.html", result=result)
```

(add these three routes and the `import hashlib` / `from app.extensions import db` / `RESET_TOKEN_SALT` / `generate_reset_token` after the existing `overview`, `credential_dump`, and `encrypted_notes` routes — those stay unchanged)

- [ ] **Step 4: Write `app/categories/a02_crypto_failures/templates/a02_crypto_failures/forgot_password.html`**

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Predictable Password Reset Token" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A02{% endblock %}

{% block explanation %}
<p>
  This "forgot password" flow generates a reset token as
  <code>md5(f"{username}:{RESET_TOKEN_SALT}")[:10]</code>, where
  <code>RESET_TOKEN_SALT</code> is the hardcoded string <code>"resetSalt2024"</code> — never
  rotated, identical for every request. Because the token depends only on public
  information (a username) and a fixed secret, it's fully deterministic: anyone who knows
  the algorithm can compute any account's token offline, without ever receiving an email.
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
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Username</label>
    <input type="text" class="form-control" name="username" placeholder="e.g. alice">
  </div>
  <button type="submit" class="btn btn-primary">Send reset link</button>
</form>
{% if submitted %}
<p class="mt-3">If that account exists, a password reset link has been sent to the address on file.</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 5: Write `app/categories/a02_crypto_failures/templates/a02_crypto_failures/reset_password.html`**

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Predictable Password Reset Token" %}
{% set example_difficulty = "Hard" %}
{% block title %}Reset Password — A02{% endblock %}

{% block explanation %}
<p>See the <a href="{{ url_for('a02_crypto_failures.forgot_password') }}">forgot-password page</a>
  for how this token was derived.</p>
{% endblock %}

{% block exploitation %}
<p>Submit a new password below using a token you computed offline.</p>
{% endblock %}

{% block live_example %}
<p>Token: <code>{{ token }}</code></p>
{% if error %}
<p class="text-danger">{{ error }}</p>
{% elif success %}
<p class="text-success">Password updated. Try logging in at
  <a href="{{ url_for('a02_crypto_failures.legacy_login') }}">the legacy login page</a>.</p>
{% else %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">New password</label>
    <input type="text" class="form-control" name="new_password">
  </div>
  <button type="submit" class="btn btn-primary">Reset password</button>
</form>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Write `app/categories/a02_crypto_failures/templates/a02_crypto_failures/legacy_login.html`**

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Legacy Login (proof of takeover)" %}
{% set example_difficulty = "Hard" %}
{% block title %}Legacy Login — A02{% endblock %}

{% block explanation %}
<p>
  A small standalone login form checking credentials against the same
  <code>LegacyCredential</code> table used by the credential-dump and password-reset
  examples on this page — use it to prove a cracked or reset password actually works.
</p>
{% endblock %}

{% block exploitation %}
<p>Log in with a password you cracked from the credential dump, or one you just set via
  the password-reset flow.</p>
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Username</label>
    <input type="text" class="form-control" name="username">
  </div>
  <div class="mb-2">
    <label class="form-label">Password</label>
    <input type="text" class="form-control" name="password">
  </div>
  <button type="submit" class="btn btn-primary">Log in</button>
</form>
{% if result == "success" %}
<p class="mt-3 text-success">Login succeeded — account takeover confirmed.</p>
{% elif result == "failure" %}
<p class="mt-3 text-danger">Invalid username or password.</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 7: Modify `app/categories/a02_crypto_failures/templates/a02_crypto_failures/credential_dump.html`** — now that `legacy-login` exists, add a link to it as a new exploitation step

Change the exploitation block's `<ol>` from ending after step 3 to:
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
```

- [ ] **Step 8: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass, 0 warnings — this is the full test suite for A02's scope.

- [ ] **Step 9: Commit**

```bash
git add app/categories/a02_crypto_failures/routes.py \
  app/categories/a02_crypto_failures/templates/a02_crypto_failures/forgot_password.html \
  app/categories/a02_crypto_failures/templates/a02_crypto_failures/reset_password.html \
  app/categories/a02_crypto_failures/templates/a02_crypto_failures/legacy_login.html \
  app/categories/a02_crypto_failures/templates/a02_crypto_failures/credential_dump.html \
  tests/test_a02_reset_token.py
git commit -m "feat: add A02 Hard predictable-reset-token example and legacy login"
```

---

### Task 6: README update, Docker end-to-end verification

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: everything built in Tasks 1–5.
- Produces: updated category summary table; a manually-verified running container stack covering all three A02 exploits plus the reset-restores-A02-state check (no automated test — this is the plan's final integration check, mirroring A01's Task 11).

- [ ] **Step 1: Modify `README.md`'s category summary table**

Change:
```markdown
| A01 Broken Access Control | Implemented | IDOR (Easy), Hidden Admin Panel (Medium), Mass Assignment Role Escalation (Hard) |
| A02–A10 | Planned | See `docs/superpowers/specs/2026-09-18-owasp-lab-design.md` |
```
to:
```markdown
| A01 Broken Access Control | Implemented | IDOR (Easy), Hidden Admin Panel (Medium), Mass Assignment Role Escalation (Hard) |
| A02 Cryptographic Failures | Implemented | Leaked Credential Dump (Easy), Weak Encryption / ECB Mode (Medium), Predictable Password Reset Token (Hard) |
| A03–A10 | Planned | See `docs/superpowers/specs/2026-09-18-owasp-lab-design.md` |
```

- [ ] **Step 2: Rebuild and start the stack**

Run: `docker compose up --build -d`
Expected: both services healthy/running; no errors in `docker compose logs app`. (If the stack is already running from a prior session, `docker compose down` first for a clean rebuild against the new `pycryptodome` dependency.)

- [ ] **Step 3: Verify A02 overview and nav**

Run: `curl -s http://127.0.0.1:5001/a02/ | grep -i "Cryptographic Failures"`
Expected: match found. Also confirm via browser or curl that all three A02 example links now appear on `/a02/` (the `registered_endpoints` guard should show all three now that every route exists).

- [ ] **Step 4: Manually verify all three A02 exploits end-to-end**

```bash
# Easy: credential dump — confirm MD5 hashes are listed (no login needed)
curl -s http://127.0.0.1:5001/a02/credential-dump | grep -i "admin"

# Medium: ECB pattern leak — confirm two identical ciphertext values appear
curl -s http://127.0.0.1:5001/a02/encrypted-notes | grep -o '<code>[a-f0-9]*</code>' | sort | uniq -d

# Hard: predictable reset token — derive admin's token offline, reset, prove takeover
python3 -c "import hashlib; print(hashlib.md5(b'admin:resetSalt2024').hexdigest()[:10])"
# (use the printed token in place of <token> below)
curl -s -X POST http://127.0.0.1:5001/a02/reset-password/<token> -d "new_password=dockertest123"
curl -s -X POST http://127.0.0.1:5001/a02/legacy-login -d "username=admin&password=dockertest123" | grep -i "takeover confirmed"
```
Expected: each exploit succeeds exactly as described.

- [ ] **Step 5: Verify reset restores A02's clean state too**

```bash
curl -s -X POST http://127.0.0.1:5001/settings/reset -o /dev/null
curl -s -X POST http://127.0.0.1:5001/a02/legacy-login -d "username=admin&password=dockertest123" | grep -i "Invalid username or password"
```
Expected: the tampered admin password from Step 4 no longer works after reset — `legacy_credentials` was dropped and reseeded back to the original MD5 hashes.

- [ ] **Step 6: Tear down**

Run: `docker compose down`
Expected: containers stop cleanly.

- [ ] **Step 7: Commit**

```bash
git add README.md
git commit -m "docs: mark A02 Cryptographic Failures as implemented"
```
