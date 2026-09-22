# A10 Server-Side Request Forgery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build A10 (OWASP Top 10 2021: Server-Side Request Forgery) as a new
category with five examples covering unrestricted server-side URL fetches,
unsafe URL scheme handling, and two real-world blocklist/allowlist bypass
techniques. This is the FINAL category in the roadmap — once merged, A01–A10
are all implemented.

**Architecture:** New Flask blueprint `app/categories/a10_ssrf/` registered
in `app/__init__.py`, following the exact A01–A09 scaffold. No new database
model anywhere in this category — SSRF's proof is the fetched response
content itself, directly visible in the page the learner is already looking
at, unlike A08/A09's DB-backed proof mechanisms (which exist specifically to
make invisible server-side execution visible — a concern that doesn't apply
here). A shared, access-restricted internal-only route
(`/a10/internal/metadata`) is the common target every example that reaches a
live internal service points at.

**Tech Stack:** Flask 3.0.3, Python stdlib `urllib.request`, `urllib.parse`,
Jinja2 templates, pytest (using real local `http.server.HTTPServer`
instances and pytest's built-in `monkeypatch` fixture for genuine
outbound-fetch testing).

**Spec:** `docs/superpowers/specs/2026-09-22-owasp-lab-a10-ssrf-design.md`

## Global Constraints

- Every technique in this plan was individually live-verified in a scratch
  Python process during brainstorming before being written into the spec —
  **do not second-guess, "improve," or simplify any of it**. Specifically:
  `2130706433` (decimal), `0x7f000001` (hex), `127.1` (short-form), and `0`
  (bare zero) all genuinely resolve to `127.0.0.1` and are NOT members of
  the blocklist set `{"127.0.0.1", "localhost"}`; `0177.0.0.1` (dotted
  octal) does **not** work and must never appear as a payload;
  `urllib.request.urlopen()` follows HTTP redirects by default; a
  `socket.getaddrinfo` monkeypatch genuinely makes a fake domain resolve to
  a real local test server; `urllib` explicitly refuses to follow an
  `http://` → `file://` redirect (do not attempt to build an example around
  this); `urllib.request.Request` does NOT strip userinfo/credentials from
  a URL before connecting, unlike browsers (do not attempt to build an
  example around this either).
- No new SQLAlchemy model, no `models.py`, no `seed_fn` anywhere in this
  category — every example's proof is the raw fetched HTTP response
  content, already visible in the response the learner sees.
- `/a10/internal/metadata` must check `request.remote_addr == "127.0.0.1"`
  and return 403 to anyone else — this is a real, load-bearing access
  restriction, not decorative. Do not weaken or remove this check.
- `tests/conftest.py` is off-limits — never modify it, for any reason, in
  any task. Every test in this plan that needs a real outbound fetch uses a
  real local `http.server.HTTPServer` (matching A03's
  `test_xxe_ssrf_resolver_genuinely_fetches_http_entities` and A08's
  plugin-marketplace precedent) or pytest's built-in `monkeypatch` fixture
  — neither needs any `conftest.py` change.
- Every `HTTPServer` spun up in a test must be shut down in a `finally`
  block (`server.shutdown()` then `thread.join(timeout=5)`), even if the
  test fails partway through, to avoid leaking threads/ports across the
  test suite run — mirror the exact pattern in
  `tests/test_a03_xxe_ssrf.py::test_xxe_ssrf_resolver_genuinely_fetches_http_entities`.
  Every `HTTPRequestHandler` subclass in a test must override
  `log_message(self, *args): pass` to keep test output clean, matching the
  same precedent.
- No test in this plan may assert on a proof string (fetched content,
  fake-secret-file contents, encoded-IP payload) that also appears,
  unconditionally, in that same page's own static teaching prose — this bug
  class has recurred in A06, A07, and twice in A08. Every template below
  deliberately shows only the URL/payload to submit as static text, never
  the resulting fetched content, so tests can assert on real fetched
  content without risk of collision.
- A10 has 5 examples (2 Easy, 2 Medium, 1 Hard), not the 6 (2/2/2) shape
  every prior category delivered — an explicit, user-confirmed decision
  after two candidate techniques for a second Hard example were
  live-verified and found not to work against this app's stdlib-`urllib`
  implementation. Do not invent a 6th example to "complete" the shape.

---

## Task 1: Category Scaffold, Shared Internal-Only Target, and Example 1 (Webhook Tester Reaches Internal Metadata Endpoint)

**Files:**
- Create: `app/categories/a10_ssrf/__init__.py`
- Create: `app/categories/a10_ssrf/routes.py`
- Create: `app/categories/a10_ssrf/templates/a10_ssrf/overview.html`
- Create: `app/categories/a10_ssrf/templates/a10_ssrf/webhook_tester.html`
- Modify: `app/__init__.py`
- Test: `tests/test_a10_webhook_internal_metadata.py`

**Interfaces:**
- Produces: `a10_bp` (Blueprint, `url_prefix="/a10"`). Route endpoints
  `a10_ssrf.overview` → `GET /a10/`, `a10_ssrf.internal_metadata` → `GET
  /a10/internal/metadata` (non-nav utility endpoint, reused unchanged by
  every later task that reaches a live internal target), `a10_ssrf.
  webhook_tester` → `GET/POST /a10/webhook-tester` (reused unchanged by
  Task 2, which embeds a form targeting this same route with no new
  backend logic of its own).

- [ ] **Step 1: Write the failing test**

Create `tests/test_a10_webhook_internal_metadata.py`:

```python
def test_webhook_tester_page_renders(client):
    response = client.get("/a10/webhook-tester")
    assert response.status_code == 200


def test_webhook_tester_genuinely_fetches_an_arbitrary_url(client):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"FETCHED-VIA-WEBHOOK-TESTER-PROBE")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = client.post(
            "/a10/webhook-tester", data={"webhook_url": f"http://127.0.0.1:{port}/"}
        )
        assert response.status_code == 200
        assert b"FETCHED-VIA-WEBHOOK-TESTER-PROBE" in response.data
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_internal_metadata_rejects_a_simulated_external_caller(client):
    response = client.get(
        "/a10/internal/metadata", environ_overrides={"REMOTE_ADDR": "203.0.113.5"}
    )
    assert response.status_code == 403


def test_internal_metadata_trusts_a_localhost_origin_request(client):
    response = client.get("/a10/internal/metadata")
    assert response.status_code == 200
    assert b"AKIAFAKESSRFPROOF1234" in response.data


def test_webhook_internal_metadata_link_appears_in_overview_once_registered(client):
    response = client.get("/a10/")
    assert response.status_code == 200
    assert b"Webhook Tester Reaches Internal Metadata Endpoint" in response.data
    assert b'href="/a10/webhook-tester"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a10_webhook_internal_metadata.py -v`
Expected: FAIL — `ModuleNotFoundError` / 404s (nothing exists yet).

- [ ] **Step 3: Create the blueprint package**

Create `app/categories/a10_ssrf/__init__.py`:

```python
from flask import Blueprint

a10_bp = Blueprint(
    "a10_ssrf", __name__, template_folder="templates", url_prefix="/a10"
)

from app.categories.a10_ssrf import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a10_ssrf",
        short_id="A10",
        title="Server-Side Request Forgery",
        blurb="A URL field the server fetches on your behalf, an unrestricted scheme, or a blocklist/allowlist with a gap wide enough to reach an internal-only endpoint that should never have been visible from outside.",
        blueprint_name="a10_ssrf",
        overview_endpoint="a10_ssrf.overview",
        examples=[
            ExampleNav(
                id="webhook-internal-metadata",
                title="Webhook Tester Reaches Internal Metadata Endpoint",
                group="Unrestricted Server-Side Fetch",
                difficulty="Easy",
                endpoint="a10_ssrf.webhook_tester",
            ),
        ],
    )
)
```

- [ ] **Step 4: Create the routes**

Create `app/categories/a10_ssrf/routes.py`:

```python
import urllib.request

from flask import Response, abort, render_template, request

from app.categories.a10_ssrf import a10_bp


@a10_bp.route("/")
def overview():
    return render_template("a10_ssrf/overview.html")


@a10_bp.route("/internal/metadata")
def internal_metadata():
    # VULNERABLE from the attacker's point of view, but INTENTIONALLY
    # restrictive here: only requests that arrive from localhost are
    # trusted. This is what every A10 example exploits -- the vulnerable
    # routes' own outbound fetches arrive here via the loopback interface,
    # inheriting a trust boundary an external attacker could never cross
    # directly.
    if request.remote_addr != "127.0.0.1":
        abort(403)
    return Response(
        "instance-id: i-0a1b2c3d4e5f6g7h8\n"
        "iam-role: training-lab-admin\n"
        "access-key: AKIAFAKESSRFPROOF1234\n"
        "secret-key: fake-secret-do-not-use-ssrf-proof-9f3c2b1a\n",
        mimetype="text/plain",
    )


@a10_bp.route("/webhook-tester", methods=["GET", "POST"])
def webhook_tester():
    result = None
    error = None
    webhook_url = ""
    if request.method == "POST":
        webhook_url = request.form.get("webhook_url", "")
        try:
            # VULNERABLE: fetches whatever URL the client supplies, with no
            # validation of scheme, host, or destination at all.
            with urllib.request.urlopen(webhook_url, timeout=5) as resp:
                result = resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            error = f"Could not reach webhook URL: {e}"
    return render_template(
        "a10_ssrf/webhook_tester.html",
        webhook_url=webhook_url,
        result=result,
        error=error,
    )
```

- [ ] **Step 5: Create the templates**

Create `app/categories/a10_ssrf/templates/a10_ssrf/webhook_tester.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Webhook Tester Reaches Internal Metadata Endpoint" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A10{% endblock %}

{% block explanation %}
<p>
  This "test your webhook URL" feature fetches whatever URL you give it
  and shows you the raw response -- exactly what a webhook tester should
  do, except it never checks where that URL actually points before
  fetching it.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit any ordinary URL and the response comes back as expected. The
  vulnerability only becomes visible once you point it somewhere it
  should never be allowed to go.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Submit <code>http://127.0.0.1:5000/a10/internal/metadata</code> below.
  This app's own internal-only endpoint only trusts requests that arrive
  from localhost -- and that's exactly what this feature's own outbound
  request looks like from the endpoint's point of view.
</p>
{% endblock %}

{% block vulnerable_code %}webhook_url = request.form.get("webhook_url", "")
with urllib.request.urlopen(webhook_url, timeout=5) as resp:
    result = resp.read().decode("utf-8", errors="replace")
# no validation of scheme, host, or destination at all
{% endblock %}

{% block secure_code %}import ipaddress, socket
hostname = urllib.parse.urlparse(webhook_url).hostname
ip = ipaddress.ip_address(socket.gethostbyname(hostname))
if ip.is_private or ip.is_loopback or ip.is_link_local:
    abort(400)
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Webhook URL</label>
    <input class="form-control" type="text" name="webhook_url" value="{{ webhook_url }}">
  </div>
  <button type="submit" class="btn btn-primary">Test Webhook</button>
</form>
{% if result %}
<p class="mt-3">Response:</p>
<pre><code class="language-text">{{ result }}</code></pre>
{% endif %}
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

Create `app/categories/a10_ssrf/templates/a10_ssrf/overview.html`:

```html
{% extends "core/overview_base.html" %}
{% set category_short_id = "A10" %}
{% set category_title = "Server-Side Request Forgery" %}
{% block title %}A10: Server-Side Request Forgery{% endblock %}

{% block what_it_is %}
<p>
  Server-Side Request Forgery happens when a feature fetches a URL on the
  server's behalf -- a webhook test, a link preview, an avatar import, a
  PDF generator -- without validating where that URL actually points. The
  server ends up making requests an external attacker could never make
  directly, from inside whatever network boundary protects it.
</p>
{% endblock %}

{% block why_it_matters %}
<p>
  A firewall, a VPN, or a network ACL exists to keep outsiders away from
  internal-only services. None of that matters if the application itself
  will happily fetch any URL it's handed and hand the response right
  back -- the server becomes the attacker's proxy into the network it's
  supposed to be protected by.
</p>
{% endblock %}

{% block how_exploited %}
<p>
  Attackers submit URLs pointing at internal-only services, local files
  via unrestricted schemes, or crafted addresses designed to slip past a
  blocklist or allowlist that only checks the URL's most obvious form --
  none of it requires breaking into the network directly, only handing
  the server a URL it shouldn't trust.
</p>
{% endblock %}

{% block attack_flow_diagram %}
sequenceDiagram
    participant Attacker
    participant App as Vulnerable App
    participant Internal as Internal-Only Service
    Attacker->>App: Submit a URL (webhook, avatar, mirror, PDF source)
    App->>Internal: Server-side fetch, no validation or a bypassable one
    Internal-->>App: Response the attacker could never have requested directly
    App-->>Attacker: Raw response, exposing internal data
{% endblock %}

{% block real_world_impact %}
<p>
  SSRF has been used to reach cloud metadata services and steal instance
  credentials in real-world breaches (most famously the 2019 Capital One
  breach, which began with an SSRF request to AWS's metadata endpoint),
  and routinely shows up in bug bounty reports against webhook,
  PDF-generation, and link-preview features that fetch attacker-supplied
  URLs.
</p>
{% endblock %}

{% block vulnerable_code %}webhook_url = request.form.get("webhook_url", "")
with urllib.request.urlopen(webhook_url, timeout=5) as resp:
    result = resp.read().decode("utf-8", errors="replace")
# no validation of scheme, host, or destination at all
{% endblock %}

{% block secure_code %}import ipaddress, socket
hostname = urllib.parse.urlparse(webhook_url).hostname
ip = ipaddress.ip_address(socket.gethostbyname(hostname))
if ip.is_private or ip.is_loopback or ip.is_link_local:
    abort(400)
{% endblock %}
```

- [ ] **Step 6: Register the blueprint**

Modify `app/__init__.py` — add, immediately after the existing A09
registration block (after `app.register_blueprint(a09_bp)` and before the
`/healthz` route):

```python
    from app.categories.a10_ssrf import a10_bp

    app.register_blueprint(a10_bp)
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a10_webhook_internal_metadata.py -v`
Expected: PASS (5 passed)

- [ ] **Step 8: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all pass (388 baseline + 5 new = 393).

- [ ] **Step 9: Commit**

```bash
git add app/categories/a10_ssrf app/__init__.py tests/test_a10_webhook_internal_metadata.py
git commit -m "feat(a10): add category scaffold, internal-metadata target, and webhook-internal-metadata example"
```

---

## Task 2: Example 2 (Same Fetcher Enables Internal Port Scanning)

**Files:**
- Modify: `app/categories/a10_ssrf/routes.py`
- Modify: `app/categories/a10_ssrf/__init__.py`
- Create: `app/categories/a10_ssrf/templates/a10_ssrf/port_scan_demo.html`
- Test: `tests/test_a10_fetch_based_port_scan.py`

**Interfaces:**
- Consumes: `a10_bp`, `webhook_tester()`'s route (`a10_ssrf.webhook_tester`)
  from Task 1 — this task adds NO new vulnerable backend logic; its only
  route renders a static teaching page.
- Produces: Route endpoint `a10_ssrf.port_scan_demo` → `GET
  /a10/port-scan-demo`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a10_fetch_based_port_scan.py`:

```python
def test_port_scan_demo_page_renders(client):
    response = client.get("/a10/port-scan-demo")
    assert response.status_code == 200


def test_port_scan_demo_link_appears_in_overview_once_registered(client):
    response = client.get("/a10/")
    assert response.status_code == 200
    assert b"Same Fetcher Enables Internal Port Scanning" in response.data
    assert b'href="/a10/port-scan-demo"' in response.data


def test_webhook_tester_differentiates_open_and_closed_internal_ports(client):
    import socket
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OPEN-PORT-RESPONSE")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    open_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    # A "definitely closed" port: bind an ephemeral socket, read back the
    # port the OS assigned, then close it immediately. Nothing else should
    # grab it in the brief window before this test uses it.
    closed_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    closed_socket.bind(("127.0.0.1", 0))
    closed_port = closed_socket.getsockname()[1]
    closed_socket.close()

    try:
        open_response = client.post(
            "/a10/webhook-tester", data={"webhook_url": f"http://127.0.0.1:{open_port}/"}
        )
        assert open_response.status_code == 200
        assert b"OPEN-PORT-RESPONSE" in open_response.data

        closed_response = client.post(
            "/a10/webhook-tester", data={"webhook_url": f"http://127.0.0.1:{closed_port}/"}
        )
        assert closed_response.status_code == 200
        assert b"Could not reach webhook URL" in closed_response.data
        assert b"OPEN-PORT-RESPONSE" not in closed_response.data
    finally:
        server.shutdown()
        thread.join(timeout=5)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a10_fetch_based_port_scan.py -v`
Expected: `test_port_scan_demo_page_renders` and the overview-link test FAIL
with 404 (no route yet). `test_webhook_tester_differentiates_open_and_
closed_internal_ports` already PASSes — the underlying mechanics from
Task 1 already make the differential behavior work; this task only adds
the dedicated teaching page. That's expected and correct, matching the
same pattern already established in A08's Task 5/6 and A09's Task 5/6.

- [ ] **Step 3: Add the route**

Modify `app/categories/a10_ssrf/routes.py` — after the `webhook_tester()`
route, add:

```python


@a10_bp.route("/port-scan-demo")
def port_scan_demo():
    return render_template("a10_ssrf/port_scan_demo.html")
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a10_ssrf/__init__.py` — in the `examples=[...]`
list, after the `webhook-internal-metadata` entry, add:

```python
            ExampleNav(
                id="fetch-based-port-scan",
                title="Same Fetcher Enables Internal Port Scanning",
                group="Unrestricted Server-Side Fetch",
                difficulty="Medium",
                endpoint="a10_ssrf.port_scan_demo",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a10_ssrf/templates/a10_ssrf/port_scan_demo.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Same Fetcher Enables Internal Port Scanning" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A10{% endblock %}

{% block explanation %}
<p>
  The "Webhook Tester" example proved this feature reaches an internal
  endpoint and shows you what's there. Here's a different use of the
  exact same mechanism: submitting URLs at different internal ports
  produces genuinely different, distinguishable responses -- letting an
  attacker map which internal services exist without ever seeing a byte
  of their actual protocol traffic.
</p>
{% endblock %}

{% block detect %}
<p>
  No new vulnerable code exists for this example -- it's the same
  unrestricted fetch from the Webhook Tester, used differently.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Go to the <a href="{{ url_for('a10_ssrf.webhook_tester') }}">Webhook
  Tester</a> and submit a few different internal addresses:
</p>
<ul>
  <li><code>http://127.0.0.1:5000/a10/internal/metadata</code> -- a real
      HTTP service, responds with content.</li>
  <li><code>http://127.0.0.1:5432/</code> -- something is listening (this
      container's own database), but it doesn't speak HTTP, so the
      response looks entirely different from either of the other two
      cases.</li>
  <li><code>http://127.0.0.1:9999/</code> -- nothing is listening at
      all, and the connection is refused immediately.</li>
</ul>
<p>
  Three different outcomes, three different facts learned about the
  internal network -- all through a feature that was only ever supposed
  to test a webhook URL.
</p>
{% endblock %}

{% block vulnerable_code %}webhook_url = request.form.get("webhook_url", "")
with urllib.request.urlopen(webhook_url, timeout=5) as resp:
    result = resp.read().decode("utf-8", errors="replace")
# the exact same unrestricted fetch as the Webhook Tester example -- no
# new code was written for this one, only a different way of using it
{% endblock %}

{% block secure_code %}# Same fix as the Webhook Tester example -- validate the resolved IP is
# not private/loopback/link-local before ever calling urlopen().
{% endblock %}

{% block live_example %}
<a href="{{ url_for('a10_ssrf.webhook_tester') }}" class="btn btn-primary">
  Go to Webhook Tester
</a>
{% endblock %}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a10_fetch_based_port_scan.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all pass (393 baseline + 3 new = 396).

- [ ] **Step 8: Commit**

```bash
git add app/categories/a10_ssrf tests/test_a10_fetch_based_port_scan.py
git commit -m "feat(a10): add fetch-based-port-scan example"
```

---

## Task 3: Example 3 (PDF Generator Reads Local Files via file:// URL)

**Files:**
- Modify: `app/categories/a10_ssrf/routes.py`
- Modify: `app/categories/a10_ssrf/__init__.py`
- Create: `app/categories/a10_ssrf/internal_data/fake_secret.txt`
- Create: `app/categories/a10_ssrf/templates/a10_ssrf/pdf_generator.html`
- Test: `tests/test_a10_file_scheme_local_read.py`

**Interfaces:**
- Consumes: `a10_bp` from Task 1 (unchanged).
- Produces: `FAKE_SECRET_FILE_PATH` (str, absolute path constant,
  `app.categories.a10_ssrf.routes`) — this task's own test imports it
  directly to read the expected content. Route endpoint
  `a10_ssrf.pdf_generator` → `GET/POST /a10/pdf-generator`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a10_file_scheme_local_read.py`:

```python
def test_pdf_generator_page_renders(client):
    response = client.get("/a10/pdf-generator")
    assert response.status_code == 200


def test_pdf_generator_fetches_a_normal_url(client):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"NORMAL-WEBPAGE-CONTENT")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = client.post(
            "/a10/pdf-generator", data={"page_url": f"http://127.0.0.1:{port}/"}
        )
        assert response.status_code == 200
        assert b"NORMAL-WEBPAGE-CONTENT" in response.data
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_file_scheme_reads_the_real_local_secret_file(client):
    from app.categories.a10_ssrf.routes import FAKE_SECRET_FILE_PATH

    with open(FAKE_SECRET_FILE_PATH) as f:
        expected_content = f.read()

    response = client.post(
        "/a10/pdf-generator", data={"page_url": f"file://{FAKE_SECRET_FILE_PATH}"}
    )
    assert response.status_code == 200
    assert expected_content.encode() in response.data


def test_file_scheme_local_read_link_appears_in_overview_once_registered(client):
    response = client.get("/a10/")
    assert response.status_code == 200
    assert b"PDF Generator Reads Local Files via" in response.data
    assert b'href="/a10/pdf-generator"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a10_file_scheme_local_read.py -v`
Expected: FAIL — `ImportError` (`FAKE_SECRET_FILE_PATH` doesn't exist yet)
/ 404.

- [ ] **Step 3: Plant the fake secret file**

Create `app/categories/a10_ssrf/internal_data/fake_secret.txt` (a real
file, checked into git — not gitignored, unlike A09's runtime-written log
file, since this is a fixed planted asset the app ships with):

```
FAKE-SECRET-FILE-CONTENTS-9f3c2b1a-do-not-use
This file exists only to prove a URL field let you read local files
instead of fetching a webpage.
```

- [ ] **Step 4: Add the route**

Modify `app/categories/a10_ssrf/routes.py` — add `import os` and `from app
import BASE_DIR` to the top imports:

```python
import os
import urllib.request

from flask import Response, abort, render_template, request

from app import BASE_DIR
from app.categories.a10_ssrf import a10_bp
```

Then, after the `port_scan_demo()` route, add:

```python


FAKE_SECRET_FILE_PATH = os.path.join(
    BASE_DIR, "app", "categories", "a10_ssrf", "internal_data", "fake_secret.txt"
)


@a10_bp.route("/pdf-generator", methods=["GET", "POST"])
def pdf_generator():
    result = None
    error = None
    page_url = ""
    if request.method == "POST":
        page_url = request.form.get("page_url", "")
        try:
            # VULNERABLE: no scheme allowlist -- file://, and anything
            # else urllib supports, is fetched exactly like http(s)://.
            with urllib.request.urlopen(page_url, timeout=5) as resp:
                result = resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            error = f"Could not generate PDF from URL: {e}"
    return render_template(
        "a10_ssrf/pdf_generator.html",
        page_url=page_url,
        result=result,
        error=error,
        fake_secret_file_url=f"file://{FAKE_SECRET_FILE_PATH}",
    )
```

- [ ] **Step 5: Add the ExampleNav entry**

Modify `app/categories/a10_ssrf/__init__.py` — in the `examples=[...]`
list, after the `fetch-based-port-scan` entry, add:

```python
            ExampleNav(
                id="file-scheme-local-read",
                title="PDF Generator Reads Local Files via file:// URL",
                group="Unsafe URL Scheme Handling",
                difficulty="Easy",
                endpoint="a10_ssrf.pdf_generator",
            ),
```

- [ ] **Step 6: Create the template**

Create `app/categories/a10_ssrf/templates/a10_ssrf/pdf_generator.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "PDF Generator Reads Local Files via file:// URL" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A10{% endblock %}

{% block explanation %}
<p>
  This "generate a PDF from this webpage" feature passes whatever URL
  you give it straight to a fetch call, exactly like the Webhook Tester
  -- but here the bug isn't the destination, it's the scheme. Nothing
  restricts this to <code>http://</code>/<code>https://</code>, and
  Python's own URL library has built-in support for reading local files
  via <code>file://</code>.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit an ordinary webpage URL and a PDF-worthy response comes back.
  Submit a <code>file://</code> URL instead and the "generated PDF"
  content is actually a local file's contents.
</p>
{% endblock %}

{% block exploitation %}
<p>Submit this exact URL below:</p>
<pre><code class="language-text">{{ fake_secret_file_url }}</code></pre>
<p>
  The response shows this server's own local file contents -- not a
  fetched webpage at all.
</p>
{% endblock %}

{% block vulnerable_code %}page_url = request.form.get("page_url", "")
with urllib.request.urlopen(page_url, timeout=5) as resp:
    result = resp.read().decode("utf-8", errors="replace")
# no scheme restriction at all -- file://, and anything urllib supports,
# is fetched exactly like http(s)://
{% endblock %}

{% block secure_code %}from urllib.parse import urlparse
if urlparse(page_url).scheme not in ("http", "https"):
    abort(400, "Only http:// and https:// URLs are allowed.")
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Page URL</label>
    <input class="form-control" type="text" name="page_url" value="{{ page_url }}">
  </div>
  <button type="submit" class="btn btn-primary">Generate PDF</button>
</form>
{% if result %}
<p class="mt-3">Generated content:</p>
<pre><code class="language-text">{{ result }}</code></pre>
{% endif %}
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

Note: this template's static text shows only the `file://` URL to submit
(`{{ fake_secret_file_url }}`, a dynamic Jinja expression) — it never
states the fake secret file's actual CONTENTS anywhere. This keeps the
test's assertion on the real file content non-vacuous.

- [ ] **Step 7: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a10_file_scheme_local_read.py -v`
Expected: PASS (4 passed)

- [ ] **Step 8: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all pass (396 baseline + 4 new = 400).

- [ ] **Step 9: Commit**

```bash
git add app/categories/a10_ssrf tests/test_a10_file_scheme_local_read.py
git commit -m "feat(a10): add file-scheme-local-read example"
```

---

## Task 4: Example 4 (Alternate IP Representation Bypasses a Naive Blocklist)

**Files:**
- Modify: `app/categories/a10_ssrf/routes.py`
- Modify: `app/categories/a10_ssrf/__init__.py`
- Create: `app/categories/a10_ssrf/templates/a10_ssrf/import_avatar.html`
- Test: `tests/test_a10_blocklist_alternate_ip_bypass.py`

**Interfaces:**
- Consumes: `a10_bp` from Task 1 (unchanged).
- Produces: `BLOCKED_HOSTS` (set of str) and route endpoint
  `a10_ssrf.import_avatar` → `GET/POST /a10/import-avatar`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a10_blocklist_alternate_ip_bypass.py`:

```python
def test_import_avatar_page_renders(client):
    response = client.get("/a10/import-avatar")
    assert response.status_code == 200


def test_import_avatar_blocks_literal_127_0_0_1(client):
    response = client.post(
        "/a10/import-avatar", data={"avatar_url": "http://127.0.0.1:9999/"}
    )
    assert response.status_code == 200
    assert b"That host is not allowed" in response.data


def test_import_avatar_blocks_literal_localhost(client):
    response = client.post(
        "/a10/import-avatar", data={"avatar_url": "http://localhost:9999/"}
    )
    assert response.status_code == 200
    assert b"That host is not allowed" in response.data


def test_alternate_ip_encodings_bypass_the_blocklist(client):
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
        # These four are live-verified to all resolve to 127.0.0.1 and to
        # NOT be members of BLOCKED_HOSTS -- see the plan's Global
        # Constraints. Do not add "0177.0.0.1" here; it does not work.
        for host in ["2130706433", "0x7f000001", "127.1", "0"]:
            response = client.post(
                "/a10/import-avatar", data={"avatar_url": f"http://{host}:{port}/"}
            )
            assert response.status_code == 200
            assert b"REACHED-VIA-ALTERNATE-ENCODING" in response.data, (
                f"payload {host!r} did not bypass the blocklist"
            )
            assert b"That host is not allowed" not in response.data
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_blocklist_alternate_ip_bypass_link_appears_in_overview_once_registered(client):
    response = client.get("/a10/")
    assert response.status_code == 200
    assert b"Alternate IP Representation Bypasses a Naive Blocklist" in response.data
    assert b'href="/a10/import-avatar"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a10_blocklist_alternate_ip_bypass.py -v`
Expected: FAIL — 404 (no route yet).

- [ ] **Step 3: Add the route**

Modify `app/categories/a10_ssrf/routes.py` — add `import urllib.parse` to
the top imports (alongside the existing `import urllib.request`):

```python
import os
import urllib.parse
import urllib.request
```

Then, after the `pdf_generator()` route, add:

```python


BLOCKED_HOSTS = {"127.0.0.1", "localhost"}


@a10_bp.route("/import-avatar", methods=["GET", "POST"])
def import_avatar():
    result = None
    error = None
    avatar_url = ""
    if request.method == "POST":
        avatar_url = request.form.get("avatar_url", "")
        hostname = urllib.parse.urlparse(avatar_url).hostname
        # VULNERABLE: blocks the exact strings "127.0.0.1"/"localhost" --
        # any other representation of the same address sails right
        # through.
        if hostname is not None and hostname.lower() in BLOCKED_HOSTS:
            error = "That host is not allowed."
        else:
            try:
                with urllib.request.urlopen(avatar_url, timeout=5) as resp:
                    result = resp.read().decode("utf-8", errors="replace")
            except Exception as e:
                error = f"Could not fetch avatar: {e}"
    return render_template(
        "a10_ssrf/import_avatar.html",
        avatar_url=avatar_url,
        result=result,
        error=error,
    )
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a10_ssrf/__init__.py` — in the `examples=[...]`
list, after the `file-scheme-local-read` entry, add:

```python
            ExampleNav(
                id="blocklist-alternate-ip-bypass",
                title="Alternate IP Representation Bypasses a Naive Blocklist",
                group="Blocklist Bypass Techniques",
                difficulty="Medium",
                endpoint="a10_ssrf.import_avatar",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a10_ssrf/templates/a10_ssrf/import_avatar.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Alternate IP Representation Bypasses a Naive Blocklist" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A10{% endblock %}

{% block explanation %}
<p>
  This "import your avatar from a URL" feature checks the submitted
  URL's host against a blocklist before fetching it -- but the check
  only recognizes the exact strings <code>127.0.0.1</code> and
  <code>localhost</code>. Any other way of writing the same address
  sails straight through.
</p>
{% endblock %}

{% block detect %}
<p>
  Submitting <code>http://127.0.0.1:5000/a10/internal/metadata</code>
  directly is correctly rejected. The blocklist looks like it works --
  until you write the same address a different way.
</p>
{% endblock %}

{% block exploitation %}
<p>Any of these reach the exact same address the blocklist just refused:</p>
<ul>
  <li><code>http://2130706433:5000/a10/internal/metadata</code> (decimal)</li>
  <li><code>http://0x7f000001:5000/a10/internal/metadata</code> (hexadecimal)</li>
  <li><code>http://127.1:5000/a10/internal/metadata</code> (short form)</li>
  <li><code>http://0:5000/a10/internal/metadata</code> (bare zero --
      Linux treats this as "any address," which routes to loopback for
      an outbound connection)</li>
</ul>
<p>
  None of these strings contain <code>127.0.0.1</code> or
  <code>localhost</code>, so the blocklist never even looks at them
  twice.
</p>
{% endblock %}

{% block vulnerable_code %}hostname = urllib.parse.urlparse(avatar_url).hostname
if hostname is not None and hostname.lower() in BLOCKED_HOSTS:
    error = "That host is not allowed."
else:
    with urllib.request.urlopen(avatar_url, timeout=5) as resp:
        result = resp.read().decode("utf-8", errors="replace")
# BLOCKED_HOSTS = {"127.0.0.1", "localhost"} -- exact-string matching only
{% endblock %}

{% block secure_code %}import ipaddress, socket
ip = ipaddress.ip_address(socket.gethostbyname(hostname))
if ip.is_private or ip.is_loopback or ip.is_link_local:
    error = "That host is not allowed."
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Avatar URL</label>
    <input class="form-control" type="text" name="avatar_url" value="{{ avatar_url }}">
  </div>
  <button type="submit" class="btn btn-primary">Import Avatar</button>
</form>
{% if result %}
<p class="mt-3">Response:</p>
<pre><code class="language-text">{{ result }}</code></pre>
{% endif %}
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a10_blocklist_alternate_ip_bypass.py -v`
Expected: PASS (5 passed)

- [ ] **Step 7: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all pass (400 baseline + 5 new = 405).

- [ ] **Step 8: Commit**

```bash
git add app/categories/a10_ssrf tests/test_a10_blocklist_alternate_ip_bypass.py
git commit -m "feat(a10): add blocklist-alternate-ip-bypass example"
```

---

## Task 5: Example 5 (Open Redirect Bypasses a Trusted-Domain Allowlist)

**Files:**
- Modify: `app/categories/a10_ssrf/routes.py`
- Modify: `app/categories/a10_ssrf/__init__.py`
- Create: `app/categories/a10_ssrf/templates/a10_ssrf/mirror_fetcher.html`
- Test: `tests/test_a10_blocklist_redirect_bypass.py`

**Interfaces:**
- Consumes: `a10_bp` from Task 1 (unchanged).
- Produces: `ALLOWED_MIRROR_HOSTS` (set of str) and route endpoint
  `a10_ssrf.mirror_fetcher` → `GET/POST /a10/mirror-fetcher`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_a10_blocklist_redirect_bypass.py`:

```python
def test_mirror_fetcher_page_renders(client):
    response = client.get("/a10/mirror-fetcher")
    assert response.status_code == 200


def test_mirror_fetcher_rejects_a_non_allowlisted_host(client):
    response = client.post(
        "/a10/mirror-fetcher", data={"mirror_url": "http://evil.example/"}
    )
    assert response.status_code == 200
    assert b"Only approved content mirrors are allowed" in response.data


def test_mirror_fetcher_fetches_a_directly_allowlisted_host(client, monkeypatch):
    import socket
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    real_getaddrinfo = socket.getaddrinfo

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DIRECT-MIRROR-CONTENT")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "trusted-mirror.example":
            host = "127.0.0.1"
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    try:
        response = client.post(
            "/a10/mirror-fetcher",
            data={"mirror_url": f"http://trusted-mirror.example:{port}/"},
        )
        assert response.status_code == 200
        assert b"DIRECT-MIRROR-CONTENT" in response.data
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_redirect_from_allowlisted_host_bypasses_validation(client, monkeypatch):
    import socket
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    real_getaddrinfo = socket.getaddrinfo

    class TargetHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"REACHED-INTERNAL-TARGET-VIA-REDIRECT")

        def log_message(self, *args):
            pass

    target = HTTPServer(("127.0.0.1", 0), TargetHandler)
    target_port = target.server_address[1]
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    target_thread.start()

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{target_port}/")
            self.end_headers()

        def log_message(self, *args):
            pass

    redirector = HTTPServer(("127.0.0.1", 0), RedirectHandler)
    redirector_port = redirector.server_address[1]
    redirector_thread = threading.Thread(target=redirector.serve_forever, daemon=True)
    redirector_thread.start()

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "trusted-mirror.example":
            host = "127.0.0.1"
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    try:
        response = client.post(
            "/a10/mirror-fetcher",
            data={"mirror_url": f"http://trusted-mirror.example:{redirector_port}/"},
        )
        assert response.status_code == 200
        assert b"REACHED-INTERNAL-TARGET-VIA-REDIRECT" in response.data
    finally:
        redirector.shutdown()
        redirector_thread.join(timeout=5)
        target.shutdown()
        target_thread.join(timeout=5)


def test_blocklist_redirect_bypass_link_appears_in_overview_once_registered(client):
    response = client.get("/a10/")
    assert response.status_code == 200
    assert b"Open Redirect Bypasses a Trusted-Domain Allowlist" in response.data
    assert b'href="/a10/mirror-fetcher"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/pytest tests/test_a10_blocklist_redirect_bypass.py -v`
Expected: FAIL — 404 (no route yet).

- [ ] **Step 3: Add the route**

Modify `app/categories/a10_ssrf/routes.py` — after the `import_avatar()`
route, add:

```python


ALLOWED_MIRROR_HOSTS = {"trusted-mirror.example"}


@a10_bp.route("/mirror-fetcher", methods=["GET", "POST"])
def mirror_fetcher():
    result = None
    error = None
    mirror_url = ""
    if request.method == "POST":
        mirror_url = request.form.get("mirror_url", "")
        hostname = urllib.parse.urlparse(mirror_url).hostname
        if hostname not in ALLOWED_MIRROR_HOSTS:
            error = "Only approved content mirrors are allowed."
        else:
            try:
                # VULNERABLE: urlopen() follows redirects by default and
                # never re-validates the Location header's host against
                # ALLOWED_MIRROR_HOSTS -- the allowlist check above only
                # ever sees the URL the client originally submitted.
                with urllib.request.urlopen(mirror_url, timeout=5) as resp:
                    result = resp.read().decode("utf-8", errors="replace")
            except Exception as e:
                error = f"Could not fetch from mirror: {e}"
    return render_template(
        "a10_ssrf/mirror_fetcher.html",
        mirror_url=mirror_url,
        result=result,
        error=error,
    )
```

- [ ] **Step 4: Add the ExampleNav entry**

Modify `app/categories/a10_ssrf/__init__.py` — in the `examples=[...]`
list, after the `blocklist-alternate-ip-bypass` entry, add:

```python
            ExampleNav(
                id="blocklist-redirect-bypass",
                title="Open Redirect Bypasses a Trusted-Domain Allowlist",
                group="Blocklist Bypass Techniques",
                difficulty="Hard",
                endpoint="a10_ssrf.mirror_fetcher",
            ),
```

- [ ] **Step 5: Create the template**

Create `app/categories/a10_ssrf/templates/a10_ssrf/mirror_fetcher.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Open Redirect Bypasses a Trusted-Domain Allowlist" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A10{% endblock %}

{% block explanation %}
<p>
  This "fetch from an approved content mirror" feature does the right
  thing on the surface -- it checks the submitted URL's host against an
  allowlist of trusted partners, not a fragile blocklist. The gap: it
  only ever validates the URL the client submitted. If that URL
  redirects somewhere else, the fetch follows the redirect without
  checking the new destination against anything.
</p>
{% endblock %}

{% block detect %}
<p>
  Submitting a URL for a host that isn't on the allowlist is correctly
  rejected. Submitting an approved host's URL is correctly fetched. The
  gap only appears once an approved host's URL turns out to redirect
  somewhere else.
</p>
{% endblock %}

{% block exploitation %}
<p>
  This exploit needs two things you control, since no real DNS record
  exists for the allowlisted domain in this training environment:
</p>
<ol>
  <li>
    Make the allowlisted domain resolve to your own machine:
    <pre><code class="language-bash">echo "127.0.0.1 trusted-mirror.example" | sudo tee -a /etc/hosts</code></pre>
  </li>
  <li>
    Serve a redirect to this app's internal-only endpoint:
    <pre><code class="language-python">from http.server import BaseHTTPRequestHandler, HTTPServer

class Redirect(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1:5000/a10/internal/metadata")
        self.end_headers()

HTTPServer(("127.0.0.1", 8080), Redirect).serve_forever()</code></pre>
  </li>
</ol>
<p>
  Then submit <code>http://trusted-mirror.example:8080/</code> below.
  The allowlist check sees and approves
  <code>trusted-mirror.example</code> -- and the fetch follows the
  redirect straight to the internal-only endpoint anyway.
</p>
{% endblock %}

{% block vulnerable_code %}hostname = urllib.parse.urlparse(mirror_url).hostname
if hostname not in ALLOWED_MIRROR_HOSTS:
    error = "Only approved content mirrors are allowed."
else:
    with urllib.request.urlopen(mirror_url, timeout=5) as resp:
        result = resp.read().decode("utf-8", errors="replace")
# urlopen() follows redirects by default and never re-checks the
# Location header's host against ALLOWED_MIRROR_HOSTS
{% endblock %}

{% block secure_code %}# Disable automatic redirect-following and re-validate every hop's host
# against the same allowlist before following it manually.
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Mirror URL</label>
    <input class="form-control" type="text" name="mirror_url" value="{{ mirror_url }}">
  </div>
  <button type="submit" class="btn btn-primary">Fetch From Mirror</button>
</form>
{% if result %}
<p class="mt-3">Response:</p>
<pre><code class="language-text">{{ result }}</code></pre>
{% endif %}
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a10_blocklist_redirect_bypass.py -v`
Expected: PASS (5 passed)

- [ ] **Step 7: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all pass (405 baseline + 5 new = 410).

- [ ] **Step 8: Commit**

```bash
git add app/categories/a10_ssrf tests/test_a10_blocklist_redirect_bypass.py
git commit -m "feat(a10): add blocklist-redirect-bypass example"
```

---

## Task 6: Final Integration — README and Overview Tests

**Files:**
- Modify: `README.md`
- Test: `tests/test_a10_overview.py`

**Interfaces:**
- Consumes: All five examples and the `CategoryNav` from Tasks 1–5.

- [ ] **Step 1: Write the overview/nav tests**

Create `tests/test_a10_overview.py`:

```python
def test_a10_overview_renders(client):
    response = client.get("/a10/")
    assert response.status_code == 200
    assert b"Server-Side Request Forgery" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a10_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")
    assert a10.short_id == "A10"
    assert [e.difficulty for e in a10.examples] == [
        "Easy",
        "Medium",
        "Easy",
        "Medium",
        "Hard",
    ]


def test_a10_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")
    grouped = a10.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Unrestricted Server-Side Fetch",
        "Unsafe URL Scheme Handling",
        "Blocklist Bypass Techniques",
    ]
    assert [e.id for e in grouped[0][1]] == [
        "webhook-internal-metadata",
        "fetch-based-port-scan",
    ]
    assert [e.id for e in grouped[1][1]] == ["file-scheme-local-read"]
    assert [e.id for e in grouped[2][1]] == [
        "blocklist-alternate-ip-bypass",
        "blocklist-redirect-bypass",
    ]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a10_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a10/")
    body = response.data.decode()
    assert "Unrestricted Server-Side Fetch" in body
    assert "Unsafe URL Scheme Handling" in body
    assert "Blocklist Bypass Techniques" in body
```

Note: unlike A08's and A09's group-heading tests, none of A10's three
group names contain a literal `&`, so no HTML-entity-escaped-ampersand
assertion is needed here.

- [ ] **Step 2: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a10_overview.py -v`
Expected: PASS (4 passed)

- [ ] **Step 3: Run the full test suite**

Run: `.venv/bin/pytest tests/ -v`
Expected: all tests pass. Baseline before this plan was 388 (post-A09).
This plan's new tests: 5 (Task 1) + 3 (Task 2) + 4 (Task 3) + 5 (Task 4) +
5 (Task 5) + 4 (Task 6) = 26 new tests → 414 total.

- [ ] **Step 4: Update README.md's intro paragraph**

Modify `README.md` — read the current file fresh before editing (its
exact wrapping/wording may have drifted slightly since this plan was
written). The current final portion of the "Currently implemented"
paragraph reads:

```
..., and **A09 Security Logging and Monitoring
Failures** (failed login attempts never logged, high-value admin action
with no audit trail, sensitive data leaked into log files, unauthenticated
log file exposure, no alert threshold for repeated failures, attack
signature logged but never flagged). Remaining categories (A10) are tracked
separately and follow the same pattern.
```

**A10 is the final category** — unlike every prior category's final-task
README update, this one does NOT move the "and" onto a new final clause
and keep a "Remaining categories" sentence; it moves the "and" onto A10's
clause and REMOVES the "Remaining categories" sentence entirely, since
nothing remains once A10 ships. Replace that whole passage with:

```
..., **A09 Security Logging and Monitoring
Failures** (failed login attempts never logged, high-value admin action
with no audit trail, sensitive data leaked into log files, unauthenticated
log file exposure, no alert threshold for repeated failures, attack
signature logged but never flagged), and **A10 Server-Side Request
Forgery** (webhook tester reaches internal metadata endpoint, same fetcher
enables internal port scanning, PDF generator reads local files via
file:// URL, alternate IP representation bypasses a naive blocklist, open
redirect bypasses a trusted-domain allowlist).
```

(The sentence now ends right after A10's closing parenthesis and period —
do not add anything after it.)

- [ ] **Step 5: Update README.md's category summary table**

Modify `README.md` — replace the line:

```
| A10 | Planned | See `docs/superpowers/specs/2026-09-18-owasp-lab-design.md` |
```

with:

```
| A10 Server-Side Request Forgery | Implemented | Webhook Tester Reaches Internal Metadata Endpoint (Easy), Same Fetcher Enables Internal Port Scanning (Medium), PDF Generator Reads Local Files via file:// URL (Easy), Alternate IP Representation Bypasses a Naive Blocklist (Medium), Open Redirect Bypasses a Trusted-Domain Allowlist (Hard) |
```

**Do not add any further trailing "Planned" row after this one** — A10 is
the last category in the OWASP Top 10 2021 set; the table simply ends
here.

- [ ] **Step 6: Commit**

```bash
git add README.md tests/test_a10_overview.py
git commit -m "docs(a10): update README and add overview/nav tests for A10 (final category)"
```

No live browser verification step is needed for this category — every
A10 example is fully exercisable and provable through the real Flask
test client (real local `HTTPServer` instances and `monkeypatch`-based
DNS resolution for the two self-referential/redirect examples, plus
direct file reads for the `file://` example), matching A08/A09's
precedent of not needing one. The Hard-tier example's full live
reproduction against a real running deployment does need one manual
step (a hosts-file edit) documented in its own template's Exploitation
section — this is a learner-facing manual step, not something this
plan's automated tests need to perform.
