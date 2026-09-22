# OWASP Top 10 Training Lab — A10 Server-Side Request Forgery Design Spec

Date: 2026-09-22
Status: Approved

New category sub-project, following the same from-scratch pattern used to build
A01–A09. This is A10's own full brainstorming cycle, and the FINAL category in
the OWASP Top 10 2021 roadmap — once merged, A01–A10 are all implemented.

## Purpose

Build A10 (OWASP Top 10 2021: Server-Side Request Forgery) as a new category
covering distinct, genuinely working SSRF mechanisms: unrestricted server-side
URL fetches, unsafe URL scheme handling, and two real-world blocklist/allowlist
bypass techniques — every one of them live-verified against this app's actual
stdlib-`urllib`-based implementation before being written into this spec, not
assumed from general SSRF folklore.

## Decisions from brainstorming

- **Overlap with A03's XXE-SSRF example was explicitly checked and avoided.**
  A03's `xxe_ssrf()` route (`app/categories/a03_injection/routes.py:175`) is
  narrowly an XML-entity-expansion vector: the target URL is hardcoded inside
  an `<!ENTITY>` declaration in the uploaded XML, the learner never supplies a
  URL through an ordinary form field, and there's no bypass technique
  involved. A10's examples are the more classic, more common SSRF shape — a
  form field that directly accepts a URL — and are mechanically unrelated to
  XML parsing. No other category touches server-side URL fetching at all;
  this is fresh territory.
- **Two tempting bypass ideas were live-verified and found NOT to work
  against this app's planned implementation, and were dropped rather than
  shipped as fake vulnerabilities:**
  - **Userinfo/authority confusion** (`http://trusted.example@127.0.0.1/`,
    exploiting how some HTTP clients strip credentials before connecting to
    the real host). Verified: Python's `urllib.request.Request` does **not**
    strip the userinfo — `req.host` retains the literal string
    `"trusted.example@127.0.0.1"` and the connection attempt fails with a DNS
    resolution error. This technique works against browsers and some other
    HTTP clients, but not against Python's stdlib `urllib`, which this app
    uses exclusively.
  - **Redirecting from an allowed `http://` URL to a `file://` URI** (to
    bypass a scheme check via redirect-chaining). Verified: `urllib`
    explicitly refuses to follow a redirect whose target scheme isn't in its
    safe list, raising `HTTPError: Redirection to url 'file://...' is not
    allowed`.
- **As a result, A10 ships 5 examples (2 Easy, 2 Medium, 1 Hard), not the 6
  (2/2/2) shape every prior category (A05–A09) delivered.** This was an
  explicit decision, confirmed with the user during brainstorming, choosing
  five genuinely distinct, independently-verified mechanisms over padding to
  six with a technique that either doesn't work or is a near-duplicate of an
  existing example.
- **Every alternate-IP-representation and redirect-bypass payload in this
  spec was live-verified in a scratch Python process before being written
  down**, using a real local `http.server.HTTPServer` and, for the
  redirect-bypass example, a `socket.getaddrinfo` monkeypatch to make a fake
  domain resolve locally — confirmed:
  - `2130706433` (decimal), `0x7f000001` (hex), `127.1` (short-form), and `0`
    (bare zero) all resolve to `127.0.0.1` via Python's real resolver and are
    **not** members of the naive blocklist set `{"127.0.0.1", "localhost"}`.
  - `0177.0.0.1` (dotted octal) does **not** work as hoped — Python parses
    each dot-separated segment independently, so this resolves to the
    literal (wrong) address `177.0.0.1`. Excluded from the exploitation
    payloads for this reason.
  - `urllib.request.urlopen()` follows HTTP redirects by default, and a
    domain resolved only via a monkeypatched resolver is fetched exactly
    like a real one — confirming the redirect-bypass mechanism is genuine,
    not simulated.
- **No new database model is needed anywhere in this category** — a
  deliberate simplification from A08/A09's `RceProof`/`SecurityEvent`
  pattern. SSRF's proof is the fetched content itself: it comes back
  directly in the HTTP response the learner already sees, with no
  out-of-band execution to record. Adding a DB-backed proof table here would
  be pure ceremony with no functional benefit.
- **The internal-only target genuinely restricts access, unlike A03's
  `/healthz` precedent (a generic health check anyone could always reach
  anyway).** `/a10/internal/metadata` checks `request.remote_addr ==
  "127.0.0.1"` and returns 403 to anyone else. Verified: Werkzeug's Flask
  test client defaults to `REMOTE_ADDR=127.0.0.1` for every request (so a
  plain test-client GET already represents "arrived via loopback"), and
  `environ_overrides={"REMOTE_ADDR": "203.0.113.5"}` genuinely simulates an
  external caller for a negative-control test. This makes the category's
  core narrative concrete and testable: the vulnerable routes' own outbound
  fetches arrive at this endpoint via the loopback interface in a real
  deployment, inheriting a trust boundary an external attacker could never
  cross directly — exactly the SSRF lesson OWASP's own description centers
  on ("even when protected by a firewall... network ACL").
- **The Hard-tier redirect-bypass example cannot be fully reproduced by a
  live learner without one extra manual step** (adding a hosts-file entry
  for the fake trusted domain, since no real DNS record exists for it) — the
  Exploitation section documents this explicitly, along with a short,
  complete, copy-pasteable Python script the learner runs locally to serve
  the redirect (extending this session's established
  `python3 -m http.server`-style local-infrastructure convention, since a
  redirect needs a few lines of custom handler code a bare static server
  can't provide).

## Components

### Group 1: Unrestricted Server-Side Fetch

**1. Webhook Tester Reaches Internal Metadata Endpoint (Easy)** — `id:
webhook-internal-metadata`. `GET/POST /a10/webhook-tester`. A "test your
webhook URL" feature fetches whatever URL is submitted and displays the raw
response, with zero validation:

```python
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
        webhook_url=webhook_url, result=result, error=error,
    )
```

Exploitation: submit `http://127.0.0.1:5000/a10/internal/metadata` (in a real
deployment, this reaches the app's own internal-only endpoint, which trusts
any loopback-origin request) and the fake internal credentials come back in
the response.

**2. Same Fetcher Enables Internal Port Scanning (Medium)** — `id:
fetch-based-port-scan`. `GET /a10/port-scan-demo` — its own dedicated,
ExampleNav-registered teaching page (matching A08's convention that every
`ExampleNav` entry points at its own distinct route, never silently reuses
another example's exact endpoint), but with **no new vulnerable backend
logic at all**: its `live_example` block embeds the identical
`webhook_url` form, submitting directly to the existing
`/a10/webhook-tester` route, exactly as A08's Hard-tier pages linked to
("Trigger It: Go to Cart") or directly embedded a form targeting an
already-existing vulnerable route rather than duplicating its logic. The
page's explanation/detect/exploitation content deepens the same
mechanism's consequence: submitting URLs at different internal ports
produces genuinely different, distinguishable outcomes (a real HTTP
response vs. a clean "could not reach" error surfaced from a connection
refusal) — letting an attacker map which internal services exist without
ever seeing a byte of their actual protocol traffic.

### Group 2: Unsafe URL Scheme Handling

**3. PDF Generator Reads Local Files via `file://` URL (Easy)** — `id:
file-scheme-local-read`. `GET/POST /a10/pdf-generator`. A "generate a PDF
from this webpage" feature passes the submitted URL straight to
`urllib.request.urlopen()` with no scheme restriction — Python's `urllib`
has built-in support for `file://` URIs, so a local file path works exactly
like a real webpage URL would:

```python
@a10_bp.route("/pdf-generator", methods=["GET", "POST"])
def pdf_generator():
    result = None
    error = None
    page_url = ""
    if request.method == "POST":
        page_url = request.form.get("page_url", "")
        try:
            # VULNERABLE: no scheme allowlist -- file://, and anything else
            # urllib supports, is fetched exactly like http(s)://.
            with urllib.request.urlopen(page_url, timeout=5) as resp:
                result = resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            error = f"Could not generate PDF from URL: {e}"
    return render_template(
        "a10_ssrf/pdf_generator.html",
        page_url=page_url, result=result, error=error,
        fake_secret_file_url=f"file://{FAKE_SECRET_FILE_PATH}",
    )
```

The teaching page renders the exact working `file://` URL (computed from
`BASE_DIR`, matching A09's `LOG_FILE_PATH` convention for absolute-path
constants) pointing at a small, purpose-built fake secret file shipped in
the repo at `app/categories/a10_ssrf/internal_data/fake_secret.txt`, so the
exploit payload is always correct regardless of where the repo is checked
out — no guessing a real system path like `/etc/passwd`.

### Group 3: Blocklist Bypass Techniques

**4. Alternate IP Representation Bypasses a Naive Blocklist (Medium)** —
`id: blocklist-alternate-ip-bypass`. `GET/POST /a10/import-avatar`. An
"import your avatar from a URL" feature validates the submitted URL's
*parsed hostname* against a blocklist before fetching:

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
        # any other representation of the same address sails right through.
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
        avatar_url=avatar_url, result=result, error=error,
    )
```

Exploitation payloads (all live-verified to resolve to `127.0.0.1` and to
NOT be blocklist members): `http://2130706433:5000/a10/internal/metadata`
(decimal), `http://0x7f000001:5000/a10/internal/metadata` (hex),
`http://127.1:5000/a10/internal/metadata` (short-form),
`http://0:5000/a10/internal/metadata` (bare zero — Linux treats `0` as
`INADDR_ANY`, which routes to loopback for an outbound connection).

**5. Open Redirect Bypasses a Trusted-Domain Allowlist (Hard)** — `id:
blocklist-redirect-bypass`. `GET/POST /a10/mirror-fetcher`. A "fetch from
one of our approved content mirrors" feature validates the submitted URL's
host against an ALLOWLIST — the more defensible-looking pattern, compared
to Group 3's Medium example's blocklist — but validates only the
*submitted* URL, not wherever a redirect ultimately leads:

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
        mirror_url=mirror_url, result=result, error=error,
    )
```

Exploitation (live reproduction against the real deployed app requires one
manual step, since no real DNS record exists for the fake trusted domain):

```bash
# 1. Make the fake trusted domain resolve to your own machine:
echo "127.0.0.1 trusted-mirror.example" | sudo tee -a /etc/hosts

# 2. Serve a redirect to the app's internal-only endpoint:
python3 -c '
from http.server import BaseHTTPRequestHandler, HTTPServer

class Redirect(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1:5000/a10/internal/metadata")
        self.end_headers()

HTTPServer(("127.0.0.1", 8080), Redirect).serve_forever()
'
```

Then submit `http://trusted-mirror.example:8080/` as the mirror URL — the
allowlist check sees and approves `trusted-mirror.example`, and the fetch
follows the redirect straight to the internal-only endpoint.

### Shared internal-only target

`GET /a10/internal/metadata` (non-nav utility endpoint, mirroring A08's
`/a08/rce-proof` convention) — every example that reaches a live internal
target points at this same route, tying the category together narratively:

```python
@a10_bp.route("/internal/metadata")
def internal_metadata():
    if request.remote_addr != "127.0.0.1":
        abort(403)
    return Response(
        "instance-id: i-0a1b2c3d4e5f6g7h8\n"
        "iam-role: training-lab-admin\n"
        "access-key: AKIAFAKESSRFPROOF1234\n"
        "secret-key: fake-secret-do-not-use-ssrf-proof-9f3c2b1a\n",
        mimetype="text/plain",
    )
```

## Data Model

None. No new SQLAlchemy model, no `models.py`, no `seed_fn` — every
example's proof is the raw fetched HTTP response content itself, already
visible in the page the learner is looking at. This mirrors A06's
lightweight, no-persisted-state category shape, not A08/A09's DB-proof
pattern (which exists specifically to make invisible server-side execution
visible — a concern that doesn't apply here, since nothing executes
out-of-band; the server just makes a request and shows you what came back).

## Navigation

New `CategoryNav` registered in `app/core/nav.py`'s `CATEGORIES` list (via
`app/categories/a10_ssrf/__init__.py`, following the exact A05–A09
pattern): `id="a10_ssrf"`, `short_id="A10"`, `title="Server-Side Request
Forgery"`, a blurb describing unrestricted server-side fetches, unsafe
scheme handling, and blocklist/allowlist bypasses, `overview_endpoint=
"a10_ssrf.overview"`, no `seed_fn`. Five `ExampleNav` entries in the three
groups above, in flat difficulty order `[Easy, Medium, Easy, Medium, Hard]`
(Group 1 is Easy→Medium, Group 2 is a single Easy entry, Group 3 is
Medium→Hard — each group internally Easy-to-Hard, satisfying
`grouped_examples()`'s per-group sortedness requirement; Group 2 having
only one example is an accepted uneven group size, matching A07's own
precedent of unevenly-sized groups within a single category).

`/a10/internal/metadata` is registered as a non-nav utility endpoint.

## Testing

- Route-level tests for all five examples via the normal `client`/`app`
  fixtures: legitimate use works; the vulnerable behavior is genuinely
  provable through the real Flask test client, never a bare string check
  that could pass regardless of real behavior:
  - **Example 1**: a real local `http.server.HTTPServer` (matching A03's
    `test_xxe_ssrf_resolver_genuinely_fetches_http_entities` and A08's
    plugin-marketplace precedent) stands in for the fetch target, serving
    the same fake-secret-shaped content the real `/a10/internal/metadata`
    route would — proving the unrestricted-fetch mechanism genuinely works.
    Separately, `/a10/internal/metadata` itself is tested directly: a
    default test-client GET (REMOTE_ADDR defaults to `127.0.0.1`) gets 200
    + the fake credentials; a GET with `environ_overrides={"REMOTE_ADDR":
    "203.0.113.5"}` gets 403 — proving the access restriction is real, not
    decorative.
  - **Example 2**: `/a10/port-scan-demo` itself is tested like every other
    example's page (renders, appears in the overview once registered).
    The differential-response claim is tested against the shared
    `/a10/webhook-tester` route it embeds a form for: one real local
    `HTTPServer` (the "open" port) plus one definitely-closed port
    (obtained by binding an ephemeral socket, reading back its assigned
    port, then closing it immediately — a standard, portable
    "guaranteed closed port" pytest idiom) — asserting genuinely
    different, distinguishable responses for each.
  - **Example 3**: reads the real fake secret file directly off disk to get
    its expected content, then asserts a `file://` submission returns that
    exact content through the live route — no synthetic double needed,
    since `file://` never touches the network.
  - **Example 4**: ONE real local `HTTPServer` bound to `127.0.0.1`, reused
    across all four alternate-IP payloads by changing only the host string
    in the submitted URL and keeping the same port — since `2130706433`,
    `0x7f000001`, `127.1`, and `0` all resolve to the exact same address,
    a single server is reachable via every one of them (verified live
    during brainstorming; no need for four separate servers). Assert the
    blocklist is genuinely bypassed (real content returned, not the "not
    allowed" error) for each encoding, while a literal
    `127.0.0.1`/`localhost` submission targeting the same server is still
    correctly rejected (positive control proving the blocklist isn't simply
    inert).
  - **Example 5**: `socket.getaddrinfo` monkeypatched locally within this
    one test file (via pytest's built-in `monkeypatch` fixture — no
    `conftest.py` changes) so `trusted-mirror.example` resolves to a real
    local `HTTPServer` serving a 302 to a second real local `HTTPServer`
    (the "internal target") — asserting the allowlist check passes the
    submitted domain and the final fetched content is genuinely the
    redirect target's, not the redirector's own.
- `tests/test_a10_overview.py` mirrors `test_a09_overview.py`: overview
  renders, nav registration, `grouped_examples()` structure and
  Easy-to-Hard sortedness (note: the difficulty list for this test is
  `["Easy", "Medium", "Easy", "Medium", "Hard"]` — five entries, not six,
  reflecting this category's 5-example shape), group headings render on the
  overview page.
- README.md's category summary table gets A10's row (Implemented status,
  full example list). **A10 is the final category** — the trailing
  "Planned" row (currently `A10 | Planned | ...`) is removed entirely
  rather than renumbered, and the intro paragraph's "Remaining categories"
  sentence is removed rather than updated, since there is nothing left to
  reference.

## Out of scope for this spec

- Any real network-level SSRF protections (a real egress firewall, a real
  metadata-service IP like `169.254.169.254`) — this is a single-container
  training app; the internal-only target is simulated as a same-app route
  with its own access check, per the Decisions section above.
- DNS rebinding — requires a real, TTL-manipulable DNS server to
  demonstrate live; out of scope for a self-contained training app with no
  external infrastructure dependency.
- Any SSRF-to-internal-protocol-smuggling technique (e.g. `gopher://`-based
  attacks against Redis/MySQL-style services) — would require raw-socket
  protocol crafting well beyond this app's established minimal-complexity,
  stdlib-only posture, and risks the same kind of fragile/exploit-tooling
  territory this session has deliberately steered away from before (see
  A06/A08's RCE-avoidance precedent).
- Any change to A03's existing XXE-SSRF example, or to any other existing
  category's routes, templates, or tests.
- Progress tracking changes — the existing `{% block tasks %}` and "Mark as
  done" mechanisms are reused as-is (no multi-task examples in this spec;
  every A10 example is single-shot, matching every prior category's
  style).
