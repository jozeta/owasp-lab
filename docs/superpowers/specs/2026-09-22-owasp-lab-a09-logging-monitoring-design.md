# OWASP Top 10 Training Lab — A09 Security Logging and Monitoring Failures Design Spec

Date: 2026-09-22
Status: Approved

New category sub-project, following the same from-scratch pattern used to build
A01–A08. This is A09's own full brainstorming cycle.

## Purpose

Build A09 (OWASP Top 10 2021: Security Logging and Monitoring Failures) as a
new category with six examples — two per difficulty tier, per the user's
explicit request — covering distinct, genuinely demonstrable logging,
log-storage, and alerting/detection gaps not already covered elsewhere in the
app.

## Decisions from brainstorming

- **Overlap with A05 and A07 was explicitly mapped and avoided.** A05 already
  owns "Verbose Error Message Disclosure" — a stack trace shown *on the error
  page itself*. A07 already owns "No Rate Limiting Enables Brute Force" — the
  absence of a *prevention* control. Neither touches whether an event gets
  recorded or escalated at all. A09's angle is strictly the *detection and
  response* gap: an event happens and either isn't logged, is logged
  insecurely, or is logged but never alerted on. The category's own Group 1
  "Failed Login Attempts Never Logged" example deliberately sits on the exact
  same surface as A07's brute-force example (repeated failed logins) but
  proves a different failure mode — A07 proves nothing stops the attempts;
  A09 proves nothing *notices* them, even without any rate limit in play.
  Confirmed via fresh reads of `a05_security_misconfiguration/__init__.py`
  and `a07_auth_failures/__init__.py` — no other category touches logging,
  log storage, or alerting at all; this is fresh territory.
- **No existing logging infrastructure exists anywhere in the app** (grepped
  the whole `app/` tree) — A09 introduces the category's own, self-contained
  mechanism rather than reusing or retrofitting anything shared.
- **Core mechanism, chosen over two other options during brainstorming (a
  DB-only design, and a file-only design using Python's real `logging`
  module):** a hybrid of (a) a shared `SecurityEvent` database table plus a
  `log_security_event(event_type, detail)` helper — directly modeled on
  A08's proven `RceProof`/`write_rce_proof()` pattern — used correctly by
  some routes and deliberately skipped by others, and (b) one genuine
  on-disk log file (`instance/a09_app.log`, plain-text append, not Python's
  `logging` module) specifically for the two log-*storage* examples, since
  "sensitive data leaked into a log file" and "the log file itself is
  exposed" are only convincing with a real file. A DB-only design would have
  made the log-storage examples abstract (dumping a database table isn't the
  same lesson as an exposed log file); a file-only design would have made
  every other example's assertions fragile string/regex parsing instead of
  structured row counts, and risks the kind of shared-mutable-state surprise
  already documented in this session for in-memory globals under gunicorn's
  multiple workers — though a real file, unlike an in-memory Python global,
  survives correctly across workers because it's genuine disk I/O, so the
  storage examples use it deliberately and only where the lesson requires a
  real file.
- **Every example includes a working positive control**, so no test can pass
  vacuously (per this session's recurring lesson from A06, A07, and A08):
  each vulnerable route sits next to, or precedes, a route that correctly
  writes to the same log, proving the logging mechanism itself works before
  the example proves it wasn't used where it mattered.
- **The "Active Alerts" concept needs no real detection logic.** Group 3's
  entire point is that no such capability exists anywhere in the app —
  implementing even a toy pattern-matcher would undercut the lesson. The
  shared monitoring page renders a literal, permanently-empty "Active Alerts
  (0)" panel with no backing computation at all; the examples prove that
  even blatant signals (a burst of failures, an injection probe string sitting
  in the log verbatim) never move that number.
- **Example 6's reflected search query is Jinja-escaped exactly like every
  other user-controlled value elsewhere in the app** (`{{ }}` expression, not
  raw block text) — this example is about logging visibility and missing
  detection, not injection; an accidental unescaped reflection would
  duplicate A03's territory and is explicitly guarded against.
- **Six examples, two per tier, in three groups.** Group 2's Hard example
  reuses Group 2's Easy example's exact log-write mechanism and log file
  (mirroring A08's established "Hard tier proves a strictly worse
  consequence of the same underlying mechanism" pattern) rather than
  inventing an unrelated bug.

## Components

### Group 1: Missing Audit Logging

**1. Failed Login Attempts Never Logged (Easy)** — `id:
failed-logins-not-logged`. `GET/POST /a09/login`. A login form checks
credentials against a fixed demo account. On success, the route calls
`log_security_event("user_login_success", "user=demo")` — a real, working
call, visible on the shared monitoring page. On failure, the route returns
an error message to the user but never calls `log_security_event()` at all,
regardless of how many consecutive failed attempts occur:

```python
@a09_bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == "demo" and password == "demo-password":
            log_security_event("user_login_success", f"user={username}")
            error = None
        else:
            # VULNERABLE: a failed login attempt is a textbook auditable
            # event (OWASP's own A09 examples call this out by name) --
            # this branch never logs anything at all, no matter how many
            # times it's hit.
            error = "Invalid username or password."
    return render_template("a09_logging_monitoring_failures/login.html", error=error)
```

The Exploitation section has the learner submit 10+ wrong-password attempts,
then check the shared monitoring page (`/a09/security-events`) and see the
event count is unchanged — while a single successful login (`demo` /
`demo-password`) immediately adds a real row, proving the mechanism works
and simply isn't wired to the failure path. Distinct from A07's brute-force
example: this route has no rate limiting either (matching the rest of this
training app's convention of one gap per lesson), but the point being taught
is different — nothing here *notices* the attempts, independent of whether
anything stops them.

**2. High-Value Admin Action With No Audit Trail (Medium)** — `id:
admin-action-no-audit`. `GET /a09/admin-actions` (form-based demo page, no
real auth gate — matching this category's teaching-page convention, not an
access-control lesson) with two actions. "Create User" logs
`log_security_event("admin_user_created", f"username={username}")` — a real,
working call. "Delete User" performs the deletion but never calls
`log_security_event()` at all. The demo user list lives in the Flask
session cookie (`session["a09_demo_users"]`), not a module-level global —
per-browser and safe across gunicorn's multiple worker processes, unlike an
in-memory Python set (the exact pitfall this session has already documented
elsewhere for A05's debugger note, and explicitly avoided again here):

```python
@a09_bp.route("/admin-actions", methods=["GET", "POST"])
def admin_actions():
    users = session.get("a09_demo_users", ["alice", "bob"])
    if request.method == "POST":
        action = request.form.get("action")
        username = request.form.get("username", "")
        if action == "create":
            if username and username not in users:
                users.append(username)
            log_security_event("admin_user_created", f"username={username}")
        elif action == "delete":
            if username in users:
                users.remove(username)
            # VULNERABLE: a destructive, high-value admin action -- the
            # exact kind of event OWASP's A09 calls out by name -- and it
            # writes nothing to the audit log at all.
        session["a09_demo_users"] = users
    return render_template(
        "a09_logging_monitoring_failures/admin_actions.html", users=sorted(users)
    )
```

The Exploitation section has the learner create a user (sees the event
appear), then delete a user (sees nothing appear), demonstrating selective,
incomplete instrumentation of otherwise-parallel actions.

### Group 2: Insecure Log Storage

**3. Sensitive Data Leaked Into Log Files (Easy)** — `id:
sensitive-data-in-logs`. `GET/POST /a09/support-login`. A second, separate
login-style form (a "support portal" login, distinct from example 1's route
so this example is self-contained) that, on any failed attempt, writes the
*entire raw submitted form data, including the plaintext password field*, to
the real on-disk log file:

```python
@a09_bp.route("/support-login", methods=["GET", "POST"])
def support_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == "support" and password == "letmein123":
            error = None
        else:
            # VULNERABLE: logs the FULL submitted credentials, including
            # the plaintext password, straight into the app's log file --
            # a textbook CWE-532 sensitive-data-in-logs bug.
            append_to_app_log(
                f"support-login failed: username={username!r} password={password!r}"
            )
            error = "Invalid username or password."
    return render_template("a09_logging_monitoring_failures/support_login.html", error=error)
```

The Exploitation section has the learner submit a memorable fake password
(e.g. `hunter2-totally-real-password`), then view the shared monitoring
page's raw log-file tail panel and find that exact password sitting in
plaintext in a file meant for operational diagnostics, not credential
storage.

**4. Unauthenticated Log File Exposure (Hard)** — `id:
log-file-world-readable`. `GET /a09/log-exposure-demo` (teaching page) that,
on load, plants one more distinctive secret into the *same* log file via
`append_to_app_log()` (self-contained — no dependency on having visited
example 3 first), then `GET /a09/download-log` — a route with **no
authentication or authorization check whatsoever** — serves the raw file
contents as a download:

```python
@a09_bp.route("/download-log")
def download_log():
    # VULNERABLE: the operational log file -- which may contain
    # plaintext credentials logged by the support-login example -- is
    # served to absolutely anyone, no session or role check at all.
    return Response(_read_app_log(), mimetype="text/plain")
```

The Exploitation section has the learner visit the demo page, then fetch
`/a09/download-log` directly (no login, no cookie, a fresh incognito-style
request) and find the just-planted secret — and, if example 3 was also
visited earlier, every other visitor's plaintext password too — proving the
log store itself has no access control, independent of whatever wrote to
it.

### Group 3: No Detection & Alerting for Active Attacks

**5. No Alert Threshold for Repeated Failures (Medium)** — `id:
no-alert-threshold`. `GET/POST /a09/monitored-login`. A third, independent
login-style route where *every* attempt — success or failure — correctly
calls `log_security_event()` (isolating this example from example 1's gap):

```python
@a09_bp.route("/monitored-login", methods=["GET", "POST"])
def monitored_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == "demo" and password == "demo-password":
            log_security_event("monitored_login_success", f"user={username}")
        else:
            log_security_event("monitored_login_failed", f"user={username}")
            error = "Invalid username or password."
    return render_template("a09_logging_monitoring_failures/monitored_login.html", error=error)
```

The Exploitation section has the learner submit 20 consecutive failed
attempts, confirm on the shared monitoring page that all 20 are genuinely
logged (proving the logging half of the system works perfectly here), and
observe the "Active Alerts" panel never leaves 0 — no lockout, no
escalation, no notification, no matter how obvious the pattern is in the
data that's sitting right there.

**6. Attack Signature Logged But Never Flagged (Hard)** — `id:
attack-signature-not-flagged`. `GET /a09/product-search?q=...`. A search
box that logs every query verbatim via `log_security_event("product_search",
f"query={query}")` and echoes the query back on the page (Jinja-escaped via
a normal `{{ query }}` expression — never raw/unescaped, so this stays a
logging-visibility lesson, not an injection one):

```python
@a09_bp.route("/product-search")
def product_search():
    query = request.args.get("q", "")
    if query:
        log_security_event("product_search", f"query={query}")
    return render_template("a09_logging_monitoring_failures/product_search.html", query=query)
```

The Exploitation section has the learner submit an unmistakable attack
signature as the query — e.g. `' OR '1'='1' --` or `../../../../etc/passwd`
— and shows two things side by side: the shared monitoring page's event log
contains that exact string, verbatim, fully visible (so the app *did*
capture the evidence) — and "Active Alerts" is still 0, because nothing in
this codebase ever pattern-matches logged content against known attack
signatures. This directly matches OWASP's own A09 example: "using APIs
where there is no ability to detect, escalate, or alert for active attacks
in real time or near real time."

## Data Model

```python
class SecurityEvent(db.Model):
    __tablename__ = "a09_security_events"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(64), nullable=False)
    detail = db.Column(db.String(255), nullable=False)
    logged_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
```

No other persisted model is needed. Example 2's demo user list is carried in
the Flask session cookie (`session["a09_demo_users"]`), not a module-level
global or its own SQLAlchemy model — it exists purely to give "create"/
"delete" a visible effect for the one browser using it, is never treated as
real user/account data, and (being a signed cookie, not server memory) is
correctly consistent regardless of which gunicorn worker handles a given
request.

The on-disk log file lives at `<BASE_DIR>/instance/a09_app.log` (using the
`BASE_DIR` constant already defined in `app/__init__.py`), is plain text,
append-only, and both the directory and file are created lazily on first
write (`os.makedirs(..., exist_ok=True)`) since `instance/` does not
currently exist on disk. It is not tracked in git — `instance/` is already
in `.gitignore` at the repo root, an existing convention this is the first
example to actually use. It is read back by both the shared monitoring page
and the `/a09/download-log` route via one small shared helper
(`_read_app_log()`), never duplicated, and the container's existing
`chown -R appuser:appuser /app` step in the `Dockerfile` already makes this
location writable by the process user — no Dockerfile change is needed.

## Navigation

New `CategoryNav` registered in `app/core/nav.py`'s `CATEGORIES` list (via
`app/categories/a09_logging_monitoring_failures/__init__.py`, following the
exact A05–A08 pattern): `id="a09_logging_monitoring_failures"`,
`short_id="A09"`, `title="Security Logging and Monitoring Failures"`, a
blurb describing missing audit trails, insecure log storage, and the
absence of alerting/detection, `overview_endpoint=
"a09_logging_monitoring_failures.overview"`, no `seed_fn` (`SecurityEvent`
starts empty and the on-disk log file starts absent — both are written to
only by the examples themselves). The six `ExampleNav` entries land in the
three groups described above, in Easy→Hard flat-list order per group (Group
1 is Easy→Medium, Group 2 is Easy→Hard, Group 3 is Medium→Hard — satisfying
`grouped_examples()`'s per-group sortedness requirement).

`/a09/security-events` (the shared monitoring page showing the
`SecurityEvent` table, the "Active Alerts (0)" panel, and the log-file tail)
is registered as a non-nav utility endpoint, mirroring A08's
`/a08/rce-proof` convention exactly.

## Testing

- Route-level tests for all six examples via the normal `client`/`app`
  fixtures: legitimate use works for each example (with a genuine positive
  control — a successful action that DOES produce a new `SecurityEvent`
  row); the vulnerable behavior is genuinely provable through real database
  row counts and real file contents, never a bare substring check that
  static teaching prose could also satisfy:
  - Examples 1–2: a successful login/create-user action increases
    `SecurityEvent.query.count()` by exactly 1 with the correct
    `event_type`; repeated failed logins / a delete-user action leave the
    count unchanged.
  - Examples 3–4: after a failed support-login submission with a
    distinctive fake password, the on-disk log file (read directly, not via
    any route) contains that exact password string; `GET
    /a09/download-log` with a fresh, cookie-less test client still returns
    200 and the same content, proving no auth gate exists.
  - Example 5: 20 submissions (mixed success/failure) to
    `/a09/monitored-login` produce exactly 20 new `SecurityEvent` rows with
    the correct `event_type` values — proving the logging half works — while
    nothing in the response or any other state ever reflects an "alert"
    (there is no alert model/count to increment in the first place, so this
    is confirmed by absence: no route, template, or model anywhere produces
    a non-zero alert count).
  - Example 6: submitting an attack-signature query string produces a new
    `SecurityEvent` row whose `detail` contains that exact string verbatim,
    and the rendered search-results page contains the Jinja-escaped form of
    that string (confirming no unescaped reflection), while — as with
    example 5 — no alert count anywhere becomes non-zero.
- `tests/test_a09_overview.py` mirrors `test_a08_overview.py` exactly:
  overview renders, nav registration, `grouped_examples()` structure and
  Easy-to-Hard sortedness, group headings render on the overview page.
- README.md's category summary table gets A09's row (Implemented status,
  full example list), matching every other row's format exactly, and the
  trailing "Planned" row becomes "A10".

## Out of scope for this spec

- A10 (a separate, future sub-project).
- Any real detection/alerting logic of any kind — the entire point of
  Group 3 is that none exists; implementing even a toy version would
  undercut the lesson (see Decisions above).
- Any change to A05's "Verbose Error Message Disclosure" example, A07's
  "No Rate Limiting Enables Brute Force" example, or any other existing
  category's routes, templates, or tests.
- Any new third-party logging/monitoring dependency (e.g. Python's
  `logging` module's handler ecosystem, or a real APM/SIEM integration) —
  a plain file-append helper and a database table cover this category's
  needs fully, matching this app's established minimal-dependency posture.
- Progress tracking changes — the existing `{% block tasks %}` and "Mark as
  done" mechanisms are reused as-is (no multi-task examples in this spec;
  every A09 example is single-shot, matching every prior category's style).
