# OWASP Top 10 Training Lab — A05 Security Misconfiguration Design Spec

Date: 2026-09-21
Status: Approved
New category sub-project, following the same from-scratch pattern used to build
A01–A04. A05–A10 were always planned but undesigned (the master spec at
`docs/superpowers/specs/2026-09-18-owasp-lab-design.md` only fully detailed A01 as
a reference/pilot category); this is A05's own full brainstorming cycle.

## Purpose

Build A05 (OWASP Top 10 2021: Security Misconfiguration) as a new category with
six examples — two per difficulty tier, per the user's explicit request — covering
distinct, genuinely exploitable real-world misconfiguration patterns not already
covered elsewhere in the app (XXE is already A03; this spec avoids re-treading it).

## Decisions from brainstorming

- **Six examples, two per tier, grouped into three tier-pure groups** (unlike
  A04's one-per-tier shape): "Exposed Files & Directories" (Easy, Easy),
  "Insecure Response Configuration" (Medium, Medium), "Exposed Debug & Admin
  Interfaces" (Hard, Hard). Keeping each group internally uniform in difficulty
  makes the Easy→Hard sortedness invariant trivial to satisfy and mirrors how
  A03's deepening work grouped multiple same-subtype examples together.
- **No new database models or seed function needed.** Every example's fake
  sensitive content is either a bundled file or hardcoded in its route,
  matching A04's precedent (A04 also has no `seed_fn`).
- **Three technical claims were live-verified before finalizing this spec, not
  assumed:**
  - The Werkzeug interactive debugger genuinely allows remote code execution
    when `WERKZEUG_DEBUG_PIN` is disabled: a scratch Flask app was crashed
    with debug mode on, and `subprocess.check_output(['id'])` was executed
    through the debugger's console endpoint, returning real shell output
    (`uid=501(zeta)...`).
  - Scoping the debugger to *one* route without exposing it app-wide is
    possible via Werkzeug's `DispatcherMiddleware`, mounting a small internal
    Flask sub-app (with `DEBUG`/`PROPAGATE_EXCEPTIONS` enabled only on that
    sub-app) at a dedicated URL prefix. Verified live: a normal route on the
    main app still returns Flask's plain 500 page on an uncaught exception,
    while the mounted sub-app's route gets the real interactive debugger and
    genuine RCE (`subprocess.check_output(['whoami'])` → `zeta`) — zero blast
    radius on the rest of the app.
  - A CORS misconfiguration that reflects the request's `Origin` header back
    verbatim (instead of validating against an allowlist), combined with
    `Access-Control-Allow-Credentials: true`, is genuinely exploitable by a
    truly cross-site attacker page reading a victim's session-scoped secret —
    but only once two further facts, also verified live, are accounted for:
    a literal `Access-Control-Allow-Origin: *` is correctly *rejected* by real
    browsers when credentials are involved (confirmed: `fetch` with
    `credentials: 'include'` against a wildcard-origin response fails with
    `TypeError: Failed to fetch`), and Flask's session cookie defaults to
    `SameSite=Lax`, which blocks the cookie on a **genuinely cross-site**
    request (a same-host-different-port test looked like it worked but was a
    false positive — SameSite treats different ports on `127.0.0.1` as the
    *same* site; retesting with a real cross-site pair, `127.0.0.1` vs
    `localhost`, confirmed `SameSite=Lax` blocks it as expected). Making the
    example genuinely exploitable against a real external attacker therefore
    requires the vulnerable endpoint's cookie to explicitly use
    `SameSite=None; Secure` — verified live that Chrome accepts a `Secure`
    cookie over plain HTTP specifically because `127.0.0.1` is treated as a
    secure context (the loopback exception), and that the full chain then
    works end-to-end against a genuinely cross-site attacker page.
- **The CORS example's cookie is a dedicated, hand-set cookie scoped to that
  one example** (`resp.set_cookie("a05_loyalty_token", ..., samesite="None",
  secure=True)`), not a change to Flask's global `SESSION_COOKIE_SAMESITE`
  config — changing that globally would weaken every other category's
  session-based mechanics (login state, admin auth, etc.) for one example's
  sake.
- **The Werkzeug-debugger example needs one small, explicit architectural
  change**: `wsgi.py` composes the final WSGI callable by wrapping the main
  Flask app with `DispatcherMiddleware`, mounting a tiny internal-tools
  sub-app (debugger enabled) at `/internal-tools`. The Dockerfile/gunicorn
  config is unaffected (gunicorn already just calls whatever WSGI callable
  `wsgi:app` resolves to; the composed object keeps that same name). This is
  the one part of this spec that touches shared infrastructure rather than
  being purely additive within `app/categories/a05_security_misconfiguration/`.
- **Testing implication of the above:** the normal Flask `client` test fixture
  (built from the bare `create_app()` Flask app) does not exercise the
  `DispatcherMiddleware`-mounted sub-app at all. The debugger example's tests
  need a dedicated `werkzeug.test.Client` wrapping the actual composed WSGI
  callable — a new, one-off test pattern for this codebase, confined to that
  one test file.

## Components

### Group 1: Exposed Files & Directories

**1. Exposed Database Backup File (Easy)** — `id: exposed-backup`. Teaching
page at `GET /a05/backup-exposure` explains that automated nightly backups are
written to a predictable, web-accessible path with no access control. The raw
artifact, `GET /a05/backups/db_backup_2024-01-15.sql.bak`, serves (with no
auth check at all) a bundled fake SQL dump excerpt containing realistic-looking
`INSERT`-style config rows: a fake `DATABASE_URL` connection string with
credentials, a fake `STRIPE_SECRET_KEY`, and a fake `SESSION_SECRET` — mirrors
the existing `xxe_secret.txt`/`cmd_secret.txt` convention of a real bundled
file with plausible fake secrets.

**2. Directory Listing Exposed (Easy)** — `id: directory-listing`. Teaching
page at `GET /a05/directory-listing`. The raw artifact, `GET /a05/uploads/`,
renders a deliberately unstyled page (no `example_page_base.html` chrome — it
should look like a genuine misconfigured web-server directory index, not part
of this app's UI) listing filenames (`Q3_payroll_export.csv`,
`meeting_notes.txt`, `site_backup_old.zip`), each linking to
`GET /a05/uploads/<filename>`, which serves hardcoded fake content per file —
`Q3_payroll_export.csv` contains fake employee names, SSNs, and salaries.

### Group 2: Insecure Response Configuration

**3. Verbose Error Message Disclosure (Medium)** — `id: verbose-errors`.
`GET/POST /a05/inventory-check`, a "check warehouse inventory" feature.
Submitting a SKU triggers a simulated internal connection failure whose
exception message embeds a fake internal secret:

```python
WAREHOUSE_DB_PASSWORD = "wh_S3rv1ce_2024!"

try:
    raise ConnectionError(
        f"Failed to connect to warehouse DB at "
        f"postgresql://warehouse_svc:{WAREHOUSE_DB_PASSWORD}@10.0.4.12:5432/inventory "
        f"while looking up SKU '{sku}'"
    )
except Exception as e:
    # VULNERABLE: the raw exception message and full traceback are rendered
    # directly back to the client
    error_detail = "".join(traceback.format_exception(type(e), e, e.__traceback__))
```

This is deliberately a plain information-disclosure bug (a manually-rendered
error message, not Werkzeug's interactive debugger) — kept distinct in kind
and severity from the Hard-tier debugger example below, which is genuine RCE.

**4. Permissive CORS with Credentials (Medium)** — `id: cors-credentials`.
Teaching page `GET /a05/cors-credentials` sets a dedicated cookie
(`a05_loyalty_token`, `SameSite=None; Secure`, live-verified to work over
plain HTTP on `127.0.0.1`) if not already present. The vulnerable API,
`GET /a05/api/loyalty-status`, reflects the request's `Origin` header
verbatim as `Access-Control-Allow-Origin` and sets
`Access-Control-Allow-Credentials: true`. The Exploitation/Try-It section
gives a copy-pasteable attacker HTML snippet (matching this session's
established pattern of handing the learner an external artifact for
cross-process/cross-origin exploits, e.g. the DOM-XSS and sqlmap/commix
examples) — the learner saves it and opens it from any different origin
(a different port on `127.0.0.1` is *not* sufficient to demonstrate the real
exploit, since SameSite treats different ports on the same host as the same
site; the page's instructions say so explicitly and suggest `python3 -m
http.server` on a different hostname alias, e.g. `localhost` vs `127.0.0.1`,
matching what was verified live).

### Group 3: Exposed Debug & Admin Interfaces

**5. Exposed Debug Console (Hard)** — `id: debug-console-rce`. Teaching page
`GET /a05/internal-diagnostics` (normal `example_page_base.html` page, in the
main app) explains that a legacy internal diagnostics tool was mounted
separately and accidentally shipped with Flask's debug mode left on. The
actual vulnerable artifact is NOT a Flask-routed endpoint in the main app —
it's `GET /internal-tools/diagnostics`, served by a tiny internal Flask
sub-app mounted via `DispatcherMiddleware` (see Decisions above), with
`DEBUG`/`PROPAGATE_EXCEPTIONS` enabled only on that sub-app. Visiting it
crashes and shows the *real*, unstyled Werkzeug interactive debugger page
(genuinely jarring against the rest of the app's UI — a deliberate, realistic
signal). The Exploitation section walks through using the debugger's console
to run `subprocess.check_output(...)`, exactly as live-verified.

**6. Forgotten Admin Panel with Default Credentials (Hard)** —
`id: default-admin-creds`. `GET/POST /a05/admin-login` checks a hardcoded
username/password (`admin` / `DataVault@2019`, framed as the factory-default
credentials from a fictional internal tool's setup guide, never rotated after
deployment) and sets a session flag on success. `GET /a05/admin-panel`
(reachable only with that flag set) shows a fake "Internal Ops Dashboard"
with an "Export All User Data" feature dumping fake customer PII (names,
emails, password-hint-style fields) — distinct, self-contained fake data, no
coupling to other categories' seeded `User` table. The Detect/Exploitation
text frames this as recognizing a real-world pattern (unrotated vendor
default credentials), not a page-leaked secret, which is what earns this its
Hard placement despite the technique itself being simple.

## Navigation

New `CategoryNav` registered in `app/core/nav.py`'s `CATEGORIES` list (via
`app/categories/a05_security_misconfiguration/__init__.py`, following the
exact A04 pattern): `id="a05_security_misconfiguration"`, `short_id="A05"`,
`title="Security Misconfiguration"`, a blurb describing missing hardening/
insecure defaults, `overview_endpoint="a05_security_misconfiguration.overview"`,
no `seed_fn`. The six `ExampleNav` entries land in the three groups described
above, in Easy→Hard flat-list order per group.

## Testing

- Route-level tests for all six examples via the normal `client`/`app`
  fixtures, following the same conventions as every prior category (legitimate
  use works; the vulnerable content/behavior is genuinely present in the
  response; the teaching-text-hidden toggle still leaves the live exploit
  functional).
- A dedicated test for the debugger example using `werkzeug.test.Client`
  wrapping the actual composed WSGI callable from `wsgi.py` (not the plain
  Flask `client` fixture), confirming: a normal main-app route still returns
  a plain 500 on an uncaught exception (proving no blast radius), and the
  mounted `/internal-tools/diagnostics` path genuinely returns the interactive
  debugger page with a working console.
- `tests/test_a05_overview.py` mirrors `test_a04_overview.py` exactly:
  overview renders, nav registration, `grouped_examples()` structure and
  Easy-to-Hard sortedness, group headings render on the overview page.
- README.md's category summary table gets A05's row (Implemented status,
  full example list), matching every other row's format exactly.

## Out of scope for this spec

- A06–A10 (separate, future sub-projects).
- Any change to XXE (already A03) or any other existing category's routes,
  templates, or tests.
- Any change to Flask's global `SESSION_COOKIE_SAMESITE`/`SESSION_COOKIE_SECURE`
  config, or to the `switch_user`/`current_user`/`User` mechanism.
- Progress tracking changes — the existing `{% block tasks %}` and
  "Mark as done" mechanisms are reused as-is (no multi-task examples in this
  spec; every A05 example is single-shot, matching A01/A02/A04's style).
