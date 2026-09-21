# OWASP Top 10 Training Lab — A07 Identification and Authentication Failures Design Spec

Date: 2026-09-21
Status: Approved

New category sub-project, following the same from-scratch pattern used to build
A01–A06. This is A07's own full brainstorming cycle.

## Purpose

Build A07 (OWASP Top 10 2021: Identification and Authentication Failures) as
a new category with six examples — two per difficulty tier, per the user's
explicit request — covering distinct, genuinely exploitable real-world
authentication and session-management failures not already covered elsewhere
in the app.

## Decisions from brainstorming

- **Overlap with existing categories was explicitly mapped and avoided.**
  A02 Cryptographic Failures already owns "Predictable Password Reset Token"
  (a token-*randomness* weakness) — A07 does not touch password-reset token
  guessing at all. A05 Security Misconfiguration already owns "Forgotten
  Admin Panel with Default Credentials" (a credential that was never
  rotated) — A07's brute-force examples instead teach the *absence of any
  rate-limiting protection*, a different lesson (a defense that was never
  built, not a credential that was never changed). A03 Injection already has
  a SQL-injection login bypass — mechanically unrelated to A07's
  session/credential-lifecycle focus.
- **This app's existing sitewide login mechanism (`app/core/views.py`'s
  `switch_user`) is a simple "pick a seeded account" convenience dropdown
  with no password check at all**, used by every other category for
  "act as this user." A07 does not touch it. A07 builds its own,
  completely separate login routes and session mechanism, following this
  app's established convention that each category with account-like data
  gets its own scoped model (A02's `LegacyCredential`, A03's
  `InjectionAccount`) rather than reusing the shared `User` table.
- **A07 needs a genuine server-side session mechanism, not Flask's built-in
  `session`.** Flask's default session is a signed client-side cookie
  encoding the whole session dict — there is no separate "session
  identifier" a server looks up, which is what real-world session fixation
  and "session not invalidated" bugs are actually about (the classic
  PHP/Java pattern: a session ID cookie the server uses as a lookup key
  into server-side state). A07 therefore adds a small, self-contained
  `AuthSession` table (a real server-side session store, keyed by a random
  token) used only by A07's own routes, cookie name `a07_session_id`.
  Flask's built-in `session` (and everything built on it — `switch_user`,
  `logout`, every other category's login state) is completely untouched.
- **Three technical claims were live-verified before finalizing this spec,
  not assumed**, using a scratch Flask app implementing exactly the
  `AuthSession` design below, driven with `curl` using separate cookie jars
  to simulate distinct "victim" and "attacker" browsers — each with both a
  positive control (the vulnerable behavior) and a negative control (the
  fix genuinely closes it):
  - **Session fixation.** An endpoint that resolves the session id via
    `request.args.get("sid") or request.cookies.get(SID_COOKIE)`, and
    *adopts* any client-supplied value as a real session if it doesn't
    already exist (rather than only trusting values the server itself
    minted), permits a full three-actor attack: the attacker visits with a
    chosen `?sid=planted-by-attacker-1234`, gets it registered as a live
    (unauthenticated) session; the victim visits the same URL (adopting
    that id as their own cookie) and logs in, which sets `user_id` on that
    *same* session record without rotating the id; the attacker, who never
    authenticated, then presents `planted-by-attacker-1234` directly and is
    genuinely logged in as the victim. Verified end-to-end with real HTTP
    requests and distinct cookie jars — confirmed `LOGGED IN AS alice` for
    the attacker's request. The negative control (ignore `?sid=`, and mint
    a **new** session id on every successful login, discarding whatever
    pre-auth id was in use) was verified to fully block it: the same attack
    sequence against the secure variant returns `NOT LOGGED IN` for the
    attacker at every step.
  - **Session not invalidated on logout.** A logout handler that only does
    `resp.set_cookie(SID_COOKIE, "", expires=0)` — clearing the *client's*
    cookie — without deleting the corresponding `AuthSession` row
    server-side, leaves any separately-held copy of the old session id
    (e.g. one an attacker captured earlier via the URL-exposure bug, or
    just a saved cookie) fully valid indefinitely. Verified live: after the
    "victim" cookie jar POSTs to `/logout` (and correctly sees
    `NOT LOGGED IN` on its own next request, since its cookie was cleared),
    a *separate* request presenting the same old session id by hand still
    returns `LOGGED IN AS alice`. The negative control (`logout` actually
    deletes the server-side `AuthSession` row) was verified to close this:
    the identical old-id replay then returns `NOT LOGGED IN`.
  - **Session identifier accepted from a URL query parameter.** Confirmed
    as part of the same spike: `GET /account?sid=<value>` is sufficient by
    itself to both establish and later resume a session — no cookie
    interaction required at all — which is exactly the real-world failure
    mode of "session identifier exposed in the URL" (browser history,
    `Referer` leakage to third-party resources, and shared screenshots all
    become session-hijacking vectors once a valid id can travel as a URL
    parameter).
- **The rate-limiting/brute-force claims did not need a live spike.**
  `requirements.txt` was already confirmed to contain no rate-limiting
  library (no Flask-Limiter or equivalent), and a repo-wide search confirmed
  no `before_request` hook or any other throttling logic exists anywhere in
  `app/`. The absence of any such protection is a plain code fact, not a
  runtime behavior needing empirical verification the way browser-observable
  cookie/session mechanics did.
- **The MFA-bypass claim is a straightforward logic omission**, not a
  runtime behavior needing a live spike either: the protected destination
  route checks only that an `AuthSession` row has a `username` set, never
  that its `mfa_verified` flag is `True` — an omitted check, verifiable by
  reading the route's own logic once written, the same way A05's plain
  information-disclosure examples needed no live verification (only its
  RCE/CORS mechanisms did).

## Components

### Group 1: Brute Force & Credential Stuffing

**1. No Rate Limiting Enables Brute Force (Easy)** — `id: brute-force-login`.
`GET/POST /a07/customer-login`. A normal-looking customer account login page
backed by one seeded `A07Account` with a deliberately weak, common password
(`username="dana"`, `password="welcome1"`). The route checks the submitted
password against the stored hash and sets an `AuthSession` on success — with
no attempt limit, delay, CAPTCHA, or lockout of any kind, regardless of how
many consecutive wrong guesses arrive for the same username. The
Exploitation section gives a small common-password wordlist and walks
through scripting repeated login attempts until one succeeds.

**2. Credential Stuffing Across Multiple Accounts (Medium)** — `id:
credential-stuffing`. `GET/POST /a07/loyalty-portal-login`. A second,
differently-branded login page ("Loyalty Rewards Portal") reusing the exact
same unprotected login-checking logic, but backed by *three* seeded
`A07Account` rows, each assigned a password drawn from a small
commonly-reused/breached set (e.g. `"Summer2023!"`, `"letmein123"`,
`"qwerty1!"`). The Exploitation section gives a small
`username:password` combo list (the real-world shape of a credential-
stuffing wordlist — known-breached pairs, not a single-target guess list)
and demonstrates trying every pair against every username, succeeding on
whichever pairs happen to match — the lesson being password reuse across
services, tested at volume, not patience against one account like example 1.

### Group 2: Session Identity & Lifecycle

**3. Session Identifier Exposed in URL (Easy)** — `id: session-in-url`.
`GET /a07/account` (protected) and `GET /a07/share-session-link`. After
logging in via either Group 1 example, a "Get a shareable link to this
session" feature on the account page generates and displays a URL of the
form `/a07/account?sid=<the live AuthSession id>`. The Exploitation section
explains that this URL — once it appears in browser history, an
analytics/log line, a `Referer` header sent to a third-party resource
linked from the page, or a shared screenshot — is a complete, standalone
credential: opening it in a totally different browser (no cookies at all)
authenticates as that user immediately, verified live during brainstorming
(`GET /account?sid=<value>` alone is sufficient to resume a session).

**4. Session Not Invalidated on Logout (Medium)** — `id:
session-survives-logout`. `POST /a07/logout`. The account page displays the
current session's raw id for teaching transparency (framed as "your session
ID: `<value>` — note this down"). The Exploitation section has the learner
log in, copy their own session id, log out (confirming their own browser
now shows logged-out), then manually replay a request carrying the
*old*, pre-logout session id (e.g. via `curl -b
"a07_session_id=<copied-value>" /a07/account`) and observe it still
authenticates — proving the server-side session record was never actually
invalidated, only the client's cookie was cleared. Live-verified with both
the vulnerable behavior and the fix (deleting the server-side row on
logout) during brainstorming.

**5. Session Fixation (Hard)** — `id: session-fixation`. `GET
/a07/session-fixation-demo` (teaching page) plus the same `/a07/account`
and `/a07/customer-login` endpoints reused from examples 1 and 3. The
Exploitation section gives a copy-pasteable "attacker" link containing a
chosen `?sid=` value (matching this session's established pattern of
handing the learner a real external artifact for a multi-actor exploit,
e.g. A05's CORS attacker HTML snippet): the learner opens it themselves
first (simulating "visiting a link an attacker sent"), then logs in
normally through `/a07/customer-login` while that planted id is active,
then — in a second, separate browser context (or `curl` with a clean
cookie jar) — presents the exact same planted id directly and is logged in
as themselves with zero credentials ever having been given to the
"attacker" side. Full three-actor chain live-verified end-to-end during
brainstorming, including the negative control (id rotation on login blocks
it completely).

### Group 3: MFA Bypass

**6. Bypassable Multi-Factor Authentication (Hard)** — `id: mfa-bypass`.
`GET/POST /a07/mfa-login` (step 1: password) → `GET/POST
/a07/mfa-verify` (step 2: 6-digit code) → `GET /a07/mfa-dashboard`
(protected destination). Step 1 succeeding sets `AuthSession.username` and
leaves `mfa_verified=False`; since there's no real SMS/email in this lab,
the step-2 page displays the correct code directly (framed honestly as a
lab-only shortcut: "Your code is `482913` — shown here since this lab
doesn't send real SMS/email"), so the flow can be completed legitimately
too. The vulnerability: `mfa-dashboard` checks only
`AuthSession.username is not None`, never `AuthSession.mfa_verified` — so
navigating directly to `/a07/mfa-dashboard` immediately after step 1,
skipping step 2 entirely, succeeds exactly as if the second factor had been
completed.

## Navigation

New `CategoryNav` registered in `app/core/nav.py`'s `CATEGORIES` list (via
`app/categories/a07_auth_failures/__init__.py`, following the exact A05/A06
pattern): `id="a07_auth_failures"`, `short_id="A07"`,
`title="Identification and Authentication Failures"`, a blurb describing
broken login protections and session-lifecycle handling,
`overview_endpoint="a07_auth_failures.overview"`, `seed_fn` seeding the
`A07Account` rows (dana + the three loyalty-portal accounts). The six
`ExampleNav` entries land in the three groups described above, in
Easy→Hard flat-list order per group (Group 2 is Easy, Medium, Hard —
satisfying `grouped_examples()`'s per-group sortedness requirement).

## Data Model

```python
class A07Account(db.Model):
    __tablename__ = "a07_accounts"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class AuthSession(db.Model):
    __tablename__ = "a07_auth_sessions"

    id = db.Column(db.String(32), primary_key=True)  # secrets.token_hex(16)
    username = db.Column(db.String(80), nullable=True)
    mfa_verified = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
```

`AuthSession` rows are looked up by the `a07_session_id` cookie value (and,
for examples 3 and 5 specifically, an equivalent `?sid=` query parameter —
the deliberate vulnerability), never by anything derived from Flask's own
`session` object.

## Testing

- Route-level tests for all six examples via the normal `client`/`app`
  fixtures: legitimate login works for each of examples 1, 2, and 6;
  the vulnerable behavior is genuinely provable through the real Flask test
  client for every example — specifically:
  - Examples 1–2: a scripted loop of wrong-then-right password attempts
    against the same account succeeds with no 429/lockout response at any
    point, proving no rate limiting exists.
  - Example 3: an anonymous `client` (no cookies carried over) can
    authenticate purely via `?sid=<value>` copied from a previously
    authenticated response.
  - Example 4: a session id captured before a `POST /a07/logout` still
    authenticates via `Cookie` header after that logout call, using a
    second, independent test client/cookie jar.
  - Example 5: the full three-actor sequence — an "attacker" test client
    establishes a chosen id via `?sid=`, a "victim" test client adopts it
    and logs in, the original "attacker" client (which never submitted
    credentials) is then authenticated.
  - Example 6: `GET /a07/mfa-dashboard` immediately after step 1 (never
    calling `/a07/mfa-verify`) succeeds.
- `tests/test_a07_overview.py` mirrors `test_a06_overview.py` exactly:
  overview renders, nav registration, `grouped_examples()` structure and
  Easy-to-Hard sortedness, group headings render on the overview page.
- README.md's category summary table gets A07's row (Implemented status,
  full example list), matching every other row's format exactly, and the
  trailing "Planned" row becomes "A08–A10".

## Out of scope for this spec

- A08–A10 (separate, future sub-projects).
- Any change to Flask's built-in `session` object, `switch_user`, or
  `logout` in `app/core/views.py` — those stay exactly as they are today
  and continue to be used by every other category unmodified.
- Any change to A02's password-reset-token example or A05's default-admin-
  credentials example — both stay as-is; A07 deliberately does not
  re-tread either.
- Any real MFA delivery mechanism (SMS/email) — the lab displays the code
  directly, honestly framed as a lab-only shortcut, matching this app's
  established practice of not pretending to have infrastructure it doesn't
  (e.g. A05's CORS example similarly used a plain local HTTP server as the
  "attacker collector" rather than simulating a hosted attacker site).
- Progress tracking changes — the existing `{% block tasks %}` and
  "Mark as done" mechanisms are reused as-is (no multi-task examples in
  this spec; every A07 example is single-shot, matching every prior
  category's style).
