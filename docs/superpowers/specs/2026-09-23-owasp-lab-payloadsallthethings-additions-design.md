# PayloadsAllTheThings-Derived Additions — Design Spec

## Overview

Add 15 new intentionally-vulnerable examples to the OWASP Top 10 Training
Lab, sourced from two external reference pages the user provided:
[PayloadsAllTheThings' Account Takeover](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Account%20Takeover)
(including its `mfa-bypass.md` sub-page) and
[Brute Force & Rate Limit](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Brute%20Force%20Rate%20Limit).
Both source documents were fetched and read in full via `gh api` before
this spec was written (not assumed or hallucinated).

This grows the app from 63 to 78 examples, spanning A01, A02, A04, A05,
and A07 — no new categories, only new examples and groups within
existing ones. Like every other addition this session, every new example
also needs real, escalating hints (3-5 each) to satisfy the scoring
system's cross-category sanity test, which asserts every registered
example has well-formed hints and checks the exact total count.

## Source Material Triage

Read in full: Account Takeover `README.md` (187 lines), its
`mfa-bypass.md` sub-page (99 lines), and Brute Force & Rate Limit
`README.md` (147 lines).

**Already covered by existing content — not duplicated:**
- "Weak Password Reset Token" → A02's existing `reset-token` example.
- "Account Takeover via Cross Site Scripting" (cookie theft) → A03's
  `reflected-xss`/`stored-xss` and A06's `jquery-xss-session-theft`.
- "Account Takeover via JWT" (edit claims / weak signature) → A08's
  `jwt-alg-none-bypass`.
- "Bypass 2FA by Force Browsing" → this is A07's existing `mfa-bypass`
  example, verbatim (skip past `/2fa/verify` straight to the dashboard).
- Most of the Brute Force & Rate Limit page (Burp Intruder attack types,
  ffuf usage, JA3/TLS fingerprinting, IPv4/IPv6 proxy rotation) is
  attacker tooling/methodology for testing an app that already lacks
  rate limiting — not itself an app-side vulnerability to build. A07's
  existing `brute-force-login`/`credential-stuffing` examples already
  teach "no rate limiting on login."

**Not feasible for this app's architecture — out of scope:**
- "Account Takeover via HTTP Request Smuggling" — needs two HTTP parsers
  in a chain (reverse proxy + backend) to desync; this app is a single
  Flask/gunicorn process with no reverse-proxy layer in docker-compose.
- MFA "Response Manipulation" / "Status Code Manipulation" — these
  describe a JS-driven SPA trusting a client-side API response
  (`success:false→true`, `4xx→200`) to decide whether auth succeeded.
  This app is server-rendered (Flask redirects decide navigation, not
  client JS reading a response body), so there is no analogous trust
  boundary anywhere else in the app to reproduce this against.

**One cross-page synthesis:** the Brute Force & Rate Limit page's
abstract "brute-force a low-entropy secret" concept has no NEW
standalone application here (A07 already demonstrates password
brute-forcing) — but the MFA page's own "Lack of Brute-Force Protection"
entry is the concrete, novel instance: a 6-digit numeric OTP is a
1,000,000-value space, far smaller than a password, making rate limiting
matter even more there. This becomes example #13 below.

## Decisions (confirmed with the user during brainstorming)

1. **Scope: all 15 candidates, now.** Not a curated subset.
2. **"Password Reset Poisoning via Host Header" → A04 Insecure Design.**
   The flaw is a missing trust-boundary validation in the design itself
   (no allowlist check on `Host`/`X-Forwarded-Host` before using it to
   build a security-sensitive URL), not primarily an authentication
   failure.
3. **Two separate CSRF examples, not one.** "Account Takeover via CSRF"
   (A01, password change) and "CSRF on Disabling 2FA" (A07) are kept
   distinct — different consequence framing (full takeover vs. silent
   security-control downgrade), matching how real bug-bounty programs
   treat them as separate findings.
4. **MFA architecture: fully independent routes, no shared "correct
   baseline."** Each of the 6 new MFA-bypass examples (10-15 below) gets
   its own dedicated login → send-code → verify route sequence with its
   own OTP generation, each with exactly one deliberate flaw. This
   matches this app's established pattern everywhere else — including
   A07's own three existing near-identical login routes
   (`brute_force_login`/`credential_stuffing`/`mfa_login`), all reusing
   the same `A07Account` model with zero shared "correct" flow anywhere
   in the app to layer flaws onto.

## Existing Infrastructure This Builds On

- **A07's existing models** (`app/categories/a07_auth_failures/models.py`):
  `A07Account` (username, password_hash) and `AuthSession` (id,
  username, `mfa_verified`, created_at) — the shared cookie+DB session
  row every A07 route already reads/writes via
  `session_store.get_or_create_session()`. The existing `mfa_login` route
  demonstrates the ONLY OTP mechanism in the app today:
  `MFA_DEMO_CODE = "482913"`, a single hardcoded-forever code checked in
  `/mfa-verify` — no per-session generation, no expiry, no rate limiting.
  This is why `mfa-bypass`'s own teaching content only covers force-
  browsing past the verify step, not the code's own weaknesses — that
  gap is exactly what examples 10-14 below fill.
- **A04's existing session-based state** (`coupon_cart`/`quantity_cart`
  use Flask's built-in `session` object for per-browser demo state, no
  DB model) — the precedent this spec follows for examples that only
  need state within one learner's own browser, avoiding new DB tables
  where a session key suffices.
- **This app has zero CSRF protection and zero clickjacking protection
  anywhere** (`app/core/views.py`'s existing comment: "No CSRF token:
  matches every other POST route in this app... adding one only here
  would be inconsistent"). Examples 1 and 15 (CSRF) and example 6
  (clickjacking) are the first examples to NAME these gaps explicitly as
  the teaching point, rather than incidentally relying on them.
- **Scoring + hints system** (merged just before this request):
  `ExampleNav.hints: list[str]`, `tests/test_all_examples_have_hints.py`
  asserting every example has 3-5 hints and the total count is exact.
  Every new example below needs real hints following the same
  vague-to-explicit rubric and the same "raw unescaped `<`/`>`/`&`, rely
  on Jinja's `{{ hint }}` autoescaping" convention established in that
  project.

## The 15 New Examples

### A01 Broken Access Control (3 → 5 examples)

**New group: "Cross-Site Request Forgery"**

1. **Account Takeover via CSRF** (Medium) — `POST /a01/change-password`
   (new endpoint `a01_access_control.change_password`). Sets the
   logged-in viewer's password directly from `new_password` form data,
   with no CSRF token and no current-password confirmation required.
   Exploitation: an attacker-hosted page with an auto-submitting HTML
   form targeting this endpoint; a logged-in victim who merely visits
   the attacker's page has their password silently changed.

**Existing group: "Insecure Direct Object References (IDOR)"** (sibling
to the existing Easy `idor` read-only example)

2. **IDOR on Password-Change API** (Medium) — `POST
   /a01/api/password-change` (new endpoint
   `a01_access_control.password_change_api`), a JSON API accepting
   `{"email": ..., "new_password": ...}` that updates whichever `User`
   row matches the given email — not the authenticated viewer. No
   ownership check at all. A write-based escalation of the existing
   read-only IDOR example.

### A02 Cryptographic Failures (3 → 5 examples)

**New group: "Token Leakage"**

3. **Reset Token Leaked via Referrer Header** (Medium) — new sibling
   route to the existing Hard `reset-token` flow (separate URL, separate
   `LegacyCredential`-backed token, kept independent per the
   fully-independent-routes decision). The post-reset landing page links
   to (or embeds an image from) a third-party domain with no
   `rel="noreferrer"` and no `Referrer-Policy` header, while the token is
   still present in the current page's URL — so the full URL, token
   included, is sent to that third party in the `Referer` header.
4. **Reset Token Leaked in API Response** (Easy) — `POST
   /a02/api/forgot-password` (new endpoint), returns the freshly
   generated reset token directly in its own JSON response body (a
   left-in dev-mode convenience), letting an attacker skip email
   delivery entirely and reset any known account's password immediately.

### A04 Insecure Design (3 → 4 examples)

**New group: "Password Reset Design Flaws"**

5. **Password Reset Poisoning via Host Header** (Hard) — `GET/POST
   /a04/forgot-password` (new endpoint). Builds the (simulated, shown
   on-page rather than actually emailed — matching this app's existing
   no-real-email-sending convention) reset link using `request.host` /
   `request.headers.get("X-Forwarded-Host")` with no allowlist
   validation: `f"http://{host}/a04/reset-password?token={token}"`.
   Submitting a spoofed `Host` or `X-Forwarded-Host` header changes the
   domain embedded in the link a real victim would receive and click.

### A05 Security Misconfiguration (6 → 7 examples)

**New group: "Missing Security Headers"**

6. **Clickjacking on a Sensitive Action Page** (Easy) — `GET/POST
   /a05/delete-account` (new endpoint), a real-looking "Permanently
   delete my account" confirmation page served with no
   `X-Frame-Options` and no CSP `frame-ancestors` (consistent with the
   rest of this app, which sets neither anywhere). Exploitation: an
   attacker iframes this page under an innocuous-looking overlay,
   tricking a logged-in victim into an invisible click that submits the
   real deletion.

### A07 Identification and Authentication Failures (6 → 15 examples)

**New group: "Account Recovery Abuse"**

7. **Password Reset via Username Collision** (Hard) — new registration +
   forgot-password route pair. Registration stores the submitted
   username exactly as-is, including leading/trailing whitespace (so
   `"admin "` and `"admin"` are distinct rows); the forgot-password
   lookup strips whitespace before querying, so requesting a reset for
   `"admin "` resolves to and emails a token for the real `"admin"`
   account.
8. **Account Takeover via Unicode Normalization** (Hard) — new
   registration + lookup route pair. Registration stores
   username/email exactly as submitted, permitting Unicode lookalike
   characters (e.g. a circled-letter homoglyph); a separate lookup path
   (password reset or duplicate-check) applies naive case-folding/NFKC
   normalization that collapses the lookalike and the real account into
   the same identity for that lookup's purposes.
9. **Password Reset Silently Disables 2FA** (Medium) — new forgot-
   password route for MFA-enabled accounts. On successful reset, sets
   `mfa_verified = True` unconditionally (or simply never resets it to
   `False`), so an attacker who compromises only the password via any
   means lands directly past MFA with no re-verification.

**Existing group: "Multi-Factor Authentication Bypass"** (currently just
the Hard `mfa-bypass` force-browsing example; grows to 7 members)

10. **MFA Code Leaked to Client** (Easy) — new login → verify route pair.
    Server generates a random 6-digit code and returns it directly in
    the verify page's own rendered output (e.g. a debug attribute or
    comment never stripped for "production").
11. **MFA Code Reusability** (Medium) — new login → verify route pair.
    A generated code is never invalidated after successful use, so the
    same code remains valid indefinitely across repeated, separate
    verification attempts.
12. **MFA Code Not Bound to Session** (Hard) — new login → verify route
    pair. The verify endpoint checks "does this code match ANY currently
    pending code" rather than "does this code match THIS session's own
    challenge" — an attacker who generates and captures their own valid
    code via their own login can submit it against a different victim's
    separate pending challenge and have it wrongly accepted. This is the
    one example needing state visible across sessions (not scoped to one
    browser's session cookie) — exact storage mechanism (small dedicated
    model vs. module-level dict) is a plan-writing decision, since the
    flaw is specifically that the code ISN'T session-scoped.
13. **MFA Brute-Force (No Rate Limiting)** (Medium) — new login → verify
    route pair. A real, correctly single-use, correctly session-bound
    6-digit code — but the verify endpoint has no rate limiting, lockout,
    or delay, so all 1,000,000 possibilities can be tried in an
    automated loop. The one example directly bridging the Brute
    Force & Rate Limit source page into a concrete, novel (lower-entropy
    than any existing brute-force example) vulnerability.
14. **MFA Bypass via Magic/Null Value** (Easy) — new login → verify route
    pair. A real random code is generated and required normally, except
    the verify logic also unconditionally accepts a hardcoded backdoor
    value (e.g. `"000000"` or an empty string), left over from testing.
15. **CSRF on Disabling 2FA** (Medium) — `POST /a07/mfa/disable` (new
    endpoint), reusing the existing `mfa_login`/`mfa_verify` accounts.
    Disables MFA for the current session with no CSRF token and no
    re-authentication, exploitable via an auto-submitting form from an
    attacker page while the victim is logged in with MFA already
    verified.

## Data Model Approach

No new categories, no schema changes to already-shipped tables. New
per-example state:

- **Examples reusing existing models as-is:** #1 and #2 (A01's existing
  `User` model already has `password_hash`), #15 (A07's existing
  `AuthSession.mfa_verified`).
- **Examples reusing existing models with new routes only:** #3 and #4
  (A02's existing `LegacyCredential`), #9 (A07's existing `A07Account` +
  `AuthSession`).
- **Examples needing Flask `session`-based ephemeral state, no new DB
  table** (matching A04's existing `coupon_cart`/`quantity_cart`
  precedent): #5 (A04 has no user-auth model at all — the demo reset
  flow doesn't need one), #6 (a session-flag "sensitive action page",
  no persistence needed).
- **Examples needing a small new dedicated table or in-memory store,
  decided at plan-writing:** #7, #8 (new registration flows distinct
  from `A07Account`'s existing login-only usage — or extend
  `A07Account` with nullable fields if that proves simpler once the
  exact route shape is drafted), #10-14 (each needs to persist a
  generated code across the login→verify redirect; Flask `session`
  suffices for all except #12, which specifically needs cross-session
  visibility to demonstrate its flaw).

This app has no formal migrations (`db.create_all()`/`drop_all()` only,
established precedent from the scoring+hints project) — any new columns
on already-existing tables carry the same "Reset Lab after upgrading"
operational note already documented for that project.

## Testing Approach

Same as every prior sub-project this session: real Flask-test-client
requests exercising the actual vulnerable route (no mocked vulnerable
logic), per-category nav/grouping tests updated for the new counts and
group memberships, and hint-shape tests for every new example following
the scoring system's established rubric (3-5 hints, non-empty, no
duplicates). The final cross-category sanity test
(`test_all_examples_have_hints.py`) needs its `total == 63` assertion
updated to `total == 78`.

## Scope Note for the Implementation Plan

This is comparable in scale to the scoring+hints project (12 tasks) —
likely 15+ tasks once broken down, though A07's 6 MFA-bypass examples
(10-14, plus 9 and 15) may reasonably batch into 2-3 tasks each covering
2-3 closely related routes, rather than one task per example, mirroring
how A03's 19-example hint-authoring split into just 2 tasks by group.
Exact task boundaries are a writing-plans decision, not fixed here.
