# OWASP Top 10 Training Lab — A03 LDAP Injection Design Spec

Date: 2026-09-20
Status: Approved
Sub-project 6c of the extended post-A04 roadmap's A03-expansion block (sub-project 6
overall): quick fixes → UI/infra polish → sidebar regrouping → content retrofit →
UI polish round 2 → A03 expansion (**XXE (done)** → **SSTI (done)** →
**LDAP injection (this spec)** → SQLi/XSS/CMD deepening, each its own sub-project) →
progress tracking & stats.

## Purpose

Add LDAP injection as a new vulnerability sub-type under A03, with two
graduated examples: an authentication-bypass case and a blind
boolean-extraction case. This is the third of six A03 injection
sub-projects (XXE done, SSTI done, LDAP this one, then SQLi/XSS/CMD
deepening).

## Decisions from brainstorming

- **Genuine infrastructure, not a simulated vulnerability.** Unlike XXE
  (needed only a new pip package) and SSTI (needed nothing new at all —
  `render_template_string` is built into Flask/Jinja2), a genuine LDAP
  injection demo requires an actual LDAP directory server to bind/search
  against — the same way this project's SQL injection examples need a
  real Postgres database rather than a fake one. Confirmed with you
  before proceeding, since this is a materially bigger infrastructure
  commitment than either prior A03 piece: a new `docker-compose.yml`
  service, seeded directory data, and a new Python dependency.
- **`osixia/openldap:1.5.0`** chosen as the LDAP server image — a
  well-established, widely-used test/dev OpenLDAP image. Live-tested
  directly (via `docker run`) before writing this spec: binds correctly
  as admin, accepts entry creation, and correctly enforces real LDAP
  schema semantics (see below). TLS is disabled (`LDAP_TLS: "false"`) to
  skip certificate-generation overhead at startup — this is a local
  training lab already banner-warned "never expose to an untrusted
  network," plain LDAP on localhost is appropriate.
- **`ldap3==2.9.1`** chosen as the Python client — a pure-Python LDAP
  library with no compiled C-extension/`libldap` OS headers required,
  unlike the alternative `python-ldap` (which needs `libldap2-dev` at
  build time and would be a materially riskier, harder-to-verify Docker
  dependency, closer in risk profile to XXE's `lxml` C-extension
  surprises than SSTI's zero-new-dependency case). Installed and
  live-tested against the real running server before writing this spec —
  not assumed.
- **Both example mechanisms fully live-verified against a real running
  `osixia/openldap` instance** before writing this spec — not assumed
  from general LDAP-injection theory (the discipline XXE's SSRF
  sub-example painfully required after an assumption turned out wrong):
  - **Password-wildcard authentication bypass**: with the vulnerable
    filter `(&(uid={username})(userPassword={password}))` built via raw
    string interpolation, submitting `password=*` for a known username
    genuinely logs in without knowing the real password — confirmed live
    (a `*` in an LDAP filter is a presence match: any non-empty attribute
    value satisfies it).
  - **A real, load-bearing technical discovery**: `userPassword` uses
    LDAP's `octetStringMatch` equality matching rule, which has **no
    substring-matching support** by design in standard schema — confirmed
    live that `(userPassword=s*)` never matches even against a real
    stored value starting with `s`, on the real server. This means a
    character-by-character blind extraction of a *password* via
    substring filters genuinely does not work, even when the underlying
    code is vulnerable. This is authentic LDAP behavior, not a
    limitation of the training lab — the Hard example is designed around
    it honestly (see below), not despite it.
  - **Blind boolean data exfiltration** (the Hard example's mechanism):
    seeded a secret string into a normal `description` attribute (which
    *does* support substring matching, unlike `userPassword`), and
    genuinely extracted the complete secret character-by-character using
    only a found/not-found boolean oracle via `(&(uid={target})(description={query}*))`
    — confirmed live end-to-end against the real server, extracted value
    byte-for-byte matched the seeded value.
  - **Secure pattern**: `ldap3.utils.conv.escape_filter_chars()` applied
    to user input before building either filter — confirmed live to
    neutralize both the wildcard bypass and the substring-injection
    extraction, while still allowing legitimate logins/searches to work
    normally.
- **No HTML-escaping complication.** LDAP filter metacharacters
  (`(`, `)`, `*`, `\`, NUL) are not HTML-significant — neither of this
  project's two standing escaping constraints (HTML-entity escaping from
  XXE, `{% raw %}` Jinja-wrapping from SSTI) apply to LDAP payloads beyond
  the normal baseline. Confirmed by inspection: none of these examples'
  illustrative payloads contain `<`, `>`, `{{`, or `{%`.
- **Testing strategy — mirrors the project's existing SQLite-for-Postgres
  precedent, with one documented divergence.** This project's own test
  suite already substitutes SQLite in-memory for the real Postgres used
  in Docker (`app/config.py`'s `TestConfig`), rather than requiring a
  live database during `pytest`. The equivalent for LDAP is `ldap3`'s
  built-in `MOCK_SYNC` client strategy — an in-memory fake directory with
  the same API, verified live to work for this project's needs. However,
  **a real divergence was found and confirmed live**: `MOCK_SYNC`
  does NOT replicate the real server's `userPassword`
  no-substring-matching restriction — it incorrectly allows
  `(userPassword=s*)`-style substring filters to match, where the real
  OpenLDAP server correctly rejects them. This project's design
  deliberately never relies on that restricted behavior anywhere a unit
  test needs to assert on it (the Hard example's blind extraction
  targets `description`, specifically *because of* this real
  restriction on `userPassword` — not `userPassword` itself), so the
  divergence doesn't undermine any planned test. It is documented here
  as a known constraint, and the plan's Docker verification task remains
  the authoritative live-proof step against the real server, same
  discipline as XXE and SSTI.

## Components

### 1. Docker infrastructure

`docker-compose.yml` gains a new `ldap` service:

```yaml
  ldap:
    image: osixia/openldap:1.5.0
    environment:
      LDAP_ORGANISATION: "OWASP Lab"
      LDAP_DOMAIN: "owasp-lab.local"
      LDAP_ADMIN_PASSWORD: "admin123"
      LDAP_TLS: "false"
    ports:
      - "127.0.0.1:3890:389"
```

The `app` service gains `depends_on: [postgres, ldap]` (both dependencies,
not replacing the existing `postgres` dependency) and new environment
variables for the LDAP connection (base DN, admin bind DN, admin
password, host/port), following the same `env`-based configuration
pattern already used for `DATABASE_URL`.

### 2. Dependency

`requirements.txt` gains `ldap3==2.9.1` — the version actually installed
and live-tested while writing this spec (confirmed both vulnerable
mechanisms and the secure pattern work correctly against a real running
`osixia/openldap:1.5.0` instance). The implementation plan re-verifies
this exact pinned version installs and behaves identically inside the
`python:3.12-slim` Docker target, the same verification discipline
already used for `psycopg` and `lxml` earlier in this project.

### 3. Seed data

A new `app/categories/a03_injection/ldap_seed.py` module (parallel to the
existing `seed.py`), providing a function that idempotently creates the
directory structure on app startup (checks-then-creates, matching
`seed_injection_data()`'s pattern):

- `ou=people,{base_dn}` organizational unit.
- `uid=alice,ou=people,{base_dn}` — a regular user (`inetOrgPerson`),
  password `alice123`, mirroring the existing SQLi seed data's `alice`
  account in flavor.
- `uid=root_admin,ou=people,{base_dn}` — a privileged account,
  password `sup3r-s3cret-ldap-admin-pw` (mirroring the existing SQLi
  seed data's admin account naming/flavor), with a `description`
  attribute holding a secret value (`recovery-code-x7k2p9`) — the target
  of the Hard example's blind extraction.

### 4. Routes

`app/categories/a03_injection/routes.py` gains a new `ldap3` import and
two new routes:

- `GET/POST /a03/directory-login` (Easy) — a "company directory login"
  feature. POST accepts `username`/`password` form fields, builds
  `(&(uid={username})(userPassword={password}))` via raw string
  interpolation (no escaping), searches the directory, and treats any
  match as a successful login, displaying the matched user's `cn`.
- `GET/POST /a03/directory-search` (Hard) — an "employee directory
  search" feature. POST accepts `target`/`query` form fields, builds
  `(&(uid={target})(description={query}*))` via raw string interpolation
  (no escaping), and reveals only whether a match was found (a boolean
  "Match found" / "No match" — never the actual attribute value), forming
  the blind oracle.

### 5. Templates

Two new example templates,
`app/categories/a03_injection/templates/a03_injection/directory_login.html`
and `.../directory_search.html`, in the established four-part structure
(Explanation / Detect / Exploitation / Vulnerable-vs-Secure / Try It),
using `language-python` code panels (the vulnerable/secure contrast is
Python code). No `{% raw %}` wrapping is needed anywhere in these
templates (LDAP payloads contain no Jinja syntax), and no HTML-entity
escaping is needed beyond the template engine's normal default
autoescaping (LDAP payloads contain no `<`/`>` characters).

### 6. Navigation

`app/categories/a03_injection/__init__.py` gains two new `ExampleNav`
entries in a new group `"LDAP Injection"`, appended after the existing
`"Server-Side Template Injection (SSTI)"` group: `ldap-directory-login`
(Easy) and `ldap-directory-search` (Hard).

## Global Constraints

- No changes to any existing A01/A02/A04/existing-A03 route, model, or
  template.
- No changes to the existing `postgres` service or `DATABASE_URL`
  configuration — the new `ldap` service is additive.
- The vulnerable pattern is exactly raw string interpolation into an LDAP
  filter string (both examples) — verified live (not assumed) that this
  genuinely achieves authentication bypass (Easy) and full blind data
  extraction (Hard) against the real `osixia/openldap:1.5.0` server, and
  that `ldap3.utils.conv.escape_filter_chars()` genuinely neutralizes
  both.
- Unit tests use `ldap3`'s `MOCK_SYNC` in-memory strategy (no real LDAP
  server needed for `pytest`), mirroring this project's existing
  SQLite-for-Postgres precedent. The implementation plan's tasks must not
  write any test that relies on `MOCK_SYNC` correctly replicating LDAP
  schema-level matching-rule restrictions (specifically:
  `userPassword`'s lack of substring support) — that specific behavior
  only holds against the real server, confirmed to diverge in the mock.
  The plan's Docker verification task is the authoritative proof that
  both examples work against the real service.

## Testing

- Unit tests for both routes (against `MOCK_SYNC`): legitimate login
  succeeds and displays the correct `cn`; wrong password fails; the
  password-wildcard (`*`) bypass genuinely logs in as `root_admin`
  without the real password; legitimate directory search correctly
  reports "Match found" for a real prefix and "No match" for a
  non-matching one; the full blind character-by-character extraction
  genuinely recovers the seeded `description` secret
  (`recovery-code-x7k2p9`) using only the found/not-found oracle.
- A test confirming the SECURE `escape_filter_chars()` pattern (used only
  in the Vulnerable-vs-Secure illustrative code panel, never in the live
  route) actually neutralizes both the wildcard-bypass payload and the
  substring-injection payload when fed as literal, escaped input —
  mirroring the rigor applied to every other example's Vulnerable-vs-Secure
  panel.
- Both examples' "still works with both toggles off" regression test.
- A test confirming the new sidebar group renders.
- Docker verification task (final task in the implementation plan):
  confirms `ldap3==2.9.1` installs cleanly in the `python:3.12-slim`
  container, the `ldap` service starts and accepts binds, the seed data
  loads correctly, and both exploits genuinely work against the real
  live `ldap` service (not the mock) — the wildcard bypass logs in as
  `root_admin`, and the blind extraction (run live, not simulated)
  recovers the real seeded secret from the real running directory
  server.

## Out of scope for this spec

- The SQLi/XSS/CMD deepening work (separate sub-projects, sequenced
  after this one).
- Any change to existing A01/A02/A04/existing-A03 examples.
- Any change to the existing `postgres` service, `DATABASE_URL`
  configuration, or SQL-backed seed data.
- Progress tracking / Stats page.
- TLS/StartTLS for the LDAP connection (plain LDAP is appropriate for
  this local, explicitly-never-expose-to-untrusted-network training lab).
