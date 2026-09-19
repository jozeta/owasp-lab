# OWASP Top 10 Training Lab — A03 XXE (XML External Entity Injection) Design Spec

Date: 2026-09-19
Status: Approved
Sub-project 6a of the extended post-A04 roadmap's A03-expansion block (sub-project 6
overall): quick fixes → UI/infra polish → sidebar regrouping → content retrofit →
UI polish round 2 → **A03 expansion (XXE, then SSI, then LDAP, then SQLi/XSS/CMD
deepening, each its own sub-project)** → progress tracking & stats.

## Purpose

Add XML External Entity (XXE) injection as a new vulnerability sub-type under
A03, with two graduated examples: file disclosure and server-side request
forgery (SSRF) via XXE. This is the first of three new A03 injection
sub-types (XXE, then SSI, then LDAP), each built as its own independent
sub-project so this branch stays reviewable and mergeable on its own.

## Decisions from brainstorming

- **The vulnerable parsing pattern is `lxml.etree.XMLParser(resolve_entities=True)`,
  verified live before writing this spec** — not assumed. Python's built-in
  `xml.dom.minidom`/`xml.sax`/`xml.etree.ElementTree` have had external
  entity resolution disabled by default for years (a hardening fix), so they
  are NOT genuinely exploitable and would have made a dishonest lesson.
  `lxml` (a new dependency, added to `requirements.txt`) with
  `resolve_entities=True` explicitly set is the real, commonly-seen
  vulnerable pattern — confirmed by direct testing that it exfiltrates a
  local file's contents through the parsed entity, while the parser's
  secure default (`resolve_entities=False`, i.e. just `XMLParser()`)
  correctly raises `Entity 'xxe' not defined` on the identical payload.
- **Two examples, not a full multi-task ladder.** Unlike the SQLi/XSS/CMD
  deepening sub-projects (explicitly asked for multiple difficulties +
  multi-task-with-solutions), the original request for XXE/SSI/LDAP just
  asked for "more examples" (plural) — scoped here as two graduated
  examples: Easy (file disclosure) and Hard (SSRF), sharing the same
  underlying vulnerable code path but demonstrating different attacker
  goals.
- **File disclosure target is a real file on disk**, not a database row —
  committed into the repo at `app/categories/a03_injection/xxe_secret.txt`,
  synthetic content in the same "leaked internal notes" flavor as the
  existing `Secret` model's seed data, but standalone (reading this file
  doesn't require visiting any other example first).
- **SSRF target is this app's own `/healthz` endpoint** (already exists,
  `app/__init__.py:44-46`). The Explanation section is explicit that in
  this lab the target happens to be reachable directly too (flat lab
  topology) — the real-world danger XXE-SSRF demonstrates is reaching
  resources the attacker canNOT reach directly, with cloud metadata
  endpoints (a well-known, publicly documented SSRF target class) as the
  concrete real-world example.
- **No route/model changes to any OTHER example** — this only adds new
  routes, one new static file, and (new dependency) `lxml` to
  `requirements.txt`. Existing A03 examples (SQLi/XSS/CMD trio) are
  untouched.
- **Content structure matches the established four-part pattern** from the
  content-retrofit sub-project (Explanation / Detect / Exploitation /
  Vulnerable vs. Secure) — these are new examples, so they're built in
  that structure from day one, not retrofitted later.

## Components

### 1. Dependency

`requirements.txt` gains `lxml==6.1.3` — the version actually installed
and tested live while writing this spec (confirmed
`XMLParser(resolve_entities=True)` exfiltrates a local file's contents,
and the secure default correctly rejects the same payload with
`Entity 'xxe' not defined`). The implementation plan re-verifies this
exact pinned version installs and behaves identically inside the
`python:3.12-slim` Docker target, the same verification discipline
already used for `psycopg` earlier in this project.

### 2. Static seed file

`app/categories/a03_injection/xxe_secret.txt` (new, committed to the repo,
plain text, not seeded into the DB):

```
Internal Notes -- Do Not Distribute
Backup encryption passphrase: xK9-vault-passphrase-2024
On-call escalation contact: oncall-secops@owasp-lab.internal
```

### 3. Routes

`app/categories/a03_injection/routes.py` gains, near the top:

```python
import os
from lxml import etree

XXE_SECRET_PATH = os.path.join(os.path.dirname(__file__), "xxe_secret.txt")
```

And two new route pairs:

- `GET/POST /a03/xml-import` (Easy) — a "contact import" feature. POST
  accepts an `xml_input` form field, parses it with the vulnerable parser,
  extracts the `<name>` element's text, and displays it. Legitimate use:
  `<contact><name>Alice</name></contact>` displays "Alice". Attack: a
  `<!DOCTYPE>` declaring an external entity pointing at
  `file://<XXE_SECRET_PATH>`, referenced inside `<name>`, displays the
  secret file's contents instead.
- `GET/POST /a03/xxe-ssrf` (Hard) — same vulnerable parsing pattern, same
  `<status><message>` shape, but the exploitation payload's entity targets
  `http://127.0.0.1:5000/healthz` instead of a file, and the response
  displays the fetched content (`{"status": "ok"}`), proving the server
  itself issued an HTTP request the attacker directed.

Both routes share the identical vulnerable parsing logic (only the
exploitation payload's entity target differs), matching the design
decision that this is one underlying bug demonstrated two ways.

### 4. Templates

Two new example templates,
`app/categories/a03_injection/templates/a03_injection/xml_import.html` and
`.../xxe_ssrf.html`, in the established four-part structure (Explanation /
Detect / Exploitation / Vulnerable vs. Secure / Try It), following the
exact template-block conventions already established across every other
A03 example.

### 5. Navigation

`app/categories/a03_injection/__init__.py` gains two new `ExampleNav`
entries in a new group `"XML External Entity Injection (XXE)"`:
`xml-import` (Easy) and `xxe-ssrf` (Hard) — appended after the existing
three groups (SQL Injection, Cross-Site Scripting (XSS), OS Command
Injection) so the new group renders last in the sidebar, matching
first-occurrence ordering.

### 6. Docker

`Dockerfile` needs no changes — `lxml` installs via the existing
`pip install -r requirements.txt` step; its C-extension wheel is
available for `python:3.12-slim` on the standard PyPI index, verified in
the implementation plan's final Docker task the same way every prior
dependency addition in this project was verified.

> **Amendment (post-implementation):** `Dockerfile`'s gunicorn worker
> count was bumped from 2 to 4 during implementation — the SSRF example's
> self-referential HTTP request was found to deadlock under normal
> browser concurrency with only 2 workers. See the implementation plan's
> SDD ledger for the full root-cause and verification.

## Testing

- Unit tests for both routes: legitimate XML input displays the expected
  name; the file-disclosure payload against `/a03/xml-import` returns the
  seeded secret file's content; the SSRF payload against `/a03/xxe-ssrf`
  returns the healthz response content.
- A test confirming the SECURE parser variant (used only in the
  Vulnerable-vs-Secure illustrative code panel, never in the live route)
  actually rejects the same payload — i.e. the illustrative "Secure" code
  is proven correct, not just plausible-looking, mirroring the rigor
  applied to every other example's Vulnerable-vs-Secure panel in the
  content-retrofit sub-project.
- Both examples' "still works with both toggles off" regression test.
- A test confirming the new sidebar group renders.

## Out of scope for this spec

- SSI injection and LDAP injection (separate sub-projects, sequenced
  after this one).
- The SQLi/XSS/CMD deepening work (separate sub-projects).
- Any change to existing A01/A02/A04/existing-A03 examples.
- Progress tracking / Stats page.
