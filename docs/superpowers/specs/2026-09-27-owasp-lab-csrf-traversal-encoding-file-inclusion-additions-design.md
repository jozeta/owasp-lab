# CSRF, Directory Traversal, Encoding & File Inclusion Additions — Design

## Overview

Adds 5 new intentionally-vulnerable examples to the OWASP Top 10 Training Lab, sourced from four PayloadsAllTheThings reference pages: [Cross-Site Request Forgery](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Cross-Site%20Request%20Forgery), [Directory Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal), [Encoding Transformations](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Encoding%20Transformations), and [File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion). A fifth page, Denial of Service, was explicitly declined by the user for this round and is entirely out of scope — not fetched, not analyzed.

1. **CSRF via Token Presence-Only Validation** — new entry in A01's existing "Cross-Site Request Forgery" group.
2. **Arbitrary File Read via Document Download** — new group "Path Traversal" in A01.
3. **Path Traversal Filter Bypass via Absolute Path** — same new "Path Traversal" group in A01.
4. **Unicode Normalization Filter Bypass (XSS)** — new entry in A03's existing "Cross-Site Scripting (XSS)" group.
5. **LFI-to-SSTI via Unsanitized Snippet Include** — new group "File Inclusion" in A03.

No new categories, no new SQLAlchemy models. Examples 90 → 95. Max score 1880 → 2010 (two Medium +20 each, three Hard +30 each).

This is a fifth round in the same series as the four merged PayloadsAllTheThings-additions rounds (round 1: 63→78; round 2: 78→86; round 3: 86→88; round 4: 88→90, merged at `d128208`). It follows every convention those rounds established: category/subgroup placement with Easy→Hard per-group sorting, the six-block `example_page_base.html` template structure, `hints=[...]` with the two-block-type escaping convention, the scoring+hints system, and the standing rule that the vulnerabilities are the deliverable and must never be softened or sanitized.

## Source Material Triage

**Denial of Service**: out of scope this round by explicit user decision, made before any of its content was fetched or analyzed. Not discussed further in this spec.

**Cross-Site Request Forgery**: A01 already has one example (`csrf-email-change` — a sensitive form with *no* CSRF protection at all: no token, no Referer check, nothing). The reference page's remaining content splits into two genuinely distinct techniques not yet covered: (a) a CSRF token that's present but never validated against the real value (matching several of the page's own linked PortSwigger labs — "token validation depends on token being present", "token is not tied to user session"), and (b) JSON-CSRF via a lenient Content-Type check that avoids a CORS preflight. User-confirmed decision: implement only (a) this round, to keep scope smaller — (b) is not implemented.

**Directory Traversal**: no existing path-traversal example anywhere in this app (confirmed by grep across `app/categories/*/routes.py` for path-traversal patterns — none found). The page's content splits cleanly into "no protection" and "naive filter, defeated by an encoding/technique the filter didn't anticipate." Both are implemented, since neither overlaps with anything existing and the second directly reuses the first's infrastructure.

**Encoding Transformations**: not a vulnerability class on its own — a technique (Unicode normalization, Punycode, Base64) used as a *gadget* elsewhere. This app already has one Unicode-normalization example (A07's account-takeover-via-username-collision, from round 1: two different usernames normalizing to the same value). The genuinely distinct angle from this page, user-confirmed as in-scope: a naive input filter checks the *raw* string for a dangerous literal substring, but the app calls `unicodedata.normalize("NFKC", ...)` on the value afterward for an unrelated legitimate reason (consistent display text) — and NFKC normalization converts fullwidth Unicode lookalike characters into their literal ASCII equivalents *after* the filter already approved the string, resurrecting exactly what the filter tried to block. Verified empirically:

```python
>>> import unicodedata
>>> s = '＜script＞alert(document.domain)＜/script＞'
>>> unicodedata.normalize('NFKC', s)
'<script>alert(document.domain)</script>'
```

**File Inclusion**: the reference page is heavily PHP-specific (`include($_GET['page'])`, `allow_url_include`, PHP-version-specific null-byte truncation) and none of it applies directly to a Python/Flask app. The distinguishing concept the page draws out — "Path Traversal reads a file; File Inclusion *executes* it" — has a genuine, well-known Flask-native equivalent: a feature that reads file content by an unsanitized path and then passes that content through `render_template_string()` (Jinja2 template execution), rather than `render_template()` (Flask's sandboxed template *name* loader). This was verified empirically to be the correct distinction, not an assumption:

```python
>>> from jinja2 import Environment, FileSystemLoader
>>> env = Environment(loader=FileSystemLoader('app/categories/a03_injection/templates'))
>>> env.get_template('../../../../../../etc/passwd')
TemplateNotFound: ../../../../../../etc/passwd
```

Flask/Jinja2's template *name* loader already rejects `..` path segments outright — a `render_template(user_controlled_name)` design would not work as a traversal vector at all (matching round 3's discovery that Werkzeug blocks CRLF injection: verify runtime behavior before designing around an assumption, don't trust general knowledge alone). Plain `open()`, however, has no such protection:

```python
>>> import os
>>> os.path.join('/app/templates', '/etc/passwd')
'/etc/passwd'          # os.path.join() discards the base entirely for an absolute 2nd argument
>>> os.path.join('/app/templates', '../' * 12 + 'etc/passwd')
'/app/templates/../../../../../../../../../../../../etc/passwd'
>>> os.path.normpath(_)
'/etc/passwd'          # and classic relative traversal also works, given enough '../' segments
```

Both primitives — the classic relative traversal and the `os.path.join()` absolute-path-override quirk — were verified to genuinely read `/etc/passwd`'s real content via plain `open()`. This is the mechanism all three of this round's traversal/inclusion examples share.

## The 5 New Examples

### 1. CSRF via Token Presence-Only Validation (A01, existing "Cross-Site Request Forgery" group, Medium)

**New route:** `/a01/change-display-name` (GET/POST). A per-session CSRF token is generated on first visit (`session["a01_csrf_token"] = secrets.token_hex(16)`) and rendered into the form as a hidden field — the page *looks* properly protected. The vulnerability: the POST handler only checks that a `csrf_token` form field is present and non-empty (`if request.form.get("csrf_token"):`), never that its value matches `session["a01_csrf_token"]`. An attacker's cross-site auto-submitting form can supply any non-empty string (e.g. `csrf_token=x`) and the request succeeds — the attacker never needs to know or steal the real token.

**Vulnerable field:** reuses the existing `User.display_name` column (already present on the model; no schema change) as the field this form updates, framed as a "change your display name" feature — distinct in mechanism from `mass-assignment`'s exploitation of the *same* underlying column (that example is about accepting unlisted form fields; this one is about a broken CSRF defense on a form that only ever accepts `display_name` itself).

**Testing approach:** real Flask test client. Log in as a user, GET the page to establish a real session token, then POST with a *different*, attacker-chosen `csrf_token` value and assert the display name still changes — proving the real token was never checked.

### 2. Arbitrary File Read via Document Download (A01, new group "Path Traversal", Medium)

**New route:** `/a01/download-document` (GET). Seeds a small `instance/a01_documents/welcome.txt` file on first access (mirroring A09's `_ensure_seed_document()`-style lazy-seed pattern already used elsewhere in this app) and reads `os.path.join(DOCUMENTS_DIR, name)` where `name` comes from `request.args.get("name", "welcome.txt")` with **zero validation of any kind**.

**Exploitation:** two independently-working techniques, both already empirically verified above:
1. Classic relative traversal: `?name=../../../../../../etc/passwd`.
2. The `os.path.join()` absolute-path-override: `?name=/etc/passwd` — no `../` needed at all, since an absolute second argument discards `DOCUMENTS_DIR` entirely.

### 3. Path Traversal Filter Bypass via Absolute Path (A01, same "Path Traversal" group, Hard)

**New route:** `/a01/download-document-filtered` (GET). Same mechanism as example 2, but this route first checks `if ".." in name: blocked = True` before proceeding — a real, working filter against the *classic* technique.

**Vulnerability:** the filter only ever considers the `".."` substring. It never considers that `os.path.join()`'s absolute-path-override doesn't involve `".."` at all: `?name=/etc/passwd` contains no `".."` anywhere, sails through the filter untouched, and reaches the exact same unguarded `open()` call. This is a "naive filter didn't consider X" story matching this app's established teaching pattern (`filtered-host-lookup`'s newline-bypass, `filter_challenge`'s per-level bypasses).

**Testing approach for both traversal examples:** real Flask test client, asserting the actual file content (`/etc/passwd`'s real first line, or a similarly universal file) appears in the response — not just that the request succeeds.

### 4. Unicode Normalization Filter Bypass (XSS) (A03, existing "Cross-Site Scripting (XSS)" group, Hard)

**New route:** `/a03/feedback` (GET/POST). A "submit feedback" feature. The POST handler checks `if "<script" in feedback.lower(): blocked = True` (a real, working filter against the literal substring) — but when the filter doesn't trip, it calls `unicodedata.normalize("NFKC", feedback)` before rendering the result with `|safe`, framed as "normalizing fullwidth punctuation for consistent display" (a plausible real reason an app might do this, e.g. cleaning up text pasted from a CJK input method).

**Exploitation:** submit feedback containing fullwidth lookalikes instead of literal angle brackets — `＜script＞alert(document.domain)＜/script＞` (U+FF1C/U+FF1E instead of U+003C/U+003E). The literal-substring filter finds no `"<script"` anywhere in the raw input and passes it through; NFKC normalization then converts the fullwidth characters into the literal ASCII tag, which renders and executes.

**Testing approach:** real Flask test client. Assert (1) the literal ASCII payload IS blocked (filter genuinely works against the obvious case), and (2) the fullwidth-lookalike payload is NOT blocked and the rendered response contains the literal, normalized `<script>` tag bytes.

### 5. LFI-to-SSTI via Unsanitized Snippet Include (A03, new group "File Inclusion", Hard)

**Existing infrastructure this reuses (for payload style only, not code):** the exact SSTI payload chain already established by `ssti-email-preview` (`self.__init__.__globals__.__builtins__.__import__('os').popen(...).read()`) — reused here as the content of a *planted file*, not typed directly into a template-string field, which is what makes this example's mechanism genuinely different from the existing SSTI examples (file-path-mediated inclusion vs. direct text-field template evaluation).

**New routes:**
- `/a03/file-inclusion` (GET) — the six-block HTML explanation page. Its `live_example` block hosts both of the forms below inline.
- `/a03/save-snippet` (POST) — accepts `name` and `content` form fields, writes `content` verbatim to `os.path.join(SNIPPETS_DIR, name)` (creating `SNIPPETS_DIR` — `instance/a03_snippets` — on first use). Framed as a stand-in for some unrelated real feature (e.g. "save a custom email signature snippet") — deliberately mundane, matching how a real LFI target is rarely the "obviously dangerous" feature.
- `/a03/render-snippet` (GET) — reads `os.path.join(SNIPPETS_DIR, name)` (where `name` comes from `request.args`, again with zero validation) and passes the *contents* through `render_template_string()`, returning the rendered result.

**Vulnerability:** `render_snippet`'s `name` parameter is never validated, exactly like the two Directory Traversal examples above — but here, whatever text comes back is executed as a live Jinja template rather than displayed as inert data, so:
1. Reading a snippet by its plain name that was genuinely saved via `save-snippet` reflects a benign save/include round-trip (proves the basic mechanism works).
2. Reading a snippet whose *content* is the SSTI payload chain (saved first via `save-snippet`) achieves genuine remote code execution the moment `render-snippet` includes it — proving "inclusion executes code," the exact distinction the reference material draws between path traversal and file inclusion.
3. Reading a file *outside* `SNIPPETS_DIR` entirely — via the same `os.path.join()` absolute-path-override already verified in examples 2/3 — discloses arbitrary file content (e.g. this example's own dedicated secret file, `file_inclusion_secret.txt`, created as a static repo file matching the existing `xxe_secret.txt`/`cmd_secret.txt` precedent, or a universal file like `/etc/hostname`).

**Testing approach:** real Flask test client, no mocking. Save a snippet containing the exact SSTI payload chain, then GET `/a03/render-snippet?name=<that snippet's name>` and assert the response contains real command output (e.g. actual `id` output, matching how `ssti-email-preview`'s own test already verifies genuine code execution rather than just checking for absence of an error).

## Category Placement Summary

| Example | Category | New/Existing Group | Difficulty | Points |
|---|---|---|---|---|
| CSRF via Token Presence-Only Validation | A01 | Existing: Cross-Site Request Forgery | Medium | +20 |
| Arbitrary File Read via Document Download | A01 | New: Path Traversal | Medium | +20 |
| Path Traversal Filter Bypass via Absolute Path | A01 | New: Path Traversal | Hard | +30 |
| Unicode Normalization Filter Bypass (XSS) | A03 | Existing: Cross-Site Scripting (XSS) | Hard | +30 |
| LFI-to-SSTI via Unsanitized Snippet Include | A03 | New: File Inclusion | Hard | +30 |

Final A01 shape: 5 → 8 examples, 4 → 5 groups.
Final A03 shape: 22 → 24 examples, 8 → 9 groups.
App total: 90 → 95 examples. Max score: 1880 → 2010.

## Data Model Approach

No new SQLAlchemy models anywhere. All five examples use only plain module-level constants (directory/file paths) and Flask `session` state, matching this session's established precedent:
- CSRF example: `session["a01_csrf_token"]`, reuses the existing `User.display_name` column.
- Directory Traversal examples: plain constants (`DOCUMENTS_DIR`), a lazily-seeded file, no session state needed (GET-only, stateless reads).
- Unicode Normalization example: no persistent state at all — a single request/response round-trip, matching `reflected-xss`'s shape.
- File Inclusion example: plain constants (`SNIPPETS_DIR`, `FILE_INCLUSION_SECRET_PATH`), snippets persist as plain files on disk (matching `CSS_EXFIL_LOG_PATH`'s file-backed-state precedent from round 3, not a session or a model).

## Testing Approach

Per-example test files following this app's one-file-per-example convention (`tests/test_a01_csrf_broken_token.py`, `tests/test_a01_directory_traversal.py`, `tests/test_a03_unicode_normalization_xss.py`, `tests/test_a03_file_inclusion.py`), using the real Flask test client against the actual vulnerable routes — no mocking anywhere, and specifically no mocking of `render_template_string()` or file I/O for the File Inclusion example, since the whole point is proving real code executes and real files are read. Cross-cutting files to update: A01's `tests/test_a01_hints.py` (a single file, unlike A03's split) and `tests/test_a01_overview.py`, A03's `test_a03_hints_remaining_groups.py` and `test_a03_overview.py`, `tests/test_all_examples_have_hints.py` (total 90→95), `tests/test_hints.py` (max score 1880→2010), and `README.md`'s category summary table and intro paragraph for both A01 and A03.

## Scope Note

This round declined one full reference page (Denial of Service, per explicit user instruction, for reasons unrelated to technical fit — this app's standing safety posture treats genuine service-disruption techniques differently from the dual-use injection/access-control/RCE examples that make up the rest of this lab) and scoped two others down from their full breadth (CSRF to one of two identified techniques; Directory Traversal's rich family of platform-specific encoding bypasses — most of which are PHP/IIS/ASP.NET-specific and don't apply to this Python/Flask app — condensed to the one genuinely novel, still-current bypass this app's own `os.path.join()` behavior makes possible). 5 examples is the correct, proportionate size for what these four reference pages actually yield here, matching every prior round's practice of not padding scope with tangential or architecturally-mismatched material.
