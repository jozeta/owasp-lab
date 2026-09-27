# HTTP Parameter Pollution, IDOR, Insecure Randomness & Open Redirect Additions — Design

## Overview

Adds 5 new intentionally-vulnerable examples to the OWASP Top 10 Training Lab, sourced from PayloadsAllTheThings' [HTTP Parameter Pollution](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/HTTP%20Parameter%20Pollution), [Insecure Direct Object References](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Direct%20Object%20References), [Insecure Randomness](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Randomness), and [Open Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect) reference pages. Two further pages — [LDAP Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection) and [Mass Assignment](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Mass%20Assignment) — were triaged and both fully declined (user-confirmed) as already covered by existing examples with no genuinely distinct sub-technique worth adding.

1. **IDOR via Wildcard Pattern-Matched Lookup** — new entry in A01's existing "Insecure Direct Object References (IDOR)" group.
2. **Predictable API Key via Time-Seeded PRNG** — new group "Weak Random Number Generation" in A02.
3. **Unvalidated Open Redirect** — new group "Open Redirect" in A01.
4. **Open Redirect Allowlist Bypass via Domain Suffix** — same new "Open Redirect" group in A01.
5. **HTTP Parameter Pollution — Role Escalation via Inconsistent Duplicate-Parameter Handling** — new group "HTTP Parameter Pollution" in A01.

No new categories, no new SQLAlchemy models. Examples 95 → 100. Max score 2010 → 2140 (two Medium +20 each, three Hard +30 each).

This is a sixth round in the same series as the five merged PayloadsAllTheThings-additions rounds (round 1: 63→78; round 2: 78→86; round 3: 86→88; round 4: 88→90; round 5: 90→95, merged at `92192cd`). It follows every convention those rounds established: category/subgroup placement with Easy→Hard per-group sorting, the six-block `example_page_base.html` template structure, `hints=[...]` with the two-block-type escaping convention, the scoring+hints system, and the standing rule that the vulnerabilities are the deliverable and must never be softened or sanitized.

## Source Material Triage

**LDAP Injection**: fully declined (user-confirmed). A03 already has two examples covering the exact two techniques this reference page describes — `ldap-directory-login` (AND-logic auth bypass via wildcard filter injection, matching the page's "Authentication Bypass" section) and `ldap-directory-search` (boolean-blind prefix-matching character extraction, matching the page's "Blind Exploitation" section almost line-for-line). The page's remaining content (`userPassword` octet-string ordering comparisons, an LDAP-field-discovery script) is obscure and doesn't map cleanly to a new Flask feature.

**Mass Assignment**: fully declined (user-confirmed). A01's existing `mass-assignment` example already demonstrates the exact scenario this reference page describes — unrestricted attribute binding via a loop over all submitted fields, letting an attacker smuggle a privileged field (there: `role`; the page's own example: `isAdmin`). The page's entire content is this one scenario, phrased as a JSON body instead of form data — a wire-format variation of an identical bug, not a distinct vulnerability class.

**Insecure Direct Object References**: A01 already has two examples (`idor` — guess another user's numeric ID; `password-change-idor` — an unauthenticated JSON API keyed by email). The reference page's "Wildcard Parameter" technique, user-confirmed as in-scope, is genuinely distinct: a lookup that assumes exact-identifier matching but is implemented with SQL `LIKE`-style pattern matching, so a bare wildcard character returns every record instead of the one the caller specified.

**Insecure Randomness**: A02 already has a `reset-token` example (`generate_reset_token`), but its actual mechanism — verified by reading the route fresh — is a deterministic hash, `hashlib.md5(f"{username}:{RESET_TOKEN_SALT}")`, not a weak *random number generator*. An attacker who knows the username can directly recompute this hash; no randomness or brute-forcing is involved at all. This reference page, by contrast, is specifically about predictable *seeds* feeding a genuine PRNG (`random.seed(int(time.time()))`, MongoDB ObjectId timestamp encoding, PHP `uniqid()`/`mt_rand()` prediction) — a materially different bug class, user-confirmed as in-scope. Verified empirically that Python's `random.seed(n)` is fully deterministic: re-seeding with the same integer reproduces an identical output sequence.

**Open Redirect**: A10 has an example titled "Open Redirect Bypasses a Trusted-Domain Allowlist" (`blocklist-redirect-bypass`), but its actual mechanism — verified by reading the route fresh — is the *server* fetching a URL via `urllib.request.urlopen()` and blindly following an HTTP redirect it receives back; the allowlist check never re-validates the `Location` header's host. This is genuinely Server-Side Request Forgery reached via a redirect, not classic Open Redirect (CWE-601), where the *server* sends the *victim's own browser* a redirect to an attacker-chosen URL — the phishing-enabling vulnerability this entire reference page describes. Client-facing Open Redirect is therefore genuinely unimplemented anywhere in this app. User-confirmed scope: two examples, landing in a new A01 group (matching OWASP's common mapping of unvalidated redirects to Broken Access Control) — a basic unvalidated case, plus the page's classic "trusted domain as a substring of an attacker domain" filter-bypass technique. Verified empirically that Flask's `redirect()` passes any URL through as the response's `Location` header completely unchanged, with no built-in host validation of any kind.

**HTTP Parameter Pollution**: no existing coverage anywhere in the app. Verified empirically, directly against this app's installed Flask/Werkzeug, rather than trusting the reference page's own claims about framework behavior:
```python
# GET query string, POST form data, with ?param=first&param=second:
request.args.get('param')      # -> 'first' (first occurrence)
request.args.getlist('param')  # -> ['first', 'second'] (all occurrences)
# POST JSON body with a duplicate key {"param": "first", "param": "second"}:
request.get_json()['param']    # -> 'second' (standard Python json.loads: last key wins)
```
This confirms the reference table's claim for Flask specifically (first-occurrence via `.get()`) and reveals the exact mechanism needed for a genuine, app-native HPP vulnerability: a route whose authorization check reads `.get()` (always sees the first occurrence) while its actual write reads `.getlist()[-1]` (the last occurrence) — an internal inconsistency between two lines of the *same* function, not a cross-framework parsing quirk. This is a clean, novel, and entirely plausible real-world bug shape (a "let a later resubmitted field override an earlier one" convention applied inconsistently with the authorization check that runs first).

## The 5 New Examples

### 1. IDOR via Wildcard Pattern-Matched Lookup (A01, existing "Insecure Direct Object References (IDOR)" group, Medium)

**New route:** `/a01/lookup-account` (GET/POST). A "look up an account by username" feature (framed as a legitimate "check if this username exists" or "find my account" utility). The vulnerable query:
```python
User.query.filter(User.username.like(username)).all()
```
**Vulnerability:** `like()` performs SQL pattern matching, not equality. `%` matches any sequence of characters (including empty), `_` matches any single character — neither is escaped or rejected. Submitting a bare `%` returns every user account in the system in one request, including other users' emails, display names, and roles.

**Distinctness from existing IDOR examples:** `idor` requires guessing a specific numeric ID one at a time; `password-change-idor` requires knowing a specific target's email. This example requires no guessing at all — a single wildcard character discloses every record simultaneously, a fundamentally different failure mode (a query-operator mistake, not a missing-ownership-check mistake, though the outcome — unauthorized access to other users' data — is the same OWASP category).

**Testing approach:** real Flask test client, no mocking. Seed multiple users, submit `%` as the lookup value, assert every seeded user's data appears in the response.

### 2. Predictable API Key via Time-Seeded PRNG (A02, new group "Weak Random Number Generation", Hard)

**New route:** `/a02/generate-api-key` (GET/POST). An "API key generator" feature.
```python
random.seed(int(time.time()))
api_key = "".join(random.choices("0123456789abcdef", k=32))
```
**Vulnerability:** seeding Python's `random` module with the current Unix timestamp makes the entire output sequence reproducible by anyone who knows (or can narrow down) the second the key was generated — verified empirically that re-seeding with the same integer produces byte-identical output.

**Distinctness from the existing `reset-token` example:** that example's token is a deterministic *hash* of a known input (the username) — no randomness or timing is involved; an attacker who knows the username can compute the exact token instantly, from any point in time. This example's token *is* generated by a real PRNG, but the PRNG's *seed* is predictable — an attacker who does *not* know any user-specific secret still recovers the key, but only by knowing or estimating *when* the key was generated and testing a small window of candidate seed values (matching this lab's established "search a small window" oracle pattern already used elsewhere, e.g. blind SQLi's binary search).

**Testing approach:** real Flask test client, no mocking. Generate a key via the route, independently reproduce it in the test by re-seeding `random` with a timestamp captured immediately before/after the request and regenerating the same 32-hex-character sequence, and assert the two match exactly.

### 3. Unvalidated Open Redirect (A01, new group "Open Redirect", Medium)

**New route:** `/a01/continue` (GET). A "continue to your destination" feature (e.g., linked from a hypothetical post-checkout or post-logout flow).
```python
next_url = request.args.get("next", "/")
return redirect(next_url)
```
**Vulnerability:** zero validation of any kind on `next_url` — verified empirically that Flask's `redirect()` sends whatever string it's given as the `Location` header, including a fully external URL, with no host-checking. An attacker crafts `?next=https://evil.example.com/phish` and distributes the link; because the domain in the visible link is this app's own trusted domain, victims are more likely to click it, then land on the attacker's page.

**Testing approach:** real Flask test client. Request the route with an external `next` value, assert the response is a redirect (3xx) whose `Location` header is exactly the attacker-supplied external URL.

### 4. Open Redirect Allowlist Bypass via Domain Suffix (A01, same "Open Redirect" group, Hard)

**New route:** `/a01/continue-filtered` (GET). Same feature, with a naive allowlist:
```python
next_url = request.args.get("next", "/")
if "trusted-partner.example" in next_url:
    return redirect(next_url)
return "Invalid redirect target", 400
```
**Vulnerability:** the check only tests whether the trusted hostname appears *anywhere* in the string, not that it's genuinely the URL's host. `https://trusted-partner.example.evil.com/phish` contains `trusted-partner.example` as a literal substring, passes the check, and redirects to a host entirely under attacker control (`evil.com`, with `trusted-partner.example` merely a subdomain label the attacker chose). This is the reference page's own headline filter-bypass technique (`whitelisted.com.evil.com`), adapted to this app's naming conventions (`trusted-partner.example`, matching the `.example` TLD convention already used for fictional domains elsewhere in this app, e.g. A05's `attacker.example`, A10's `trusted-mirror.example`).

**Testing approach:** real Flask test client. Confirm the filter genuinely blocks an unrelated external URL (400), then confirm `https://trusted-partner.example.evil.com/phish` passes the check and produces a redirect to that exact attacker-controlled host.

### 5. HTTP Parameter Pollution — Role Escalation via Inconsistent Duplicate-Parameter Handling (A01, new group "HTTP Parameter Pollution", Hard)

**New route:** `/a01/update-preferences` (GET/POST). A "preferences" feature framed as a multi-step form where a hidden field from an earlier step can be legitimately overridden by a later one.
```python
submitted_role = request.form.get("role", "user")
if submitted_role not in ("user", "premium"):
    abort(403)
viewer.role = request.form.getlist("role")[-1]
db.session.commit()
```
**Vulnerability:** the authorization check (`request.form.get("role")`) and the actual write (`request.form.getlist("role")[-1]`) read *different* occurrences of the same duplicated form field — verified empirically that Werkzeug's `.get()` always returns the first occurrence while `.getlist()` returns all occurrences in submission order. Submitting `role=user&role=admin` makes the check see `"user"` (passes) while the write applies `"admin"` (the last occurrence) — a genuine internal inconsistency within one function, not a cross-framework parsing quirk.

**Distinctness from the existing `mass-assignment` example:** that example accepts *any* submitted field name with no allowlist at all; this example's field name (`role`) *is* explicitly checked — the bug is that the check and the write don't agree on *which value* a repeated field actually holds.

**Testing approach:** real Flask test client, no mocking. Submit a single `role=admin` value and confirm it's rejected (403). Submit `role=user&role=admin` (both values for the same key, in that order) and confirm the request succeeds and the viewer's role is genuinely updated to `admin` in the database — proving the check and the write disagree, not merely that the route accepts multiple values.

## Category Placement Summary

| Example | Category | New/Existing Group | Difficulty | Points |
|---|---|---|---|---|
| IDOR via Wildcard Pattern-Matched Lookup | A01 | Existing: Insecure Direct Object References (IDOR) | Medium | +20 |
| Predictable API Key via Time-Seeded PRNG | A02 | New: Weak Random Number Generation | Hard | +30 |
| Unvalidated Open Redirect | A01 | New: Open Redirect | Medium | +20 |
| Open Redirect Allowlist Bypass via Domain Suffix | A01 | New: Open Redirect | Hard | +30 |
| HTTP Parameter Pollution — Role Escalation | A01 | New: HTTP Parameter Pollution | Hard | +30 |

Final A01 shape: 8 → 12 examples, 5 → 7 groups (two new groups this round).
Final A02 shape: 5 → 6 examples, 4 → 5 groups.
App total: 95 → 100 examples. Max score: 2010 → 2140.

## Data Model Approach

No new SQLAlchemy models anywhere. All five examples use only:
- The existing `User` model, queried via a different operator (`.like()` instead of `==`) for example 1, and a new field write path (`role`) for example 5 (the `User.role` column already exists, used by the existing `mass-assignment` and `admin-users` examples).
- Plain module-level/session state for the PRNG example (the generated key is displayed and optionally stored in `session` for redisplay — no new model).
- No persistent state at all for the two Open Redirect examples (pure request/response, matching `reflected-xss`'s shape) or the HPP example beyond the existing `User.role` write.

## Testing Approach

Per-example test files following this app's one-file-per-example convention (`tests/test_a01_idor_wildcard.py`, `tests/test_a02_insecure_randomness.py`, `tests/test_a01_open_redirect.py` covering both Open Redirect examples together since they share a feature, `tests/test_a01_http_parameter_pollution.py`), using the real Flask test client against the actual vulnerable routes — no mocking anywhere, including no mocking of `random.seed()`/`random.choices()` for the PRNG example, since the whole point is proving the same seed genuinely reproduces the same output. Cross-cutting files to update: `tests/test_a01_hints.py`, `tests/test_a01_overview.py`, `tests/test_a02_hints.py` (a single file, unlike A03's split), `tests/test_a02_overview.py`, `tests/test_all_examples_have_hints.py` (total 95→100), `tests/test_hints.py` (max score 2010→2140), and `README.md`'s category summary table and intro paragraph for both A01 and A02.

## Scope Note

This round declined two full reference pages (LDAP Injection, Mass Assignment — both user-confirmed as already covered with no genuinely distinct sub-technique) and, for the remaining four pages, added exactly the content that survived triage: one IDOR sub-technique, one Insecure Randomness mechanism, two Open Redirect examples (basic + the page's own headline bypass technique), and one HTTP Parameter Pollution example built around this app's actual, empirically-verified Werkzeug behavior. Two of the five findings this round (the Insecure Randomness distinction and the Open Redirect category correction) came from discovering that an *existing* example's title described a different vulnerability than its actual code — this is worth flagging as a pattern: category/title accuracy is worth periodically re-verifying against actual route behavior, not just trusted from prior rounds' documentation.
