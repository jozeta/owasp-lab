# CRLF/Log Injection & CSS Injection Additions — Design

## Overview

Adds 2 new intentionally-vulnerable examples to the OWASP Top 10 Training Lab, sourced from PayloadsAllTheThings' [CRLF Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection) and [CSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSS%20Injection) reference pages:

1. **Log Injection / Forging** — new group in A09 Security Logging and Monitoring Failures.
2. **CSS Attribute-Selector Data Exfiltration** — new group "CSS Injection" in A03 Injection.

No new categories, no new SQLAlchemy models. Examples 86 → 88. Max score 1780 → 1830 (one Medium +20, one Hard +30).

This is a third round in the same series as the two merged PayloadsAllTheThings-additions rounds (round 1: 63→78 examples across A01/A02/A04/A05/A07; round 2: 78→86 examples across A04/A05, Business Logic Errors and CORS Misconfiguration). It follows every convention those rounds established: category/subgroup placement with Easy→Hard per-group sorting, the six-block `example_page_base.html` template structure (`explanation`/`detect`/`exploitation`/`tasks`/`vulnerable_code`/`secure_code`/`live_example`), `hints=[...]` with the two-block-type escaping convention, the scoring+hints system, and the standing rule that the vulnerabilities are the deliverable and must never be softened or sanitized.

## Source Material Triage

### CRLF Injection page

The page's entire substantive content is HTTP response splitting via CRLF (`\r\n`) injected into response headers: session fixation via a forged second `Set-Cookie`, reflected XSS via injecting a full second HTTP response body, and open redirect via injecting a `Location` header — all three achieved the same way, by getting raw `\r\n` into a header value.

**This is empirically infeasible on this app's stack.** Verified directly against the installed Werkzeug 3.1.8 / Flask 3.0.3:

```python
r = Response("hi")
r.headers["X-Test"] = "value\r\nX-Injected: evil"
# ValueError: Header values must not contain newline characters.

redirect("https://example.com\r\nSet-Cookie: admin=true")
# ValueError: Header values must not contain newline characters.

r3 = Response("hi")
r3.set_cookie("session", "abc\r\nSet-Cookie: admin=true")
# No exception, but Python's http.cookies module octal-escapes the CRLF
# into `\015\012` in the Set-Cookie value -- not passed through raw.

Response("hi", headers=[("X-Test", "value\r\nX-Injected: evil")])
# ValueError: Header values must not contain newline characters.
```

Every normal Flask/Werkzeug API for setting a header value rejects or neutralizes `\r`/`\n`. There is no route-level code this app could write, using its established plain `render_template()`/`redirect()`/`jsonify()` conventions, that would let literal CRLF injection into an HTTP response header actually happen. Building a genuine demo would require dropping to raw WSGI/socket-level response writing — architecturally inconsistent with every other route in this app and out of proportion to a 2-page reference source.

**Decision (user-confirmed):** skip literal CRLF header injection. Substitute **Log Injection / Forging** (CWE-117), the sibling vulnerability class CRLF-injection write-ups (including OWASP's own CWE-93 page) consistently cite alongside response splitting — unsanitized `\n` in user input let into a plaintext log file, forging fake, independent-looking log lines. This is genuinely and unconditionally exploitable on this stack with no framework hardening in the way.

### CSS Injection page

The page covers six distinct techniques. Feasibility triage for a lab that must work in an ordinary current browser with no external tooling:

| Technique | Verdict | Why |
|---|---|---|
| Attribute-selector exfiltration via `background-image` | **Include** | Classic, broadly supported in every browser for years. The workhorse technique this page is built around. |
| `@import` chaining / Blind CSS Exfiltration (SIC) | Skip | Needs a live long-polling attacker server issuing new payloads mid-connection — real infrastructure, not a single self-contained Flask route. |
| CSS Conditionals (`if()` / inline style exfiltration) | Skip | `if()` in CSS is a bleeding-edge feature not yet supported in released stable browsers as of this writing — a demo built on it would silently fail to render for most users testing the lab. |
| `@font-face` `unicode-range` presence-detection | Skip (user-scoped out) | Broadly supported and a genuinely different primitive, but the user chose the single-example scope for this round; presence-only detection (no character ordering) is also a narrower teaching payoff than the attribute-selector technique. |
| `attr()` as a URL via `image-set()` | Skip | Explicitly called out in the source page itself as a very recent Chrome-only capability ("Advanced attr()"). Not reliably demoable across browsers. |
| Ligatures / `fontleak` | Skip | Requires running a separate Docker-packaged tool server-side; out of scope for a single training-lab route. |

**Decision (user-confirmed):** one example, the attribute-selector + `background-image` technique, landing in **A03 Injection** as a new "CSS Injection" group — the category's own blurb ("untrusted input executed by an interpreter... instead of being treated as data... including the browser") covers this directly, since the browser's CSS parser is the interpreter here.

## The 2 New Examples

### 1. Log Injection / Forging (A09, new group, Medium)

**Title:** "Audit Log Forged via Unescaped Display Name"

**Existing infrastructure this reuses:** A09's `append_to_app_log(line)` helper (`app/categories/a09_logging_monitoring_failures/routes.py:19-22`) already writes `f.write(line + "\n")` with no escaping of embedded newlines inside `line` itself — confirmed by reading the current file. The existing `/a09/download-log` route (unauthenticated) and `/a09/security-events` route (via `log_contents=_read_app_log()`) both already display the raw file contents. No new log-storage plumbing is needed; only a new route that writes attacker-controlled content into a line via this existing helper.

**New route:** `/a09/update-display-name` (GET shows a form with a **textarea** — matching A03's `filtered-host-lookup` convention of using a textarea specifically so a literal newline is easy for a tester to enter — POST updates a session-stored display name and calls, unescaped:

```python
append_to_app_log(f"display name updated to '{display_name}'")
```

**Vulnerability:** no newline stripping, no structured/parameterized logging, no escaping of any kind. A display name containing literal `\n` characters splits into multiple independent-looking log lines once written.

**Exploitation:** submit a display name shaped like:

```
Johan
[2026-09-24 12:00:00] ADMIN: granted superuser role to attacker
```

The audit log (viewable via `/a09/download-log` or `/a09/security-events`) now shows what looks like a genuine, timestamped admin-action log entry that never actually happened — indistinguishable from a real line to anyone reading the log, including any downstream tooling or human analyst that trusts one-line-per-event log parsing. The same technique lets an attacker retroactively fabricate a "clean" line to bury or disguise a real attack's own log entry among decoys.

**Group rationale:** sits naturally alongside A09's existing "Insecure Log Storage" group (`sensitive-data-in-logs`, `log-file-world-readable`) but is a distinct flaw class — those two are about log *secrecy* (what leaks into the log), this one is about log *integrity* (what an attacker can forge into the log). New group: "Log Injection / Forging".

### 2. CSS Attribute-Selector Data Exfiltration (A03, new group, Hard)

**Title:** "CSS Attribute-Selector Data Exfiltration via Profile Theme"

**New route:** `/a03/theme-preview` (GET/POST). Renders a "Customize Your Profile Theme" preview page containing:
- A `<style>{{ custom_css | safe }}</style>` block containing whatever CSS the user just submitted, completely unescaped — no sanitization, no CSP header anywhere in this app.
- A hidden field with a real, fixed demo value: `<input type="hidden" name="account_recovery_pin" value="{{ ACCOUNT_RECOVERY_PIN }}">`, where `ACCOUNT_RECOVERY_PIN` is a module-level constant (e.g. `"7429"`), matching A04's established convention of plain module-level constants for demo data (`DEMO_PRODUCT_PRICE_CENTS`, `COUPON_CODE`) rather than a new DB model.

**Vulnerability:** raw, attacker-controlled CSS rendered unescaped directly into the page alongside a sensitive hidden field, with no sanitization and no CSP to restrict what a `background-image` URL can point at.

**Live demo:** a second route, `/a03/css-exfil-demo`, rendering a sandboxed `<iframe>` (matching A05's `cors_null_origin_demo.html`/`delete_account_clickjack_demo.html` precedent) that genuinely contains the same hidden PIN input plus a real, attacker-authored CSS rule:

```css
input[name="account_recovery_pin"][value^="7"] {
  background-image: url(/a03/css-exfil-collector?leak=7);
}
```

This is not simulated — the sandboxed iframe's CSS parser genuinely evaluates the attribute selector against the genuine hidden input value and, on a match, the browser genuinely issues a real subresource request for the `background-image` URL. (Sandboxed iframes without `allow-same-origin` still load ordinary subresources like background images; the sandbox restricts script execution and top-level navigation, not passive resource loads.) The `/a03/css-exfil-collector` endpoint accepts the `leak` query parameter with **no validation that it's actually correct** and appends it to a session-scoped "exfiltrated data" list, proving the channel itself — not just one lucky guess — is wide open. The demo page displays the growing "Exfiltrated so far" list, so a live visitor sees the leak happen in their own browser.

**Exploitation narrative (explained in the Exploitation block/hints, not fully automated in the demo — matching this lab's existing precedent for blind/oracle techniques like `blind-sqli`, `ldap-directory-search`, and `blind-report-injection`, which each prove one working step and describe full automation in prose):** a real attacker doesn't know the PIN in advance. They inject one attribute-selector rule per candidate character (`value^="0"`, `value^="1"`, ... `value^="9"`), each pointing at a URL encoding which digit it's testing; whichever request actually arrives at the attacker's collector reveals the first correct digit. Repeating this, extending the prefix by one character each round, recovers the entire PIN — the same character-by-character oracle pattern as this lab's existing blind-injection examples, just driven by the CSS engine's selector matching instead of a SQL/LDAP boolean or a timing delay.

**Testing approach:** this app's test suite uses the Flask test client, not a real browser — matching how A05's iframe-based live-demo pages are already tested. Tests assert:
1. `/a03/theme-preview` renders a POSTed `custom_css` payload completely unescaped in the response body (proving no sanitization).
2. The hidden `account_recovery_pin` input's real value is genuinely present in the rendered DOM.
3. `/a03/css-exfil-demo` renders an `<iframe>` containing the real PIN value and the attribute-selector CSS rule (HTML-entity-encoded correctly per this app's two-block-type escaping convention, since this is a static teaching block rendered unescaped).
4. `/a03/css-exfil-collector?leak=<anything>` accepts and stores an arbitrary value with no auth and no correctness check, and that value shows up in a subsequent GET of the demo page.

**Group rationale:** new "CSS Injection" group in A03, sibling to the existing "Cross-Site Scripting (XSS)" group — both are "untrusted input executed by the browser," but this is a materially different primitive (styling engine side-channel, not script execution), and CSS injection specifically evades script-blocking defenses like a strict CSP that would stop the existing XSS examples — worth calling out explicitly in the Explanation block as the reason this vulnerability class exists at all.

## Category Placement Summary

| Example | Category | New/Existing Group | Difficulty | Points |
|---|---|---|---|---|
| Audit Log Forged via Unescaped Display Name | A09 Security Logging and Monitoring Failures | New: "Log Injection / Forging" | Medium | +20 |
| CSS Attribute-Selector Data Exfiltration via Profile Theme | A03 Injection | New: "CSS Injection" | Hard | +30 |

Final A09 shape: 6 → 7 examples, 3 → 4 groups.
Final A03 shape: 19 → 20 examples, 6 → 7 groups.
App total: 86 → 88 examples. Max score: 1780 → 1830.

## Data Model Approach

No new SQLAlchemy models. Both examples use only Flask session state and plain module-level constants:
- Log injection: reuses A09's existing `append_to_app_log()` file-based log and `session`-stored display name (new session key, e.g. `a09_display_name`).
- CSS injection: a plain module-level constant `ACCOUNT_RECOVERY_PIN` in A03's `routes.py`, plus a session-scoped list for the collector's captured `leak` values (new session key, e.g. `a03_css_exfil_log`).

## Testing Approach

Per-example test files following this app's one-file-per-example convention (`tests/test_a09_log_injection.py`, `tests/test_a03_css_exfil.py`), using the real Flask test client against the actual vulnerable routes — no mocking. Cross-cutting files to update: `tests/test_a09_hints.py`, `tests/test_a09_overview.py`, `tests/test_a03_hints.py`, `tests/test_a03_overview.py`, `tests/test_all_examples_have_hints.py` (total 86→88), `tests/test_hints.py` (max score 1780→1830), and `README.md`'s category summary table and example counts.

## Scope Note

This is a small round by design: the CRLF source material's core technique turned out to be infeasible on this stack (see triage above), and the CSS source material was deliberately scoped to its single most broadly-supported, self-contained technique per the user's explicit choice. 2 examples is the correct, proportionate size for what these two reference pages actually yield here — not a signal to pad scope with tangential material.
