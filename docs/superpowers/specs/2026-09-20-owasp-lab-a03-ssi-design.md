# OWASP Top 10 Training Lab — A03 SSTI (Server-Side Template Injection) Design Spec

Date: 2026-09-20
Status: Approved
Sub-project 6b of the extended post-A04 roadmap's A03-expansion block (sub-project 6
overall): quick fixes → UI/infra polish → sidebar regrouping → content retrofit →
UI polish round 2 → A03 expansion (**XXE (done)** → **SSTI (this spec)** → LDAP →
SQLi/XSS/CMD deepening, each its own sub-project) → progress tracking & stats.

## Purpose

Add Jinja2 Server-Side Template Injection (SSTI) as a new vulnerability
sub-type under A03, with two graduated examples: a direct RCE case and a
naive-blacklist-bypass case. This is the second of six A03 injection
sub-projects (XXE done, SSTI this one, then LDAP, then SQLi/XSS/CMD
deepening), each built as its own independent sub-project.

## Decisions from brainstorming

- **Scoped to Jinja2 SSTI, not classical Apache-style SSI directives.**
  The original request said "SSI injection," but classical Server-Side
  Includes (`<!--#exec cmd="..."-->` style, historically processed by
  Apache's `mod_include`) has no natural home in a Flask app — Flask/Jinja2
  has no built-in SSI directive processor, so demonstrating it would mean
  building a fake mini-parser that doesn't reflect how any real Flask app
  is ever actually vulnerable. Jinja2 Server-Side Template Injection (SSTI)
  — the `render_template_string(user_input)` pattern — is the vulnerability
  that's genuinely endemic to Flask apps, is distinct from everything
  already covered (XSS, command injection, XXE), and is what real-world
  Flask SSTI bug reports/CVEs are about. Confirmed with you before
  proceeding, since it materially changes the entire technical design.
- **Both example mechanisms verified live against this project's exact
  Flask 3.0.3 / Jinja2 3.1.6 stack before writing this spec** — not
  assumed from general SSTI knowledge (the discipline that XXE's SSRF
  sub-example painfully required after an assumption turned out wrong):
  - The basic detection probe (`{{ 7*7 }}` → `49`) and the classic
    no-sandbox Jinja2 gadget chain
    (`{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}`)
    both work exactly as expected, genuinely returning real command output
    from `render_template_string()` with no sandboxing.
  - A naive keyword blacklist (rejecting literal `os`, `import`, `exec`,
    `eval`, `popen`, `subprocess`, `system`, case-insensitive) correctly
    blocks the unobfuscated payload above, but is bypassable using
    Jinja2's `~` string-concatenation operator to build the blocked
    substrings at render time
    (`{{ self.__init__.__globals__.__builtins__['__imp'~'ort__']('o'~'s').__dict__['pop'~'en']('id').read() }}`)
    — confirmed this bypass genuinely achieves RCE while the filter
    correctly rejects the literal payload.
  - The secure pattern
    (`render_template_string("...{{ name }}...", name=user_input)`,
    treating user input as a template *variable* rather than template
    *source*) genuinely neutralizes both the detection probe and the RCE
    payload — both render back as inert, HTML-escaped literal text.
- **Two examples, Easy/Hard, matching XXE's graduated-pair precedent** —
  Easy: direct SSTI with zero filtering. Hard: SSTI behind a naive
  keyword blacklist that must be bypassed, teaching the real lesson that
  blacklisting substrings does not fix SSTI (the underlying flaw —
  rendering attacker-controlled template *source* at all — is what must
  change, not the specific keywords blocked).
- **No new dependency.** `render_template_string` is part of Flask/Jinja2,
  already installed. Unlike XXE, this sub-project needs no
  `requirements.txt` change and no new Docker-packaging verification for a
  third-party C-extension wheel.
- **No self-referential/SSRF-style risk.** Unlike XXE's SSRF sub-example
  (which made the app call back into itself over HTTP and hit a
  gunicorn-worker-starvation bug under real browser concurrency), SSTI's
  RCE payload runs `os.popen(...)` directly in-process — no outbound
  network call, no shared-worker-pool contention. This specific risk
  class from XXE doesn't apply here, though the plan's Docker verification
  task still confirms real command execution against the live container as
  standard practice.
- **New escaping risk this sub-project introduces that XXE never hit:**
  every example page shows illustrative `{{ }}`/`{% %}` Jinja syntax as
  *text* (e.g. "submit `{{7*7}}`" as instructional copy). Unlike XXE's
  payloads (which were XML angle-brackets, needing HTML-entity escaping),
  these payloads are literal Jinja template syntax that this project's own
  page-rendering Jinja engine would otherwise evaluate for real if shown
  unguarded inside a template block. Every such block must be wrapped in
  `{% raw %}...{% endraw %}` — this is the *other* escaping bug class this
  project hit once already (content-retrofit sub-project, `greet.html`/
  `comments.html`), now newly relevant here. Global Constraint below.

## Components

### 1. Routes

`app/categories/a03_injection/routes.py` gains, using Flask's existing
`render_template_string` (added to the existing `flask` import line, no
new import block needed beyond that):

- `GET/POST /a03/email-preview` (Easy) — a "custom email notification
  preview" feature. POST accepts a `greeting_template` form field, passes
  it directly into `render_template_string(greeting_template)`, and
  displays the rendered result. Legitimate use:
  `Hi {{ "Alice" }}, thanks for signing up!` renders normally. Attack:
  `{{7*7}}` detects the bug; the gadget-chain payload achieves RCE.
- `GET/POST /a03/bio-preview` (Hard) — a "custom profile bio template
  preview" feature, same underlying `render_template_string()` call, but
  first runs the submitted `bio_template` through a naive keyword
  blacklist (case-insensitive substring check against `os`, `import`,
  `exec`, `eval`, `popen`, `subprocess`, `system`) and returns an error if
  any are present, *without* rendering. Trainee must construct the RCE
  payload using `~` concatenation to avoid every blacklisted literal
  substring while still calling the same underlying functions.

Both routes share the identical vulnerable core
(`render_template_string(user_input)`), matching the XXE precedent of
"one underlying bug, two features/attacker-goals" — here the Hard
example additionally demonstrates why a common but flawed mitigation
(keyword blacklisting) fails.

### 2. Templates

Two new example templates,
`app/categories/a03_injection/templates/a03_injection/email_preview.html`
and `.../bio_preview.html`, in the established four-part structure
(Explanation / Detect / Exploitation / Vulnerable-vs-Secure / Try It).
Code panels use `language-python` (the vulnerable/secure contrast is
Python code, not markup — same convention as XXE's Vulnerable-vs-Secure
panels). Every illustrative `{{ }}`/`{% %}` payload shown as instructional
text is wrapped in `{% raw %}...{% endraw %}` per the Global Constraint
below.

### 3. Navigation

`app/categories/a03_injection/__init__.py` gains two new `ExampleNav`
entries in a new group `"Server-Side Template Injection (SSTI)"`,
appended after the existing `"XML External Entity Injection (XXE)"`
group: `ssti-email-preview` (Easy, endpoint
`a03_injection.email_preview`) and `ssti-blacklist-bypass` (Hard,
endpoint `a03_injection.bio_preview`).

### 4. Docker

No `Dockerfile`/`requirements.txt` changes needed — no new dependency.
The implementation plan's Docker verification task confirms real command
execution against the live container for both examples (output should
show the container's actual user/environment, e.g. matching `whoami`
inside the `python:3.12-slim`-based image, not a host-machine artifact),
following the same verification discipline as every prior sub-project.

## Global Constraints

- No changes to any existing A01/A02/A04/existing-A03 route, model, or
  template.
- The vulnerable pattern is exactly `render_template_string(user_input)`
  with no filtering (Easy) or with only a naive substring blacklist that
  doesn't address the underlying flaw (Hard) — both verified live (not
  assumed) to genuinely achieve RCE via `os.popen(...)`, and the secure
  pattern (`render_template_string("...{{ name }}...", name=user_input)`)
  verified live to genuinely neutralize both payloads.
- Every illustrative Jinja `{{ }}`/`{% %}` syntax shown as instructional
  text inside a `<pre><code>` or inline `<code>` block MUST be wrapped in
  `{% raw %}...{% endraw %}` — the plan's implementer tasks must verify
  this directly (e.g. rendering the page and confirming literal `{{7*7}}`
  text appears, not `49`) rather than assuming the wrapping is correct.
  This is a new instance of a bug class this project has hit before under
  different circumstances (unescaped HTML angle-brackets in XXE/
  content-retrofit); here the risk is unescaped/unwrapped Jinja syntax
  specifically.
- Any raw XML/HTML angle-bracket content shown as text (if any appears
  incidentally in these examples) still needs HTML-entity escaping per the
  standing XXE-era constraint — not expected to be a major factor here
  since these payloads are primarily Jinja syntax, not markup, but the
  implementer should stay alert to it.

## Testing

- Unit tests for both routes: legitimate input renders normally; the
  `{{7*7}}` detect probe evaluates to `49` on the Easy route; the RCE
  payload against the Easy route returns real command output (e.g.
  contains `uid=`); the naive blacklist correctly rejects blacklisted
  payloads on the Hard route (renders an error, does not execute); the
  `~`-concatenation bypass payload succeeds on the Hard route and returns
  real command output.
- A test confirming the SECURE `render_template_string` pattern (used
  only in the Vulnerable-vs-Secure illustrative code panel, never in the
  live route) actually neutralizes both the detect probe and the RCE
  payload when fed the identical malicious strings as *data* rather than
  *template source* — mirroring the rigor applied to every other
  example's Vulnerable-vs-Secure panel.
- A dedicated regression test for the `{% raw %}` escaping constraint: GET
  each page with `show_explanations`/`show_exploit_instructions` on, and
  assert the response body contains the literal string `{{7*7}}` (or the
  relevant illustrative payload text) while NOT containing `49` (or the
  relevant evaluated result) anywhere outside the live "Try It" result
  block — this directly guards the bug class called out in the Global
  Constraints, the same way the content-retrofit sub-project's final
  review added Detect-content tests after finding a related gap.
- Both examples' "still works with both toggles off" regression test.
- A test confirming the new sidebar group renders.

## Out of scope for this spec

- Classical Apache-style SSI directive processing (explicitly descoped in
  favor of Jinja2 SSTI, per the brainstorming decision above).
- LDAP injection and the SQLi/XSS/CMD deepening work (separate
  sub-projects, sequenced after this one).
- Any change to existing A01/A02/A04/existing-A03 examples.
- Progress tracking / Stats page.
