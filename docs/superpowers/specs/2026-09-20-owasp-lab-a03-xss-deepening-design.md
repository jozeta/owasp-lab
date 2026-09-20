# OWASP Top 10 Training Lab — A03 XSS Deepening Design Spec

Date: 2026-09-20
Status: Approved
Sub-project 6e of the extended post-A04 roadmap's A03-expansion block (sub-project 6
overall): quick fixes → UI/infra polish → sidebar regrouping → content retrofit →
UI polish round 2 → A03 expansion (XXE (done) → SSTI (done) → LDAP (done) →
SQLi deepening (done) → **XSS deepening (this spec)** → CMD-injection deepening) →
progress tracking & stats.

## Purpose

Deepen the existing Cross-Site Scripting coverage under A03 with one new,
purely additive example that teaches filter-evasion technique across three
graduated difficulties, reusing the "multi-task with solutions" content
pattern built in the SQLi-deepening sub-project without modification. This
is the fifth of six A03 injection sub-projects (XXE, SSTI, LDAP, SQLi
deepening done; XSS deepening this one, then CMD-injection deepening).

## Decisions from brainstorming

- **Purely additive — the two existing XSS examples (`reflected-xss`/Medium,
  `stored-xss`/Hard) are completely untouched.** Matches the additive-only
  pattern every A03 sub-project has used.
- **DOM-based XSS is explicitly out of scope for this piece, confirmed with
  you after live verification.** A scratch page was built and live-tested
  in a real browser tab: a client-side sink reading `location.hash` and
  writing it unsanitized into `innerHTML` via
  `document.getElementById('welcome').innerHTML = 'Welcome, ' + name + '!'`
  genuinely executes injected script (`<img src=x onerror=console.log(...)>`
  fired, confirmed via `read_console_messages`) — so the mechanism itself
  is real and would have worked as a new example. The blocker was raised
  explicitly before finalizing: DOM XSS would be the first purely
  client-side-only vulnerability in this entire lab, meaning its live
  exploit behavior cannot be verified by pytest's Flask test client at
  all (no client-side JS execution), unlike every other example in the
  project. You chose to skip it and keep this piece entirely server-side
  and fully pytest-testable, matching the rest of the lab's testing
  rigor.
- **The "multiple tasks with solutions" pattern (built in SQLi deepening)
  is reused exactly as-is** — the `{% block tasks %}` section in
  `app/core/templates/core/example_page_base.html`, using Bootstrap's
  `collapse` component for per-task "Show solution" reveals. No
  limitation was found that required changing it.
- **One new example, not several.** Confirmed with you: a single "Filter
  Bypass Challenge" example carries three graduated bypass Tasks (Easy,
  Medium, Hard), rather than spreading the same three techniques across
  three separate nav entries/pages. This mirrors the SQLi-deepening
  flagship's shape (one example, one endpoint, multiple published-solution
  tasks) and needs no new model or seed data, since every task is
  reflected (request-scoped), not persisted.
- **All three filter-bypass techniques were live-verified before
  finalizing this spec, not assumed:**
  - A filter blocking only the literal substring `<script` is bypassed by
    switching tags entirely — confirmed live via the DOM-XSS scratch page
    above, where `<img src=x onerror=console.log(...)>` executed with no
    `<script` substring present anywhere in the payload.
  - A filter that strips `<script>` and `</script>` as two independent
    passes (a realistic naive-implementation bug, distinct from stripping
    the pair as one unit) is bypassed by the nested-tag trick
    `<scr<script>ipt>alert('bypass')</scr</script>ipt>` — verified with a
    real Python reproduction of exactly this two-pass filter: after both
    substrings are removed, the leftover fragments recombine into a
    literal `<script>alert('bypass')</script>`, confirmed byte-for-byte.
  - A filter that HTML-escapes only `<` and `>` (leaving quotes untouched)
    is safe in a *tag* context but not in an HTML *attribute value*
    context — verified with a real Python reproduction: rendering the
    escaped output inside `<input type="text" value="{escaped}">`, a
    payload of `" autofocus onfocus="console.log('ATTR-BREAKOUT-XSS')`
    breaks out of the `value` attribute and adds a live event handler
    that fires without any user interaction, confirmed against the
    generated HTML string.

## Components

### 1. New Hard example — Filter Bypass Challenge

`GET /a03/filter-challenge` — a single route accepting `level` (`1`, `2`,
or `3`) and `payload` query parameters. Each level applies a distinct,
independently naive filter function to `payload` before reflecting the
result with `|safe`, matching this project's established
build-raw-HTML-then-`|safe` vulnerable pattern (the same pattern already
used in `greet()` and `comments()`):

- **Level 1 (Task 1, Easy):** filter blocks the literal substring
  `<script` (case-insensitive), nothing else:
  ```python
  def filter_level_1(payload: str) -> str:
      if "<script" in payload.lower():
          return "[blocked: script tag detected]"
      return payload
  ```
  Bypass: `<img src=x onerror=console.log('LEVEL-1-BYPASS')>` — a
  different element entirely, never containing the blocked substring.

- **Level 2 (Task 2, Medium):** filter strips `<script>` and `</script>`
  as two separate passes:
  ```python
  def filter_level_2(payload: str) -> str:
      payload = re.sub(r"<script>", "", payload, flags=re.IGNORECASE)
      payload = re.sub(r"</script>", "", payload, flags=re.IGNORECASE)
      return payload
  ```
  Bypass: `<scr<script>ipt>console.log('LEVEL-2-BYPASS')</scr</script>ipt>`
  — removing the inner `<script>`/`</script>` substrings leaves the outer
  fragments to recombine into a real `<script>...</script>` tag.

- **Level 3 (Task 3, Hard):** filter HTML-escapes only `<` and `>`,
  reflected inside an HTML attribute value rather than tag context:
  ```python
  def filter_level_3(payload: str) -> str:
      return payload.replace("<", "&lt;").replace(">", "&gt;")
  ```
  rendered as `<input type="text" value="{filtered}" placeholder="Your
  name">`. Bypass: `" autofocus onfocus="console.log('LEVEL-3-BYPASS')`
  — breaks out of the `value` attribute via an unescaped quote and adds a
  self-firing event handler; no angle brackets required, so the filter's
  own escaping never engages.

The page uses the existing Tasks pattern for all three, each task
describing its filter, one input for trying a payload against that
level, and a collapsed "Show solution" reveal containing the exact
bypass payload and an explanation of why the filter misses it.

### 2. Navigation

The new `filter-challenge` entry registers in the *existing*
"Cross-Site Scripting (XSS)" nav group in
`app/categories/a03_injection/__init__.py`, appended immediately after
the existing `stored-xss` entry (difficulty Hard) and before the
`command-injection` entry that starts the next group — preserving the
group's Easy→Hard sortedness (Medium, Hard, Hard) and following the same
insertion pattern established by SQLi deepening's `roster-lookup` entry.

## Testing

- Route-level tests for `/a03/filter-challenge` at all three levels:
  legitimate/non-malicious input passes through each filter unchanged;
  each level's blocked literal payload is genuinely blocked (proving the
  filter is real, not a no-op); each level's bypass payload survives its
  filter and appears in the raw response body in its executable,
  unescaped form (proving the bypass genuinely defeats that specific
  filter, not just that *some* input got through).
- A test confirming the Tasks section renders on this new example
  (matching the existing toggle-on/off test pattern from SQLi deepening).
- The standard nav-registration/grouping test, updated for the new entry
  landing inside the existing XSS group rather than a new group.
- No Docker/browser verification task is required for this sub-project —
  every technique here is a server-side string-transformation bug,
  fully exercised and provable through the Flask test client alone.

## Out of scope for this spec

- DOM-based XSS (declined above after live verification; the underlying
  mechanism was proven to work, but the testing-strategy trade-off — no
  pytest coverage of the live exploit — was not accepted for this piece).
- Any change to the two existing XSS examples (`reflected-xss`/
  `stored-xss`) or their existing routes/templates/tests.
- Any change to the shared `{% block tasks %}` base-template mechanism —
  reused exactly as built in SQLi deepening.
- CMD-injection deepening (the next, separate sub-project).
- Progress tracking / Stats page (a separate, later sub-project).
- Any change to XXE, SSTI, LDAP, or SQLi-deepening examples.
