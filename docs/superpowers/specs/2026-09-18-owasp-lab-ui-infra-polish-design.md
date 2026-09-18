# OWASP Top 10 Training Lab — UI/Infra Polish Design Spec

Date: 2026-09-18
Status: Approved
Sub-project 2 of 5 in the post-A04 enhancement batch (see the decomposition
agreed in conversation: quick fixes → **UI/infra polish** → sidebar
regrouping → content retrofit → progress tracking & stats).

## Purpose

Five independent, low-risk UI/infrastructure improvements to the existing
shared framework (`app/core/`), applied once so every category (A01–A10)
benefits: hover tooltips on the top nav, syntax-highlighted code panels with
line numbers, dark mode, a Tools page, and an About page. None of this
touches category-specific vulnerable logic.

## Decisions from brainstorming

- **Tooltips** use Bootstrap 5's native tooltip component (already
  vendored) driven by a new one-sentence `blurb` field on `CategoryNav` — no
  new library.
- **Line numbers** come from vendoring the small, standalone
  `highlightjs-line-numbers.js` plugin alongside the already-vendored
  highlight.js v11.9.0, rather than hand-rolling CSS-counter line wrapping.
- **Dark mode** is a manual toggle (not OS-preference-only), defaulting to
  `prefers-color-scheme` on first visit, persisted in `localStorage`.
  Toggling reloads the page rather than attempting live re-render of
  Mermaid SVGs and highlight.js output — the simplest correct approach.
- **Tools and About** are plain content pages on the existing `core_bp`
  blueprint (`/tools`, `/about`) — no new blueprint, no DB-backed content
  (static Jinja templates, edited directly in future if the tool/tech list
  changes).
- **Retrofit scope**: the `blurb` field is added to all 4 existing
  categories' `__init__.py` (one line each) so tooltips work everywhere
  immediately; no other existing category code changes.

## Components

### 1. Hover tooltips

- `app/core/nav.py`: add `blurb: str = ""` to `CategoryNav`.
- Each category's `__init__.py` (`a01_access_control` through
  `a04_insecure_design`, plus the pattern for A05–A10 going forward) passes
  `blurb=...` in its existing `CATEGORIES.append(CategoryNav(...))` call.
  Blurb text (one sentence each, reusing the spirit of each category's
  existing "What It Is" overview paragraph, condensed):
  - A01: "Access control that isn't enforced on the server, letting users act outside their intended permissions."
  - A02: "Weak or misused cryptography that exposes passwords and sensitive data instead of protecting them."
  - A03: "Untrusted input executed by an interpreter — SQL, shell, or the browser — instead of being treated as data."
  - A04: "Missing security controls baked into the design itself, not just a coding mistake."
- `app/core/templates/core/base.html`: add `data-bs-toggle="tooltip" data-bs-placement="bottom" title="{{ category.blurb }}"` to each top-nav category `<a>`.
- `static/js/lab.js`: on `DOMContentLoaded`, initialize Bootstrap tooltips:
  `document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => new bootstrap.Tooltip(el))`.

### 2. Syntax highlighting with line numbers

- Vendor `static/vendor/highlightjs/highlightjs-line-numbers.min.js`
  (MIT-licensed, single file, compatible with highlight.js 11.x).
- `app/core/templates/core/base.html`: add its `<script>` tag after the
  existing highlight.js `<script>`.
- `static/js/lab.js`: after `hljs.highlightAll()`, call
  `hljs.initLineNumbersOnLoad()` (guarded the same way as the existing
  `window.hljs` check).
- No changes needed to how category templates emit code blocks — they
  already use `<pre><code class="language-python">`.

### 3. Dark mode

- `static/vendor/highlightjs/github-dark.min.css`: new vendored file (dark
  counterpart to the already-vendored `github.min.css`).
- `app/core/templates/core/base.html`:
  - Give the highlight.js `<link>` an `id="hljs-theme"` so JS can swap its
    `href`.
  - Remove the hardcoded `data-bs-theme="light"` from `<html>`; leave the
    attribute unset in markup — JS sets it before first paint (see below).
  - Add a toggle `<button id="theme-toggle">` in the right-hand nav
    cluster, next to Tools/About/Settings, showing a sun/moon glyph (plain
    Unicode characters `☀️` / `\u{1F319}` — no new icon library).
  - Add a tiny inline `<script>` in `<head>` (before CSS/body render) that
    reads `localStorage.getItem('theme')`, falls back to
    `matchMedia('(prefers-color-scheme: dark)')`, and sets
    `document.documentElement.setAttribute('data-bs-theme', theme)`
    immediately — avoids a flash of the wrong theme.
- `static/js/lab.js`: click handler on `#theme-toggle` that flips the
  current theme, writes it to `localStorage`, and calls
  `location.reload()`.
- `static/css/lab.css`: a handful of dark-mode overrides for the elements
  Bootstrap's `data-bs-theme` doesn't auto-cover (the sidebar's
  `bg-light`/`border-end`, which needs a dark-mode variant via
  `[data-bs-theme="dark"] #sidebar { ... }`).
- `static/js/lab.js`: when the resolved theme is dark, pass
  `mermaid.initialize({ startOnLoad: true, theme: "dark" })` instead of
  `"default"`, and swap the `#hljs-theme` link's `href` to
  `github-dark.min.css` (both read from the same theme value already
  resolved in `<head>`, exposed via a small `window.__labTheme` set by the
  inline head script).

### 4. Tools page (`GET /tools`)

- `app/core/views.py`: new route rendering `core/tools.html`. No template
  inheritance changes beyond extending `core/base.html` directly (this is a
  plain content page, not a category overview).
- `app/core/templates/core/base.html`: add a "Tools" nav-item in the
  right-hand cluster.
- Content (a Bootstrap table: Tool | What it's for | Download):

  | Tool | What it's for | Download |
  | --- | --- | --- |
  | Browser DevTools | Inspect requests/responses, cookies, and page source — the starting point for almost every exercise. Built into Chrome, Firefox, Edge, Safari. | (built-in, no download) |
  | curl | Send crafted HTTP requests from the command line — essential for exploits that need custom headers, methods, or raw payloads. | <https://curl.se/download.html> |
  | An intercepting proxy (Burp Suite Community or OWASP ZAP) | Inspect and modify requests/responses in flight; replay and fuzz payloads. | <https://portswigger.net/burp/communitydownload> / <https://www.zaproxy.org/download/> |
  | sqlmap | Automates detecting and exploiting SQL injection — useful once you understand a vulnerability manually and want to see full automated exploitation. | <https://github.com/sqlmapproject/sqlmap> |
  | netcat / ncat | Low-level TCP interaction — useful for command-injection exercises that involve reverse or bind shells. | <https://nmap.org/ncat/> |
  | Python 3 | Write short scripts to compute payloads (e.g. hashing a reset token offline) or automate an exploit. | <https://www.python.org/downloads/> |
  | A REST client (Postman or Insomnia) | Build and save HTTP requests with a GUI, as an alternative to curl. | <https://www.postman.com/downloads/> / <https://insomnia.rest/download> |

  Each row also gets a one-line note in the page intro: "You won't need
  every tool for every exercise — most examples are fully exploitable from
  the browser alone; the rest call out which tool they need."

### 5. About page (`GET /about`)

- `app/core/views.py`: new route rendering `core/about.html`.
- `app/core/templates/core/base.html`: add an "About" nav-item next to
  Tools.
- Content:
  - **What this is**: a self-contained, intentionally vulnerable training
    lab teaching the OWASP Top 10 (2021) through working, exploitable
    examples — modeled after OWASP WebGoat, Juice Shop, and DVWA. Restates
    the "vulnerabilities are the deliverable" framing from the README.
  - **Infrastructure**: Flask (Python) + Jinja2 server-rendered templates,
    Bootstrap 5 (vendored, no CDN), PostgreSQL via SQLAlchemy, packaged with
    Docker + docker-compose, non-root container, bound to `127.0.0.1` only.
  - **Safety model**: short recap of the README's Safety model section
    (localhost-only, non-root, synthetic data, force-reset safety net),
    with a link to the full README-equivalent detail if useful — since
    there's no README route, this section just inlines the same three
    bullets directly.
  - **Why examples still work with explanations/exploit-steps hidden**:
    one paragraph explaining the Settings toggles exist to let you attempt
    blind exploitation, and that hiding the teaching text never disables
    the underlying vulnerability.

## Testing

- One test per new route (`/tools`, `/about`) asserting 200 and a
  distinguishing string from their content.
- A test asserting every entry in `CATEGORIES` has a non-empty `blurb`
  (catches a category added later without one).
- A test asserting the tooltip `title` attribute renders for at least one
  category link in the home page response.
- A test asserting `github-dark.min.css` and
  `highlightjs-line-numbers.min.js` exist under `static/vendor/` (a cheap
  guard against the vendoring step being skipped).
- No JS unit tests (no JS test harness in this project) — the dark-mode
  toggle and tooltip initialization are verified manually via the Docker
  verification step at the end of the implementation plan, the same way
  prior categories' UI was manually spot-checked.

## Out of scope for this spec

- Any change to category-specific vulnerable routes/logic.
- Sidebar regrouping by vulnerability sub-type (sub-project 3).
- Rewriting example content (sub-project 4).
- Progress tracking / Stats page (sub-project 5).
