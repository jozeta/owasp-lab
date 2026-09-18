# OWASP Top 10 Training Lab — UI Polish Round 2 Design Spec

Date: 2026-09-19
Status: Approved
Sub-project 5 of 7 in the extended post-A04 roadmap (quick fixes → UI/infra
polish → sidebar regrouping → content retrofit → **UI polish round 2** →
A03 expansion → progress tracking & stats).

## Purpose

A second round of small, self-contained UI/chrome improvements, parallel
in spirit and size to the already-completed "UI/infra polish" sub-project:
collapse the top nav's settings-like links behind a hamburger dropdown,
restyle the theme toggle to fit inside it, fix cramped line-number padding
in code panels, a light visual-polish pass within the existing Bootstrap
look, and one content addition to the Tools page.

## Decisions from brainstorming

- **Hamburger dropdown** is a *new*, always-visible (not just mobile)
  Bootstrap dropdown in the right-hand nav cluster — distinct from the
  navbar's existing `navbar-toggler`/`#navMain` collapse button, which
  only handles narrow-viewport collapsing of the whole nav and is
  untouched by this spec. The new dropdown holds, in order: Theme, Tools,
  About, Settings, and (when logged in) Log out. "Logged in as X" / "Log
  in" stay outside the dropdown, visible in the nav bar directly, since
  they're identity/primary-action rather than settings.
- **Theme control moves from a standalone button to a dropdown item.**
  Since it's no longer competing for space as an always-visible button, it
  gets a lighter, compact treatment (icon + short label, styled like every
  other `dropdown-item`) instead of the current full "🌓 Theme"
  `btn btn-outline-light`. The `id="theme-toggle"` and the
  `onclick="toggleLabTheme()"` handler are unchanged — `toggleLabTheme()`
  itself needs no JS changes, only its markup/styling context changes.
- **Line-number padding fix targets the vendored plugin's real class
  names** (`hljs-ln-numbers`, `hljs-ln-code`), confirmed by grepping the
  vendored `highlightjs-line-numbers.min.js` — not guessed selectors.
- **Polish pass stays CSS-only**, in `static/css/lab.css`, and stays within
  the existing Bootstrap 5 look per your explicit choice (not a redesign):
  subtle card shadows/borders for depth, a hover state for sidebar links
  (currently only the active link has any distinct styling), and slightly
  bolder card-header text for clearer visual hierarchy. Both light and
  dark mode get matching treatment (the dark-mode sidebar-contrast bug
  from an earlier sub-project's final review is the cautionary example
  here — every new dark-mode-affecting rule gets its dark counterpart in
  the same change, not added later).
- **Tools page addition**: zproxy, linked exactly as given
  (`https://github.com/jozeta/zproxy`), described plainly as "a
  lightweight alternative to Burp Suite" — no hedging or caveats about the
  project's maturity, per your explicit answer.

## Components

### 1. Hamburger dropdown

`app/core/templates/core/base.html`'s right-hand nav cluster currently
reads:

```html
        <ul class="navbar-nav">
          {% if current_user %}
          <li class="nav-item d-flex align-items-center text-light me-3">Logged in as {{ current_user.username }}</li>
          <li class="nav-item">
            <form action="{{ url_for('core.logout') }}" method="post" class="d-inline">
              <button type="submit" class="btn btn-outline-light btn-sm">Log out</button>
            </form>
          </li>
          {% else %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('core.switch_user') }}">Log in</a></li>
          {% endif %}
          <li class="nav-item">
            <button type="button" id="theme-toggle" class="btn btn-outline-light btn-sm" onclick="toggleLabTheme()">🌓 Theme</button>
          </li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('core.tools_page') }}">Tools</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('core.about_page') }}">About</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('core.settings_page') }}">Settings</a></li>
        </ul>
```

Restructured to:

```html
        <ul class="navbar-nav">
          {% if current_user %}
          <li class="nav-item d-flex align-items-center text-light me-3">Logged in as {{ current_user.username }}</li>
          {% else %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('core.switch_user') }}">Log in</a></li>
          {% endif %}
          <li class="nav-item dropdown">
            <button class="btn btn-outline-light btn-sm dropdown-toggle" type="button"
                    data-bs-toggle="dropdown" aria-expanded="false" aria-label="Menu">
              ☰
            </button>
            <ul class="dropdown-menu dropdown-menu-end">
              <li>
                <button type="button" id="theme-toggle" class="dropdown-item" onclick="toggleLabTheme()">
                  🌗 Toggle theme
                </button>
              </li>
              <li><a class="dropdown-item" href="{{ url_for('core.tools_page') }}">Tools</a></li>
              <li><a class="dropdown-item" href="{{ url_for('core.about_page') }}">About</a></li>
              <li><a class="dropdown-item" href="{{ url_for('core.settings_page') }}">Settings</a></li>
              {% if current_user %}
              <li><hr class="dropdown-divider"></li>
              <li>
                <form action="{{ url_for('core.logout') }}" method="post">
                  <button type="submit" class="dropdown-item">Log out</button>
                </form>
              </li>
              {% endif %}
            </ul>
          </li>
        </ul>
```

The dropdown uses Bootstrap's native `dropdown`/`dropdown-toggle`/
`dropdown-menu`/`dropdown-item` components — already available via the
vendored Bootstrap bundle JS, no new wiring required. All existing tests
that check for `href="..."` substrings against Tools/About/Settings links
keep passing unmodified, since the links remain in the rendered HTML (just
inside a dropdown that's collapsed by CSS until clicked, not
conditionally rendered).

### 2. Line-number padding fix

`static/css/lab.css` gains:

```css
.hljs-ln-numbers {
  padding-right: 1em;
  text-align: right;
  -webkit-user-select: none;
  user-select: none;
}

.hljs-ln-code {
  padding-left: 1em;
}
```

### 3. Visual polish pass

`static/css/lab.css` gains (light + dark variants together, per the
lesson from the earlier dark-mode-contrast final-review finding):

```css
.card {
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
}

[data-bs-theme="dark"] .card {
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
}

.card-header {
  font-weight: 600;
}

#sidebar .nav-link:hover {
  background-color: rgba(0, 0, 0, 0.04);
  border-radius: 0.25rem;
}

[data-bs-theme="dark"] #sidebar .nav-link:hover {
  background-color: rgba(255, 255, 255, 0.08);
}
```

### 4. Tools page addition

`app/core/templates/core/tools.html`'s table gains one row, in the same
position/style as the existing rows:

```html
    <tr>
      <td>zproxy</td>
      <td>A lightweight alternative to Burp Suite.</td>
      <td><a href="https://github.com/jozeta/zproxy">github.com/jozeta/zproxy</a></td>
    </tr>
```

## Testing

- Existing nav-link tests (checking `href="..."` substrings for
  Tools/About/Settings) keep passing unmodified — dropdown items still
  render those hrefs in the page source.
- A new test confirms the hamburger dropdown toggle button and
  `dropdown-menu` markup are present on the home page.
- The existing `id="theme-toggle"` test keeps passing unmodified (the
  attribute moves templates but not away).
- A new test confirms the Log out button only appears (as a dropdown item)
  when logged in, and the Log in link appears outside the dropdown when
  not.
- A new test confirms the Tools page contains the zproxy row and its
  exact link.
- No test for the CSS-only line-number/polish changes (no CSS testing
  convention in this project, matching sub-project 2's precedent) — spot
  checked manually in the final Docker-verification task, same pattern as
  every prior sub-project.

## Out of scope for this spec

- Any route, model, or vulnerable-logic change.
- A05–A10 content (unaffected — this only touches shared chrome).
- The A03 expansion (sub-project 6) and progress tracking (sub-project 7).
