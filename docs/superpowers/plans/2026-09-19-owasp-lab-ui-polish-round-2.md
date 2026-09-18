# UI Polish Round 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse the top nav's settings-like links (Theme, Tools, About, Settings, Log out) behind a hamburger dropdown, restyle the theme control to fit inside it, fix cramped line-number padding in code panels, apply a small visual-polish pass, and add zproxy to the Tools page.

**Architecture:** All changes live in `app/core/templates/core/base.html` (nav restructuring), `static/css/lab.css` (padding + polish, CSS-only), and `app/core/templates/core/tools.html` (one new table row). No routes, models, or JS logic changes — `toggleLabTheme()` is reused unmodified, only its calling markup moves.

**Tech Stack:** Flask, Jinja2, Bootstrap 5 (native dropdown component, already vendored), vanilla CSS. No new dependencies.

**Spec:** docs/superpowers/specs/2026-09-19-owasp-lab-ui-polish-round-2-design.md

## Global Constraints

- No route, model, or vulnerable-logic changes.
- The hamburger dropdown is a *new*, always-visible dropdown, distinct from the navbar's existing `navbar-toggler`/`#navMain` mobile-collapse button, which stays untouched.
- `toggleLabTheme()` in `static/js/lab.js` needs no changes — only the button's markup/class/label change.
- Every new dark-mode CSS rule gets its light-mode counterpart in the same change (and vice versa) — no rule ships light-only or dark-only.
- zproxy is added to the Tools page exactly as linked (`https://github.com/jozeta/zproxy`), described plainly as "a lightweight alternative to Burp Suite" — no hedging language.

---

### Task 1: Hamburger dropdown + theme control restyle

**Files:**
- Modify: `app/core/templates/core/base.html`
- Modify: `tests/test_core_views.py`

**Interfaces:**
- Consumes: `toggleLabTheme()` (existing, unchanged, from `static/js/lab.js`).
- Produces: nothing consumed by later tasks — this is a leaf feature.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_core_views.py`:

```python


def test_home_page_has_hamburger_dropdown_menu(client):
    response = client.get("/")
    assert response.status_code == 200
    body = response.data.decode()
    assert 'data-bs-toggle="dropdown"' in body
    assert 'class="dropdown-menu dropdown-menu-end"' in body


def test_home_page_dropdown_contains_theme_tools_about_settings(client):
    response = client.get("/")
    body = response.data.decode()
    assert 'id="theme-toggle"' in body
    assert 'class="dropdown-item" href="{}"'.format("/tools") in body
    assert 'class="dropdown-item" href="{}"'.format("/about") in body
    assert 'class="dropdown-item" href="{}"'.format("/settings") in body


def test_logged_out_home_page_has_no_logout_dropdown_item(client):
    response = client.get("/")
    body = response.data.decode()
    assert "Log out" not in body
    assert 'href="/switch-user"' in body


def test_logged_in_home_page_has_logout_as_dropdown_item(app, client, login):
    login("alice")
    response = client.get("/")
    body = response.data.decode()
    assert 'class="dropdown-item">Log out</button>' in body
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_core_views.py -k "dropdown or logout_dropdown or logout" -v`
Expected: all 4 new tests FAIL (the dropdown markup doesn't exist yet; Tools/About/Settings links currently use `class="nav-link"` not `class="dropdown-item"`; Log out is currently a `btn btn-outline-light btn-sm`, not a `dropdown-item`).

- [ ] **Step 3: Restructure the right-hand nav cluster**

In `app/core/templates/core/base.html`, the right-hand nav cluster currently reads:

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

Replace it with:

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

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `pytest tests/test_core_views.py -k "dropdown or logout_dropdown or logout" -v`
Expected: all 4 PASS.

- [ ] **Step 5: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (156 existing + 4 new = 160). Pay particular attention to any existing test that asserted on the OLD `btn btn-outline-light btn-sm` Log out button or the old standalone Tools/About/Settings `nav-link` markup — none currently do (confirmed at plan-writing time by grepping `tests/test_core_views.py` for "Log out"/"theme-toggle"/"Tools"/"About": only `Logged in as alice` presence/absence and the `id="theme-toggle"` substring are checked, both of which this change preserves), but if the full suite reveals one this plan missed, that is a real finding — fix the test to match the new markup, not the other way around, since the new markup is what this task intentionally changes.

- [ ] **Step 6: Commit**

```bash
git add app/core/templates/core/base.html tests/test_core_views.py
git commit -m "feat: collapse Theme/Tools/About/Settings/Log out into a hamburger dropdown"
```

---

### Task 2: Line-number padding fix + visual polish pass

**Files:**
- Modify: `static/css/lab.css`

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing consumed by later tasks — CSS-only, no test coverage per this project's established convention (no CSS testing harness).

- [ ] **Step 1: Append the line-number padding fix**

Append to `static/css/lab.css`:

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

- [ ] **Step 2: Append the visual polish rules**

Append to `static/css/lab.css`:

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

- [ ] **Step 3: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (160, unchanged from Task 1 — this task adds no new tests, matching the spec's stated no-CSS-test convention).

- [ ] **Step 4: Commit**

```bash
git add static/css/lab.css
git commit -m "style: fix code-panel line-number padding and add a visual polish pass"
```

---

### Task 3: Add zproxy to the Tools page

**Files:**
- Modify: `app/core/templates/core/tools.html`
- Modify: `tests/test_core_views.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing consumed by later tasks.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_core_views.py`:

```python


def test_tools_page_lists_zproxy(client):
    response = client.get("/tools")
    assert response.status_code == 200
    body = response.data.decode()
    assert "zproxy" in body
    assert 'href="https://github.com/jozeta/zproxy"' in body
    assert "lightweight alternative to Burp Suite" in body
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_core_views.py::test_tools_page_lists_zproxy -v`
Expected: FAIL (the row doesn't exist yet).

- [ ] **Step 3: Add the zproxy row**

In `app/core/templates/core/tools.html`, the table currently has this row for the intercepting proxy, immediately followed by the sqlmap row:

```html
    <tr>
      <td>An intercepting proxy (Burp Suite Community or OWASP ZAP)</td>
      <td>Inspect and modify requests/responses in flight; replay and fuzz payloads.</td>
      <td>
        <a href="https://portswigger.net/burp/communitydownload">Burp Suite Community</a>
        /
        <a href="https://www.zaproxy.org/download/">OWASP ZAP</a>
      </td>
    </tr>
    <tr>
      <td>sqlmap</td>
```

Insert the new row between them:

```html
    <tr>
      <td>An intercepting proxy (Burp Suite Community or OWASP ZAP)</td>
      <td>Inspect and modify requests/responses in flight; replay and fuzz payloads.</td>
      <td>
        <a href="https://portswigger.net/burp/communitydownload">Burp Suite Community</a>
        /
        <a href="https://www.zaproxy.org/download/">OWASP ZAP</a>
      </td>
    </tr>
    <tr>
      <td>zproxy</td>
      <td>A lightweight alternative to Burp Suite.</td>
      <td><a href="https://github.com/jozeta/zproxy">github.com/jozeta/zproxy</a></td>
    </tr>
    <tr>
      <td>sqlmap</td>
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/test_core_views.py::test_tools_page_lists_zproxy -v`
Expected: PASS

- [ ] **Step 5: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (160 + 1 = 161)

- [ ] **Step 6: Commit**

```bash
git add app/core/templates/core/tools.html tests/test_core_views.py
git commit -m "feat: add zproxy to the Tools page"
```

---

### Task 4: Full regression + Docker verification

**Files:**
- None (verification-only task; no code changes expected).

**Interfaces:**
- Consumes: nothing new (verifies Tasks 1–3's combined output).
- Produces: nothing — this is the final task.

- [ ] **Step 1: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (161 tests)

- [ ] **Step 2: Docker end-to-end verification**

```bash
docker compose up --build -d
```

Then, via curl against the live container (`http://127.0.0.1:5001`):

- `/` returns 200 and contains `data-bs-toggle="dropdown"` and `dropdown-menu dropdown-menu-end`.
- `/tools` returns 200 and contains `zproxy` and `href="https://github.com/jozeta/zproxy"`.
- A category overview page (e.g. `/a03/`) still returns 200 with `Vulnerable vs. Secure` present, confirming the shared-template change from a prior sub-project still works alongside this one.

If you have a browser tool available, additionally visit the home page and:
- Confirm the ☰ button opens a dropdown containing Toggle theme / Tools / About / Settings (and Log out when logged in), and that clicking Tools/About/Settings navigates correctly and clicking Toggle theme actually switches the theme (page reloads in the other mode).
- Confirm code panels (e.g. on `/a01/profile/1`) now show comfortable spacing between the line-number gutter and the code, in both light and dark mode.
- Confirm cards have a subtle visible shadow and sidebar links show a hover highlight, in both light and dark mode.
If no browser tool is available, note that as a known gap in your report rather than skipping the curl-based checks above.

Tear down cleanly afterward:

```bash
docker compose down
```

- [ ] **Step 3: Commit**

No code changes are expected from this task. If the Docker/curl verification finds nothing to fix, there is nothing to commit — report DONE with the verification evidence in your report file rather than an empty commit.
