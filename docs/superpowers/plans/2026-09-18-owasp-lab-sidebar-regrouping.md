# Sidebar Regrouping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Group each category's examples by vulnerability sub-type in the left sidebar and the Overview page's "Examples in This Category" list, sorted Easy → Hard within each group, retrofitted onto A01–A04 and established as the convention for A05–A10.

**Architecture:** `ExampleNav` gains a required `group` field; `CategoryNav` gains a `grouped_examples()` method that partitions `examples` into `(group_name, [ExampleNav])` pairs in first-occurrence order (never alphabetical — the source list stays the single source of truth for display order). Both the sidebar (`base.html`) and the Overview page's example list (`overview_base.html`) render through this method instead of a flat loop.

**Tech Stack:** Flask, Jinja2 (existing `selectattr`/`in` test usage, no new templating features), pytest.

**Spec:** docs/superpowers/specs/2026-09-18-owasp-lab-sidebar-regrouping-design.md

## Global Constraints

- `ExampleNav.group` is a required field (no default) — every example, in every category including future A05–A10, must declare its vulnerability sub-type explicitly.
- Group order is first-occurrence order in each category's `examples=[...]` list — never alphabetical, never auto-sorted.
- Difficulty order within a group stays hand-authored (no runtime sorting); a test per category verifies each group's difficulties are non-decreasing (Easy < Medium < Hard).
- A group heading renders only if at least one of its examples has a registered endpoint (reuses the existing `registered_endpoints` guard, now checked per-group as well as per-example).
- No change to any category's vulnerable routes, models, or example-page templates — this plan touches only `app/core/nav.py`, `app/core/templates/core/base.html`, `app/core/templates/core/overview_base.html`, each category's `__init__.py`, and tests.
- This project has no JS test harness and needs none here — this is a pure server-rendered template change.

---

### Task 1: `ExampleNav.group` + `CategoryNav.grouped_examples()` + retrofit A01–A04

**Files:**
- Modify: `app/core/nav.py`
- Modify: `tests/test_nav.py`
- Modify: `app/categories/a01_access_control/__init__.py`
- Modify: `app/categories/a02_crypto_failures/__init__.py`
- Modify: `app/categories/a03_injection/__init__.py`
- Modify: `app/categories/a04_insecure_design/__init__.py`
- Modify: `tests/test_a01_overview.py`
- Modify: `tests/test_a02_overview.py`
- Modify: `tests/test_a03_overview.py`
- Modify: `tests/test_a04_overview.py`

**Interfaces:**
- Consumes: nothing new — `ExampleNav`/`CategoryNav` already exist at `app/core/nav.py`.
- Produces: `ExampleNav.group: str` (required, positioned right after `title`), `CategoryNav.grouped_examples() -> list[tuple[str, list[ExampleNav]]]`. Task 2 calls `active_category.grouped_examples()` from both templates.

This task must land atomically: `group` is a required field, so every existing `ExampleNav(...)` construction in the codebase needs a `group=` value in the same commit, or the whole app fails to import.

- [ ] **Step 1: Update `tests/test_nav.py`'s existing tests and add new ones for `grouped_examples()`**

Replace the whole file with:

```python
from app.core.nav import CategoryNav, ExampleNav


def test_example_nav_difficulty_badge_classes():
    easy = ExampleNav(id="x", title="X", group="G", difficulty="Easy", endpoint="core.home")
    medium = ExampleNav(id="y", title="Y", group="G", difficulty="Medium", endpoint="core.home")
    hard = ExampleNav(id="z", title="Z", group="G", difficulty="Hard", endpoint="core.home")

    assert easy.difficulty_badge_class() == "text-bg-success"
    assert medium.difficulty_badge_class() == "text-bg-warning"
    assert hard.difficulty_badge_class() == "text-bg-danger"


def test_category_nav_holds_ordered_examples():
    category = CategoryNav(
        id="a01_access_control",
        short_id="A01",
        title="Broken Access Control",
        blueprint_name="a01_access_control",
        overview_endpoint="a01_access_control.overview",
        examples=[
            ExampleNav(id="idor", title="IDOR", group="IDOR", difficulty="Easy", endpoint="a01_access_control.idor"),
        ],
    )
    assert category.examples[0].difficulty == "Easy"
    assert category.seed_fn is None


def test_category_nav_defaults_to_empty_blurb():
    category = CategoryNav(
        id="x",
        short_id="X",
        title="X",
        blueprint_name="x",
        overview_endpoint="core.home",
    )
    assert category.blurb == ""


def test_every_registered_category_has_a_nonempty_blurb(app):
    # `app` fixture forces create_app() to run, which is what actually
    # imports every category blueprint and populates CATEGORIES -- without
    # it this test could vacuously pass on an empty list depending on
    # pytest's collection order.
    from app.core.nav import CATEGORIES

    for category in CATEGORIES:
        assert category.blurb.strip() != "", f"{category.short_id} is missing a blurb"


def test_grouped_examples_orders_by_first_occurrence():
    category = CategoryNav(
        id="x",
        short_id="X",
        title="X",
        blueprint_name="x",
        overview_endpoint="core.home",
        examples=[
            ExampleNav(id="a", title="A", group="Group B", difficulty="Easy", endpoint="core.home"),
            ExampleNav(id="b", title="B", group="Group A", difficulty="Easy", endpoint="core.home"),
            ExampleNav(id="c", title="C", group="Group B", difficulty="Hard", endpoint="core.home"),
        ],
    )
    grouped = category.grouped_examples()
    assert [name for name, _ in grouped] == ["Group B", "Group A"]
    assert [e.id for e in grouped[0][1]] == ["a", "c"]
    assert [e.id for e in grouped[1][1]] == ["b"]


def test_grouped_examples_single_example_category():
    category = CategoryNav(
        id="x",
        short_id="X",
        title="X",
        blueprint_name="x",
        overview_endpoint="core.home",
        examples=[
            ExampleNav(id="a", title="A", group="Only Group", difficulty="Easy", endpoint="core.home"),
        ],
    )
    grouped = category.grouped_examples()
    assert grouped == [("Only Group", [category.examples[0]])]


def test_grouped_examples_empty_category():
    category = CategoryNav(
        id="x",
        short_id="X",
        title="X",
        blueprint_name="x",
        overview_endpoint="core.home",
    )
    assert category.grouped_examples() == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_nav.py -v`
Expected: the `grouped_examples` tests FAIL with `AttributeError: 'CategoryNav' object has no attribute 'grouped_examples'`; the other tests (which now pass `group=`) FAIL with `TypeError: __init__() got an unexpected keyword argument 'group'` (the field doesn't exist on `ExampleNav` yet).

- [ ] **Step 3: Add `ExampleNav.group` and `CategoryNav.grouped_examples()`**

In `app/core/nav.py`, the current file reads:

```python
from dataclasses import dataclass, field


@dataclass
class ExampleNav:
    id: str
    title: str
    difficulty: str
    endpoint: str

    def difficulty_badge_class(self) -> str:
        return {
            "Easy": "text-bg-success",
            "Medium": "text-bg-warning",
            "Hard": "text-bg-danger",
        }[self.difficulty]


@dataclass
class CategoryNav:
    id: str
    short_id: str
    title: str
    blueprint_name: str
    overview_endpoint: str
    examples: list = field(default_factory=list)
    seed_fn: object = None
    blurb: str = ""


CATEGORIES: list = []
```

Change it to:

```python
from dataclasses import dataclass, field


@dataclass
class ExampleNav:
    id: str
    title: str
    group: str
    difficulty: str
    endpoint: str

    def difficulty_badge_class(self) -> str:
        return {
            "Easy": "text-bg-success",
            "Medium": "text-bg-warning",
            "Hard": "text-bg-danger",
        }[self.difficulty]


@dataclass
class CategoryNav:
    id: str
    short_id: str
    title: str
    blueprint_name: str
    overview_endpoint: str
    examples: list = field(default_factory=list)
    seed_fn: object = None
    blurb: str = ""

    def grouped_examples(self):
        groups = {}
        order = []
        for example in self.examples:
            if example.group not in groups:
                groups[example.group] = []
                order.append(example.group)
            groups[example.group].append(example)
        return [(name, groups[name]) for name in order]


CATEGORIES: list = []
```

- [ ] **Step 4: Run `tests/test_nav.py` to verify it passes**

Run: `pytest tests/test_nav.py -v`
Expected: PASS (7 tests: 4 pre-existing plus 3 new `grouped_examples` tests)

- [ ] **Step 5: Retrofit A01 — add `group=` to each example, no reordering needed**

In `app/categories/a01_access_control/__init__.py`, the `examples=[...]` list currently reads:

```python
        examples=[
            ExampleNav(
                id="idor",
                title="View Another User's Profile (IDOR)",
                difficulty="Easy",
                endpoint="a01_access_control.idor",
            ),
            ExampleNav(
                id="admin-users",
                title="Hidden Admin Panel",
                difficulty="Medium",
                endpoint="a01_access_control.admin_users",
            ),
            ExampleNav(
                id="mass-assignment",
                title="Account Update Role Escalation",
                difficulty="Hard",
                endpoint="a01_access_control.account_update",
            ),
        ],
```

Change it to:

```python
        examples=[
            ExampleNav(
                id="idor",
                title="View Another User's Profile (IDOR)",
                group="Insecure Direct Object References (IDOR)",
                difficulty="Easy",
                endpoint="a01_access_control.idor",
            ),
            ExampleNav(
                id="admin-users",
                title="Hidden Admin Panel",
                group="Missing Function-Level Access Control",
                difficulty="Medium",
                endpoint="a01_access_control.admin_users",
            ),
            ExampleNav(
                id="mass-assignment",
                title="Account Update Role Escalation",
                group="Mass Assignment",
                difficulty="Hard",
                endpoint="a01_access_control.account_update",
            ),
        ],
```

In `tests/test_a01_overview.py`, the `test_a01_registered_in_nav` test currently reads:

```python
def test_a01_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a01 = next(c for c in CATEGORIES if c.id == "a01_access_control")
    assert a01.short_id == "A01"
    assert [e.difficulty for e in a01.examples] == ["Easy", "Medium", "Hard"]
```

Leave it unchanged (the flat order doesn't change for A01) and append a new test:

```python


def test_a01_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a01 = next(c for c in CATEGORIES if c.id == "a01_access_control")
    grouped = a01.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Insecure Direct Object References (IDOR)",
        "Missing Function-Level Access Control",
        "Mass Assignment",
    ]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"
```

- [ ] **Step 6: Retrofit A02 — add `group=` to each example, no reordering needed**

In `app/categories/a02_crypto_failures/__init__.py`, the `examples=[...]` list currently reads:

```python
        examples=[
            ExampleNav(
                id="credential-dump",
                title="Leaked Credential Dump",
                difficulty="Easy",
                endpoint="a02_crypto_failures.credential_dump",
            ),
            ExampleNav(
                id="encrypted-notes",
                title="Weak Encryption (ECB Mode)",
                difficulty="Medium",
                endpoint="a02_crypto_failures.encrypted_notes",
            ),
            ExampleNav(
                id="reset-token",
                title="Predictable Password Reset Token",
                difficulty="Hard",
                endpoint="a02_crypto_failures.forgot_password",
            ),
        ],
```

Change it to:

```python
        examples=[
            ExampleNav(
                id="credential-dump",
                title="Leaked Credential Dump",
                group="Weak Hashing",
                difficulty="Easy",
                endpoint="a02_crypto_failures.credential_dump",
            ),
            ExampleNav(
                id="encrypted-notes",
                title="Weak Encryption (ECB Mode)",
                group="Weak Encryption",
                difficulty="Medium",
                endpoint="a02_crypto_failures.encrypted_notes",
            ),
            ExampleNav(
                id="reset-token",
                title="Predictable Password Reset Token",
                group="Predictable Tokens",
                difficulty="Hard",
                endpoint="a02_crypto_failures.forgot_password",
            ),
        ],
```

In `tests/test_a02_overview.py`, leave `test_a02_registered_in_nav` unchanged and append:

```python


def test_a02_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a02 = next(c for c in CATEGORIES if c.id == "a02_crypto_failures")
    grouped = a02.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Weak Hashing",
        "Weak Encryption",
        "Predictable Tokens",
    ]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"
```

- [ ] **Step 7: Retrofit A03 — add `group=` AND reorder so each sub-type's examples are consecutive**

In `app/categories/a03_injection/__init__.py`, the `examples=[...]` list currently reads:

```python
        examples=[
            ExampleNav(
                id="sqli-login",
                title="Authentication Bypass via SQL Injection",
                difficulty="Easy",
                endpoint="a03_injection.login",
            ),
            ExampleNav(
                id="union-exfiltration",
                title="UNION-Based SQL Injection Data Exfiltration",
                difficulty="Medium",
                endpoint="a03_injection.search",
            ),
            ExampleNav(
                id="reflected-xss",
                title="Reflected XSS in Greeting Page",
                difficulty="Medium",
                endpoint="a03_injection.greet",
            ),
            ExampleNav(
                id="blind-sqli",
                title="Blind Time-Based SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.check_username",
            ),
            ExampleNav(
                id="command-injection",
                title="OS Command Injection in Host Lookup Tool",
                difficulty="Hard",
                endpoint="a03_injection.host_lookup",
            ),
            ExampleNav(
                id="stored-xss",
                title="Stored XSS in Comments",
                difficulty="Hard",
                endpoint="a03_injection.comments",
            ),
        ],
```

Replace the entire list with this reordered, grouped version:

```python
        examples=[
            ExampleNav(
                id="sqli-login",
                title="Authentication Bypass via SQL Injection",
                group="SQL Injection",
                difficulty="Easy",
                endpoint="a03_injection.login",
            ),
            ExampleNav(
                id="union-exfiltration",
                title="UNION-Based SQL Injection Data Exfiltration",
                group="SQL Injection",
                difficulty="Medium",
                endpoint="a03_injection.search",
            ),
            ExampleNav(
                id="blind-sqli",
                title="Blind Time-Based SQL Injection",
                group="SQL Injection",
                difficulty="Hard",
                endpoint="a03_injection.check_username",
            ),
            ExampleNav(
                id="reflected-xss",
                title="Reflected XSS in Greeting Page",
                group="Cross-Site Scripting (XSS)",
                difficulty="Medium",
                endpoint="a03_injection.greet",
            ),
            ExampleNav(
                id="stored-xss",
                title="Stored XSS in Comments",
                group="Cross-Site Scripting (XSS)",
                difficulty="Hard",
                endpoint="a03_injection.comments",
            ),
            ExampleNav(
                id="command-injection",
                title="OS Command Injection in Host Lookup Tool",
                group="OS Command Injection",
                difficulty="Hard",
                endpoint="a03_injection.host_lookup",
            ),
        ],
```

In `tests/test_a03_overview.py`, the `test_a03_registered_in_nav` test currently reads:

```python
def test_a03_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    assert a03.short_id == "A03"
    assert [e.difficulty for e in a03.examples] == [
        "Easy",
        "Medium",
        "Medium",
        "Hard",
        "Hard",
        "Hard",
    ]
```

Change the asserted list to match the new order (the reorder moves `command-injection`'s difficulty from position 5 to position 6, and `reflected-xss`/`blind-sqli` swap relative order):

```python
def test_a03_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    assert a03.short_id == "A03"
    assert [e.difficulty for e in a03.examples] == [
        "Easy",
        "Medium",
        "Hard",
        "Medium",
        "Hard",
        "Hard",
    ]
```

Append a new test:

```python


def test_a03_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    grouped = a03.grouped_examples()
    assert [name for name, _ in grouped] == [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "OS Command Injection",
    ]
    assert [e.id for e in grouped[0][1]] == ["sqli-login", "union-exfiltration", "blind-sqli"]
    assert [e.id for e in grouped[1][1]] == ["reflected-xss", "stored-xss"]
    assert [e.id for e in grouped[2][1]] == ["command-injection"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"
```

- [ ] **Step 8: Retrofit A04 — add `group=` to each example, no reordering needed**

In `app/categories/a04_insecure_design/__init__.py`, the `examples=[...]` list currently reads:

```python
        examples=[
            ExampleNav(
                id="unlimited-coupon",
                title="Unlimited Coupon Reuse",
                difficulty="Easy",
                endpoint="a04_insecure_design.coupon_cart",
            ),
            ExampleNav(
                id="negative-quantity",
                title="Negative Quantity Price Manipulation",
                difficulty="Medium",
                endpoint="a04_insecure_design.quantity_cart",
            ),
            ExampleNav(
                id="checkout-bypass",
                title="Multi-Step Checkout Bypass",
                difficulty="Hard",
                endpoint="a04_insecure_design.checkout_shipping",
            ),
        ],
```

Change it to:

```python
        examples=[
            ExampleNav(
                id="unlimited-coupon",
                title="Unlimited Coupon Reuse",
                group="Business Logic Abuse",
                difficulty="Easy",
                endpoint="a04_insecure_design.coupon_cart",
            ),
            ExampleNav(
                id="negative-quantity",
                title="Negative Quantity Price Manipulation",
                group="Business Logic Abuse",
                difficulty="Medium",
                endpoint="a04_insecure_design.quantity_cart",
            ),
            ExampleNav(
                id="checkout-bypass",
                title="Multi-Step Checkout Bypass",
                group="Workflow Bypass",
                difficulty="Hard",
                endpoint="a04_insecure_design.checkout_shipping",
            ),
        ],
```

In `tests/test_a04_overview.py`, leave `test_a04_registered_in_nav` unchanged and append:

```python


def test_a04_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a04 = next(c for c in CATEGORIES if c.id == "a04_insecure_design")
    grouped = a04.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Business Logic Abuse",
        "Workflow Bypass",
    ]
    assert [e.id for e in grouped[0][1]] == ["unlimited-coupon", "negative-quantity"]
    assert [e.id for e in grouped[1][1]] == ["checkout-bypass"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"
```

- [ ] **Step 9: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (111 existing + 3 new in test_nav.py + 4 new grouped-by-subtype tests across the 4 category test files = 118)

- [ ] **Step 10: Commit**

```bash
git add app/core/nav.py tests/test_nav.py \
  app/categories/a01_access_control/__init__.py tests/test_a01_overview.py \
  app/categories/a02_crypto_failures/__init__.py tests/test_a02_overview.py \
  app/categories/a03_injection/__init__.py tests/test_a03_overview.py \
  app/categories/a04_insecure_design/__init__.py tests/test_a04_overview.py
git commit -m "feat: group ExampleNav by vulnerability sub-type, retrofit A01-A04"
```

---

### Task 2: Render grouped examples in the sidebar and Overview page

**Files:**
- Modify: `app/core/templates/core/base.html`
- Modify: `app/core/templates/core/overview_base.html`
- Modify: `tests/test_a01_overview.py`
- Modify: `tests/test_a02_overview.py`
- Modify: `tests/test_a03_overview.py`
- Modify: `tests/test_a04_overview.py`

**Interfaces:**
- Consumes: `CategoryNav.grouped_examples()` from Task 1 (already merged into this branch), and the real `group=` values Task 1 set on A01–A04.
- Produces: nothing new consumed by later tasks — this is the last functional change in this plan.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_a01_overview.py`:

```python


def test_a01_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a01/")
    body = response.data.decode()
    assert "Insecure Direct Object References (IDOR)" in body
    assert "Missing Function-Level Access Control" in body
    assert "Mass Assignment" in body
```

Append to `tests/test_a02_overview.py`:

```python


def test_a02_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a02/")
    body = response.data.decode()
    assert "Weak Hashing" in body
    assert "Weak Encryption" in body
    assert "Predictable Tokens" in body
```

Append to `tests/test_a03_overview.py`:

```python


def test_a03_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a03/")
    body = response.data.decode()
    assert "SQL Injection" in body
    assert "Cross-Site Scripting (XSS)" in body
    assert "OS Command Injection" in body
```

Append to `tests/test_a04_overview.py`:

```python


def test_a04_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a04/")
    body = response.data.decode()
    assert "Business Logic Abuse" in body
    assert "Workflow Bypass" in body
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_a01_overview.py tests/test_a02_overview.py tests/test_a03_overview.py tests/test_a04_overview.py -v`
Expected: the 4 new `*_shows_vulnerability_subtype_group_headings` tests FAIL (group names aren't in the rendered HTML yet — the templates still do a flat loop).

- [ ] **Step 3: Update the sidebar in `base.html`**

In `app/core/templates/core/base.html`, the sidebar currently reads:

```html
      <nav class="col-12 col-md-3 col-lg-2 bg-light border-end py-3" id="sidebar">
        <div class="fw-bold mb-2">{{ active_category.short_id }}: {{ active_category.title }}</div>
        <ul class="nav flex-column">
          <li class="nav-item">
            <a class="nav-link {% if request.endpoint == active_category.overview_endpoint %}active fw-bold{% endif %}"
               href="{{ url_for(active_category.overview_endpoint) }}">Overview</a>
          </li>
          {% for example in active_category.examples %}
          {% if example.endpoint in registered_endpoints %}
          <li class="nav-item d-flex justify-content-between align-items-center">
            <a class="nav-link {% if request.endpoint == example.endpoint %}active fw-bold{% endif %}"
               href="{{ url_for(example.endpoint) }}">{{ example.title }}</a>
            <span class="badge {{ example.difficulty_badge_class() }}">{{ example.difficulty }}</span>
          </li>
          {% endif %}
          {% endfor %}
        </ul>
      </nav>
```

Change it to:

```html
      <nav class="col-12 col-md-3 col-lg-2 bg-light border-end py-3" id="sidebar">
        <div class="fw-bold mb-2">{{ active_category.short_id }}: {{ active_category.title }}</div>
        <ul class="nav flex-column">
          <li class="nav-item">
            <a class="nav-link {% if request.endpoint == active_category.overview_endpoint %}active fw-bold{% endif %}"
               href="{{ url_for(active_category.overview_endpoint) }}">Overview</a>
          </li>
          {% for group_name, group_examples in active_category.grouped_examples() %}
          {% if group_examples | selectattr("endpoint", "in", registered_endpoints) | list %}
          <li class="nav-item mt-2 mb-1 small text-uppercase text-muted fw-bold">{{ group_name }}</li>
          {% for example in group_examples %}
          {% if example.endpoint in registered_endpoints %}
          <li class="nav-item d-flex justify-content-between align-items-center">
            <a class="nav-link {% if request.endpoint == example.endpoint %}active fw-bold{% endif %}"
               href="{{ url_for(example.endpoint) }}">{{ example.title }}</a>
            <span class="badge {{ example.difficulty_badge_class() }}">{{ example.difficulty }}</span>
          </li>
          {% endif %}
          {% endfor %}
          {% endif %}
          {% endfor %}
        </ul>
      </nav>
```

- [ ] **Step 4: Update the Overview page's example list in `overview_base.html`**

In `app/core/templates/core/overview_base.html`, the "Examples in This Category" section currently reads:

```html
<section>
  <h2>Examples in This Category</h2>
  <ul class="list-group">
    {% for example in active_category.examples %}
    {% if example.endpoint in registered_endpoints %}
    <li class="list-group-item d-flex justify-content-between align-items-center">
      <a href="{{ url_for(example.endpoint) }}">{{ example.title }}</a>
      <span class="badge {{ example.difficulty_badge_class() }}">{{ example.difficulty }}</span>
    </li>
    {% endif %}
    {% endfor %}
  </ul>
</section>
```

Change it to:

```html
<section>
  <h2>Examples in This Category</h2>
  {% for group_name, group_examples in active_category.grouped_examples() %}
  {% if group_examples | selectattr("endpoint", "in", registered_endpoints) | list %}
  <h3 class="h6 mt-3">{{ group_name }}</h3>
  <ul class="list-group mb-2">
    {% for example in group_examples %}
    {% if example.endpoint in registered_endpoints %}
    <li class="list-group-item d-flex justify-content-between align-items-center">
      <a href="{{ url_for(example.endpoint) }}">{{ example.title }}</a>
      <span class="badge {{ example.difficulty_badge_class() }}">{{ example.difficulty }}</span>
    </li>
    {% endif %}
    {% endfor %}
  </ul>
  {% endif %}
  {% endfor %}
</section>
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pytest tests/test_a01_overview.py tests/test_a02_overview.py tests/test_a03_overview.py tests/test_a04_overview.py -v`
Expected: all PASS, including the 4 new tests from Step 1.

- [ ] **Step 6: Run the full suite**

Run: `pytest tests/ -v`
Expected: all PASS (118 + 4 = 122)

- [ ] **Step 7: Commit**

```bash
git add app/core/templates/core/base.html app/core/templates/core/overview_base.html \
  tests/test_a01_overview.py tests/test_a02_overview.py tests/test_a03_overview.py tests/test_a04_overview.py
git commit -m "feat: render sidebar and overview examples grouped by vulnerability sub-type"
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
Expected: all PASS (122 tests)

- [ ] **Step 2: Docker end-to-end verification**

```bash
docker compose up --build -d
```

Then, via curl against the live container (`http://127.0.0.1:5001`):

- `curl -s http://127.0.0.1:5001/a01/` contains `Insecure Direct Object References (IDOR)`, `Missing Function-Level Access Control`, and `Mass Assignment`.
- `curl -s http://127.0.0.1:5001/a03/` contains `SQL Injection`, `Cross-Site Scripting (XSS)`, and `OS Command Injection`, and does NOT contain a broken/duplicated group ordering (spot-check that `SQL Injection` appears before `Cross-Site Scripting (XSS)` in the raw HTML via `grep -o` with line numbers, or by checking the byte offset of each substring).
- `curl -s http://127.0.0.1:5001/a01/profile/2` (an actual example page, not just the overview) still renders with its sidebar showing the same grouped structure (the sidebar is shared via `base.html`, so this confirms grouping isn't overview-page-only).
- `curl -s http://127.0.0.1:5001/settings/reset -X POST` (or the existing `/force-reset` GET route) still works and the app still boots cleanly afterward — this change touches nav/template rendering only, not the DB, so this is a quick sanity check that nothing broke DB-adjacent behavior.

If you have a browser tool available in this environment, additionally visit `/a03/` and `/a04/` and visually confirm: the sidebar shows group headings in muted/uppercase small text distinct from example links, examples within each group are visibly ordered Easy → Hard by their difficulty badges, and dark mode (toggle via the 🌓 button) still renders the group headings legibly (they use `text-muted`, a semantic Bootstrap class that's already dark-mode-aware, not a new hardcoded color). If no browser tool is available, note that as a known gap in your report rather than skipping the curl-based checks above.

Tear down cleanly afterward:

```bash
docker compose down
```

- [ ] **Step 3: Commit**

No code changes are expected from this task. If the Docker/curl verification finds nothing to fix, there is nothing to commit — report DONE with the verification evidence in your report file rather than an empty commit.
