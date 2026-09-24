# Business Logic Errors & CORS Misconfiguration Additions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 8 new intentionally-vulnerable examples to the OWASP Top 10
Training Lab, sourced from PayloadsAllTheThings' "Business Logic Errors"
and "CORS Misconfiguration" reference pages, spanning A04 and A05
(78 → 86 examples total).

**Architecture:** Each example is a fully independent route (or small
route trio for the premium-access multi-step flow), following every
existing category's established one-clean-flaw-per-route convention — no
shared "correct baseline" flow. Every example uses Flask's built-in
`session` or plain response cookies for ephemeral per-browser state,
matching each category's existing precedent (A04's `coupon_cart`/
`quantity_cart`; A05's `cors_credentials`/`LOYALTY_TOKEN_COOKIE`). No new
SQLAlchemy models anywhere in this plan.

**Tech Stack:** Flask 3.0.3, Jinja2, pytest.

**Spec:** `docs/superpowers/specs/2026-09-24-owasp-lab-business-logic-cors-additions-design.md`

## Global Constraints

- The vulnerabilities ARE the deliverable — never soften, sanitize, or
  add defensive checks to any new vulnerable code path. Every new route
  must be genuinely, demonstrably exploitable exactly as described below:
  the free-shipping flag really has no eligibility check; the stock
  limit is really never validated; the discount stacking really applies
  every submitted code; the premium cookie really never gets cleared on
  cancel; the rounding really nets free money with no floor or rate
  limit; each CORS variant really has the described misconfiguration
  with no allowlist/auth fix.
- Hint content is plain Python strings rendered through Jinja's
  autoescaped `{{ hint }}` expression — write literal unescaped
  `<`/`>`/`&` characters in hint text, never `&lt;`/`&gt;`/`&amp;` HTML
  entities. 3-5 hints per example, vague-to-explicit, final hint
  near-full-walkthrough.
- The six static Jinja template blocks (`explanation`/`detect`/
  `exploitation`/`vulnerable_code`/`secure_code`) are NOT autoescaped —
  literal `<`/`>`/`&` shown as code samples inside them must be manually
  entity-encoded as `&lt;`/`&gt;`/`&amp;` (the opposite convention from
  hints). Real page markup (e.g. an actual `<iframe>` tag in a demo page
  that isn't inside one of those six blocks) is left as real, unescaped
  HTML.
- `tests/conftest.py` is off-limits — never modify it, for any reason, in
  any task.
- No new SQLAlchemy models or database columns anywhere in this plan —
  every example uses Flask `session` (server-side, per-browser) or a
  plain response cookie, matching each category's existing precedent.
- Every new example gets an `ExampleNav` entry with `hints=[...]`
  following the exact rubric already established: name the general
  technique first without the specific payload, narrow toward the
  specific mechanism, final hint gives the exact working reproduction
  steps.
- Match each category's existing code style exactly: both A04 and A05
  use plain `render_template()`/`redirect()`/`jsonify()` with no shared
  session-row abstraction (that pattern is A07-only, not used here).
- Reuse each category's existing constants/helpers where relevant: A04's
  `DEMO_PRODUCT_NAME`, `DEMO_PRODUCT_PRICE_CENTS`, `COUPON_CODE`,
  `COUPON_DISCOUNT_CENTS`, `_format_cents()`; A05's `LOYALTY_TOKEN_COOKIE`
  pattern (a dedicated cookie constant per example, following that
  naming style).

---

## Orchestration Note: Tasks 1-5 All Edit A04's `routes.py`/`__init__.py`

Tasks 1, 2, 3, 4, and 5 each append a new route (or route trio) to
`app/categories/a04_insecure_design/routes.py` and a new `ExampleNav`
entry to `app/categories/a04_insecure_design/__init__.py`'s
`examples=[...]` list. Each task's own instructions describe its
insertion point relative to an existing entry's `id` (e.g. "insert
immediately after `unlimited-coupon`"), not as a rigid full-block
find/replace against the file's *original* pre-project contents. This is
intentional and required: if these five tasks run in order (1 through 5
— the intended order), each one changes what immediately surrounds the
anchor entries the next task targets. **When implementing each of these
five tasks, always re-read the actual current contents of
`__init__.py`/`routes.py` first and locate the insertion point by the
named `id`, rather than pattern-matching an exact old/new code block
copied verbatim from an earlier state of the plan.**

The worked-out final result, after all five tasks land in order, is
(existing 4 examples shown alongside the 5 new ones, in final flat-list
order):

| # | id | Difficulty | Group |
|---|---|---|---|
| 1 | `unlimited-coupon` (existing) | Easy | Business Logic Abuse |
| 2 | `free-shipping-trusted-flag` (Task 1) | Easy | Business Logic Abuse |
| 3 | `negative-quantity` (existing) | Medium | Business Logic Abuse |
| 4 | `overselling-no-stock-check` (Task 2) | Medium | Business Logic Abuse |
| 5 | `discount-stacking` (Task 3) | Medium | Business Logic Abuse |
| 6 | `checkout-bypass` (existing) | Hard | Workflow Bypass |
| 7 | `host-header-reset-poisoning` (existing) | Hard | Password Reset Design Flaws |
| 8 | `premium-access-after-cancel` (Task 4) | Medium | Premium Access Design Flaws |
| 9 | `rounding-exploit` (Task 5) | Hard | Rounding & Arithmetic Errors |

Group display order (by first occurrence in the flat list): Business
Logic Abuse, Workflow Bypass, Password Reset Design Flaws, Premium
Access Design Flaws, Rounding & Arithmetic Errors. Every group's internal
difficulty order is Easy→Hard (the last three groups have exactly one
member each, trivially sorted). Task 9 gives the exact resulting
assertions this must produce.

---

## Task 1: A04 — Free Shipping via Client-Trusted Flag

**Files:**
- Modify: `app/categories/a04_insecure_design/routes.py`
- Modify: `app/categories/a04_insecure_design/__init__.py`
- Create: `app/categories/a04_insecure_design/templates/a04_insecure_design/shipping_select.html`
- Test: `tests/test_a04_free_shipping.py`

**Interfaces:**
- Consumes: `app.categories.a04_insecure_design.routes._format_cents()`
  (existing), `DEMO_PRODUCT_NAME`/`DEMO_PRODUCT_PRICE_CENTS` (existing
  constants).
- Produces: route `a04_insecure_design.shipping_select` (`GET/POST
  /a04/shipping-select`). Nothing later depends on this.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a04_free_shipping.py`:

```python
def test_shipping_select_page_renders(client):
    response = client.get("/a04/shipping-select")
    assert response.status_code == 200
    assert b"Free Shipping" in response.data


def test_default_paid_shipping_total_includes_shipping_cost(client):
    response = client.post("/a04/shipping-select", data={"shipping_cost_cents": "599"})
    assert response.status_code == 200
    assert b"$35.98" in response.data  # $29.99 product + $5.99 shipping


def test_client_supplied_zero_shipping_cost_is_trusted_under_threshold(client):
    # Cart total ($29.99) is well under the page's own stated $50 free-shipping
    # threshold, yet the server trusts a client-submitted shipping_cost_cents=0
    # with no server-side check of that threshold at all.
    response = client.post("/a04/shipping-select", data={"shipping_cost_cents": "0"})
    assert response.status_code == 200
    assert b"$29.99" in response.data
    assert b"Free shipping applied" in response.data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_a04_free_shipping.py -v`
Expected: FAIL — route doesn't exist yet (404s).

- [ ] **Step 3: Add the new route**

Modify `app/categories/a04_insecure_design/routes.py`. Append this route
at the end of the file (after `forgot_password`):

```python


@a04_bp.route("/shipping-select", methods=["GET", "POST"])
def shipping_select():
    shipping_cost_cents = 599
    if request.method == "POST":
        # VULNERABLE: the page's own copy says "free shipping on orders
        # over $50" but the server trusts whatever shipping_cost_cents
        # value the client submits -- it never checks the real order
        # total ($29.99, well under $50) against that threshold before
        # using the submitted cost.
        try:
            shipping_cost_cents = int(request.form.get("shipping_cost_cents", "599"))
        except (ValueError, OverflowError):
            shipping_cost_cents = 599
    total_cents = DEMO_PRODUCT_PRICE_CENTS + shipping_cost_cents
    return render_template(
        "a04_insecure_design/shipping_select.html",
        product_name=DEMO_PRODUCT_NAME,
        product_price_display=_format_cents(DEMO_PRODUCT_PRICE_CENTS),
        shipping_display=_format_cents(shipping_cost_cents),
        total_display=_format_cents(total_cents),
        free_shipping_applied=shipping_cost_cents == 0,
    )
```

- [ ] **Step 4: Create `shipping_select.html`**

Create `app/categories/a04_insecure_design/templates/a04_insecure_design/shipping_select.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Free Shipping via Client-Trusted Flag" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A04{% endblock %}

{% block explanation %}
<p>
  This checkout step says "Free shipping is only available on orders
  over $50" — but the shipping cost that actually gets charged comes
  from a hidden form field the client submits, and the server uses that
  value directly. Nothing on the server ever checks the real order total
  ($29.99, well under $50) against the $50 threshold before honoring a
  submitted cost of $0.
</p>
{% endblock %}

{% block detect %}
<p>
  View this page's HTML source and find the hidden
  <code>shipping_cost_cents</code> field the form submits alongside your
  selection. A server that actually enforced the "$50 minimum" rule would
  compute the shipping cost itself from the real order total, not accept
  a client-supplied number for it.
</p>
{% endblock %}

{% block exploitation %}
<p>
  Submit the form with the hidden field edited to <code>0</code>, even
  though the cart total is nowhere near $50:
</p>
<pre><code class="language-bash">curl -X POST http://127.0.0.1:5001/a04/shipping-select -d "shipping_cost_cents=0"</code></pre>
<p>
  The confirmed total reflects free shipping anyway — the "over $50"
  rule exists only in the page's displayed copy, never in the code that
  processes the submission.
</p>
{% endblock %}

{% block vulnerable_code %}shipping_cost_cents = int(request.form.get("shipping_cost_cents", "599"))
# VULNERABLE: no check that the real order total actually meets the
# free-shipping threshold before honoring a submitted cost of 0
total_cents = DEMO_PRODUCT_PRICE_CENTS + shipping_cost_cents
{% endblock %}

{% block secure_code %}FREE_SHIPPING_THRESHOLD_CENTS = 5000
STANDARD_SHIPPING_CENTS = 599

# Shipping cost is computed server-side from the real order total --
# never trusted from the client
shipping_cost_cents = 0 if DEMO_PRODUCT_PRICE_CENTS >= FREE_SHIPPING_THRESHOLD_CENTS else STANDARD_SHIPPING_CENTS
total_cents = DEMO_PRODUCT_PRICE_CENTS + shipping_cost_cents
{% endblock %}

{% block live_example %}
<div class="card mb-3">
  <div class="card-body">
    <h5 class="card-title">{{ product_name }}</h5>
    <p class="card-text">Price: {{ product_price_display }}</p>
    <p class="card-text text-muted small">Free shipping is only available on orders over $50.</p>
    <p class="card-text">Shipping: {{ shipping_display }}</p>
    <p class="card-text"><strong>Total: {{ total_display }}</strong></p>
    {% if free_shipping_applied %}
    <p class="text-success">Free shipping applied.</p>
    {% endif %}
  </div>
</div>
<form method="post" class="d-flex gap-2">
  <input type="hidden" name="shipping_cost_cents" value="{{ '0' if free_shipping_applied else '599' }}">
  <button type="submit" class="btn btn-primary">
    {{ "Select Standard Shipping ($5.99)" if free_shipping_applied else "Select Free Shipping" }}
  </button>
</form>
{% endblock %}
```

- [ ] **Step 5: Add the `ExampleNav` entry**

Modify `app/categories/a04_insecure_design/__init__.py`. Find the
`unlimited-coupon` entry:

```python
            ExampleNav(
                id="unlimited-coupon",
                title="Unlimited Coupon Reuse",
                group="Business Logic Abuse",
                difficulty="Easy",
                endpoint="a04_insecure_design.coupon_cart",
                hints=[
                    "This coupon form doesn't track whether you already used the code. What happens if you submit the same valid code more than once?",
                    "Every successful submission adds another discount to your session — there's no check for 'already applied' and no maximum number of uses.",
                    "Submit the coupon code WELCOME10 in the form repeatedly (refresh and resubmit, or script multiple POSTs to /a04/coupon-cart with code=WELCOME10) — the discount keeps stacking, eventually pushing the total to $0 or below.",
                ],
            ),
            ExampleNav(
                id="negative-quantity",
```

Insert immediately after it (before `negative-quantity`):

```python
            ExampleNav(
                id="unlimited-coupon",
                title="Unlimited Coupon Reuse",
                group="Business Logic Abuse",
                difficulty="Easy",
                endpoint="a04_insecure_design.coupon_cart",
                hints=[
                    "This coupon form doesn't track whether you already used the code. What happens if you submit the same valid code more than once?",
                    "Every successful submission adds another discount to your session — there's no check for 'already applied' and no maximum number of uses.",
                    "Submit the coupon code WELCOME10 in the form repeatedly (refresh and resubmit, or script multiple POSTs to /a04/coupon-cart with code=WELCOME10) — the discount keeps stacking, eventually pushing the total to $0 or below.",
                ],
            ),
            ExampleNav(
                id="free-shipping-trusted-flag",
                title="Free Shipping via Client-Trusted Flag",
                group="Business Logic Abuse",
                difficulty="Easy",
                endpoint="a04_insecure_design.shipping_select",
                hints=[
                    "This checkout step says free shipping only applies over $50. Look at the form's HTML source — where does the actual shipping cost the server charges come from?",
                    "The shipping cost is a hidden form field the client submits directly. The server never checks the real order total against the $50 threshold before using whatever cost value you send.",
                    "Submit the form with the hidden shipping_cost_cents field edited to 0, even though the cart total is nowhere near $50 — e.g. curl -X POST http://127.0.0.1:5000/a04/shipping-select -d 'shipping_cost_cents=0'.",
                    "The confirmed total reflects free shipping anyway — the 'over $50' rule exists only in the page's displayed copy, never enforced in the code that processes the submission.",
                ],
            ),
            ExampleNav(
                id="negative-quantity",
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a04_free_shipping.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass. Baseline before this plan was 502. This task's new
tests aren't yet reflected in cross-cutting hint/overview/score-total
test files (that reconciliation happens incrementally as each task
discovers it needs it, same pattern as the prior round) — if
`test_a04_hints.py`/`test_a04_overview.py`/`test_all_examples_have_hints.py`/
`test_hints.py` fail because they now see 5 A04 examples instead of 4,
update them the same way every task in the prior round did: read the
actual current assertion, update the count/list/score to match reality.
Expected additions: `test_a04_hints.py`'s count → 5; `test_all_examples_have_hints.py`'s
total → 79; `test_hints.py`'s max score → 1620 (+10 for this one Easy
example). New total: 505 (502 + 3 new).

- [ ] **Step 8: Commit**

```bash
git add app/categories/a04_insecure_design tests/test_a04_free_shipping.py tests/test_a04_hints.py tests/test_a04_overview.py tests/test_all_examples_have_hints.py tests/test_hints.py
git commit -m "feat(a04): add free-shipping-via-client-trusted-flag example

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 2: A04 — Overselling: No Stock-Limit Check

**Files:**
- Modify: `app/categories/a04_insecure_design/routes.py`
- Modify: `app/categories/a04_insecure_design/__init__.py`
- Create: `app/categories/a04_insecure_design/templates/a04_insecure_design/limited_stock_cart.html`
- Test: `tests/test_a04_overselling.py`

**Interfaces:**
- Consumes: `_format_cents()`, `DEMO_PRODUCT_NAME`,
  `DEMO_PRODUCT_PRICE_CENTS` (existing).
- Produces: route `a04_insecure_design.limited_stock_cart` (`GET/POST
  /a04/limited-stock-cart`). Nothing later depends on this.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a04_overselling.py`:

```python
def test_limited_stock_cart_page_renders(client):
    response = client.get("/a04/limited-stock-cart")
    assert response.status_code == 200
    assert b"Only 3 left in stock" in response.data


def test_ordering_within_stock_succeeds(client):
    response = client.post("/a04/limited-stock-cart", data={"quantity": "2"})
    assert response.status_code == 200
    assert b"Order confirmed: 2" in response.data


def test_ordering_far_more_than_stock_is_never_rejected(client):
    # VULNERABLE: the page advertises only 3 in stock, but the handler
    # never checks the submitted quantity against that count at all.
    response = client.post("/a04/limited-stock-cart", data={"quantity": "500"})
    assert response.status_code == 200
    assert b"Order confirmed: 500" in response.data
    assert b"$14,995.00" in response.data  # 500 * $29.99
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_a04_overselling.py -v`
Expected: FAIL — route doesn't exist yet (404s).

- [ ] **Step 3: Add the new route**

Modify `app/categories/a04_insecure_design/routes.py`. Add this constant
near the top of the file (alongside `COUPON_CODE`):

```python
STOCK_COUNT = 3
```

Append this route at the end of the file:

```python


@a04_bp.route("/limited-stock-cart", methods=["GET", "POST"])
def limited_stock_cart():
    ordered_quantity = None
    total_cents = None
    if request.method == "POST":
        try:
            quantity = int(request.form.get("quantity", "1"))
        except (ValueError, OverflowError):
            quantity = 1
        # VULNERABLE: the page displays a fixed "Only 3 left!" stock
        # count, but this handler never validates the submitted quantity
        # against STOCK_COUNT (or against any real inventory at all) --
        # any positive quantity is accepted and priced normally.
        ordered_quantity = quantity
        total_cents = DEMO_PRODUCT_PRICE_CENTS * quantity
    return render_template(
        "a04_insecure_design/limited_stock_cart.html",
        product_name=DEMO_PRODUCT_NAME,
        product_price_display=_format_cents(DEMO_PRODUCT_PRICE_CENTS),
        stock_count=STOCK_COUNT,
        ordered_quantity=ordered_quantity,
        total_display=_format_cents(total_cents) if total_cents is not None else None,
    )
```

- [ ] **Step 4: Create `limited_stock_cart.html`**

Create `app/categories/a04_insecure_design/templates/a04_insecure_design/limited_stock_cart.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Overselling — No Stock-Limit Check" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A04{% endblock %}

{% block explanation %}
<p>
  This product page shows "Only {{ stock_count }} left in stock!" — but
  the order-submission handler never validates the submitted quantity
  against that count, or against any real inventory tracking at all. The
  "in stock" number shown to customers is a display-only decoration, not
  an enforced business rule.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit a quantity larger than the displayed stock count — e.g. 10 units
  of an item advertised as having only {{ stock_count }} left. If the
  order confirms without any rejection or warning, the stock count is
  never actually checked server-side.
</p>
{% endblock %}

{% block exploitation %}
<pre><code class="language-bash">curl -X POST http://127.0.0.1:5001/a04/limited-stock-cart -d "quantity=500"</code></pre>
<p>
  The order confirms for 500 units of an item the page itself says only
  {{ stock_count }} of exist, with no rejection, no warning, and no
  capped total. In a real system, this means shipping promises the
  business cannot keep — or, in a flash-sale scenario, a race to buy out
  limited inventory at a price the seller never intended to honor at that
  volume.
</p>
{% endblock %}

{% block vulnerable_code %}STOCK_COUNT = 3

quantity = int(request.form.get("quantity", "1"))
# VULNERABLE: quantity is never compared against STOCK_COUNT (or any
# real inventory) before confirming the order
total_cents = DEMO_PRODUCT_PRICE_CENTS * quantity
{% endblock %}

{% block secure_code %}STOCK_COUNT = 3

quantity = int(request.form.get("quantity", "1"))
if quantity &gt; STOCK_COUNT:
    abort(409)  # Conflict -- not enough stock to fulfill this order
total_cents = DEMO_PRODUCT_PRICE_CENTS * quantity
{% endblock %}

{% block live_example %}
<div class="card mb-3">
  <div class="card-body">
    <h5 class="card-title">{{ product_name }}</h5>
    <p class="card-text">Price: {{ product_price_display }}</p>
    <p class="card-text text-danger">Only {{ stock_count }} left in stock!</p>
  </div>
</div>
<form method="post" class="d-flex gap-2 mb-2">
  <input type="number" class="form-control" name="quantity" value="1">
  <button type="submit" class="btn btn-primary">Order</button>
</form>
{% if ordered_quantity is not none %}
<div class="alert alert-success">
  Order confirmed: {{ ordered_quantity }} units. Total: {{ total_display }}
</div>
{% endif %}
{% endblock %}
```

- [ ] **Step 5: Add the `ExampleNav` entry**

Modify `app/categories/a04_insecure_design/__init__.py`. Find the
`negative-quantity` entry (Task 1 already inserted `free-shipping-trusted-flag`
before it — re-read the actual current file to confirm, then find):

```python
            ExampleNav(
                id="negative-quantity",
                title="Negative Quantity Price Manipulation",
                group="Business Logic Abuse",
                difficulty="Medium",
                endpoint="a04_insecure_design.quantity_cart",
                hints=[
                    "This cart multiplies price by quantity with no bounds check. What normally-invalid quantity might the server accept anyway?",
                    "The server parses your submitted quantity as a plain integer and multiplies it directly into the total — negative numbers pass the int() conversion just fine.",
                    "Submit a negative quantity, e.g. quantity=-5, to /a04/quantity-cart — the total price goes negative, which a real checkout might interpret as money owed TO the customer.",
                ],
            ),
            ExampleNav(
                id="checkout-bypass",
```

Insert immediately after `negative-quantity` (before `checkout-bypass`):

```python
            ExampleNav(
                id="negative-quantity",
                title="Negative Quantity Price Manipulation",
                group="Business Logic Abuse",
                difficulty="Medium",
                endpoint="a04_insecure_design.quantity_cart",
                hints=[
                    "This cart multiplies price by quantity with no bounds check. What normally-invalid quantity might the server accept anyway?",
                    "The server parses your submitted quantity as a plain integer and multiplies it directly into the total — negative numbers pass the int() conversion just fine.",
                    "Submit a negative quantity, e.g. quantity=-5, to /a04/quantity-cart — the total price goes negative, which a real checkout might interpret as money owed TO the customer.",
                ],
            ),
            ExampleNav(
                id="overselling-no-stock-check",
                title="Overselling — No Stock-Limit Check",
                group="Business Logic Abuse",
                difficulty="Medium",
                endpoint="a04_insecure_design.limited_stock_cart",
                hints=[
                    "This page advertises a very limited stock count. Submit an order for far more units than that — does the server reject it?",
                    "The order handler never compares your submitted quantity against the displayed stock count, or against any real inventory at all — it's a display-only decoration, not an enforced rule.",
                    "Submit quantity=500 to /a04/limited-stock-cart — the order confirms for 500 units of an item the page itself says only 3 of exist, with no rejection or capped total.",
                ],
            ),
            ExampleNav(
                id="checkout-bypass",
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a04_overselling.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass, updating the same cross-cutting files again
(`test_a04_hints.py` → 6, `test_all_examples_have_hints.py` → 80,
`test_hints.py` → 1640 [+20 for this Medium example]). New total: 508
(505 + 3 new).

- [ ] **Step 8: Commit**

```bash
git add app/categories/a04_insecure_design tests/test_a04_overselling.py tests/test_a04_hints.py tests/test_a04_overview.py tests/test_all_examples_have_hints.py tests/test_hints.py
git commit -m "feat(a04): add overselling-no-stock-limit-check example

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 3: A04 — Discount Code Stacking via Parameter Pollution

**Files:**
- Modify: `app/categories/a04_insecure_design/routes.py`
- Modify: `app/categories/a04_insecure_design/__init__.py`
- Create: `app/categories/a04_insecure_design/templates/a04_insecure_design/coupon_stack.html`
- Test: `tests/test_a04_discount_stacking.py`

**Interfaces:**
- Consumes: `_format_cents()`, `DEMO_PRODUCT_NAME`,
  `DEMO_PRODUCT_PRICE_CENTS`, `COUPON_CODE`, `COUPON_DISCOUNT_CENTS`
  (existing).
- Produces: route `a04_insecure_design.coupon_stack` (`GET/POST
  /a04/coupon-stack`). New constants `SAVE20_CODE`,
  `SAVE20_DISCOUNT_CENTS`. Nothing later depends on these.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a04_discount_stacking.py`:

```python
def test_coupon_stack_page_renders(client):
    response = client.get("/a04/coupon-stack")
    assert response.status_code == 200
    assert b"Discount Code Stacking" in response.data


def test_single_code_applies_normally(client):
    response = client.post("/a04/coupon-stack", data={"code": "WELCOME10"})
    assert response.status_code == 200
    assert b"$24.99" in response.data  # $29.99 - $5.00


def test_submitting_both_codes_as_duplicate_form_fields_stacks_both(client):
    # HTTP parameter pollution: two "code" values in one POST body.
    response = client.post(
        "/a04/coupon-stack",
        data="code=WELCOME10&code=SAVE20",
        content_type="application/x-www-form-urlencoded",
    )
    assert response.status_code == 200
    assert b"$14.99" in response.data  # $29.99 - $5.00 - $10.00, both discounts stacked
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_a04_discount_stacking.py -v`
Expected: FAIL — route doesn't exist yet (404s).

- [ ] **Step 3: Add the new route**

Modify `app/categories/a04_insecure_design/routes.py`. Add these
constants near `COUPON_CODE`/`COUPON_DISCOUNT_CENTS`:

```python
SAVE20_CODE = "SAVE20"
SAVE20_DISCOUNT_CENTS = 1000
```

Append this route at the end of the file:

```python


@a04_bp.route("/coupon-stack", methods=["GET", "POST"])
def coupon_stack():
    applied_codes = []
    discount_cents = 0
    error = None
    if request.method == "POST":
        # VULNERABLE: the form has a single "code" input, implying one
        # code per order -- but this reads EVERY submitted "code" value
        # (request.form.getlist, not request.form.get) and applies a
        # discount for each one present, instead of validating exactly
        # one. Submitting both codes as duplicate form fields in one
        # request (HTTP parameter pollution) stacks both discounts.
        submitted_codes = request.form.getlist("code")
        if not submitted_codes:
            error = "Enter a coupon code."
        for submitted_code in submitted_codes:
            submitted_code = submitted_code.strip()
            if submitted_code == COUPON_CODE:
                applied_codes.append(COUPON_CODE)
                discount_cents += COUPON_DISCOUNT_CENTS
            elif submitted_code == SAVE20_CODE:
                applied_codes.append(SAVE20_CODE)
                discount_cents += SAVE20_DISCOUNT_CENTS
        if submitted_codes and not applied_codes:
            error = "Invalid coupon code."
    total_cents = max(0, DEMO_PRODUCT_PRICE_CENTS - discount_cents)
    return render_template(
        "a04_insecure_design/coupon_stack.html",
        product_name=DEMO_PRODUCT_NAME,
        product_price_display=_format_cents(DEMO_PRODUCT_PRICE_CENTS),
        applied_codes=applied_codes,
        discount_display=_format_cents(discount_cents),
        total_display=_format_cents(total_cents),
        error=error,
    )
```

- [ ] **Step 4: Create `coupon_stack.html`**

Create `app/categories/a04_insecure_design/templates/a04_insecure_design/coupon_stack.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Discount Code Stacking via Parameter Pollution" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A04{% endblock %}

{% block explanation %}
<p>
  Two valid, independent coupon codes exist: <code>WELCOME10</code>
  ($5.00 off) and <code>SAVE20</code> ($10.00 off). The form has a single
  "code" input, implying only one code applies per order — but the
  server reads <em>every</em> submitted <code>code</code> value and
  applies a discount for each one present, instead of validating exactly
  one. This is different from this category's existing "unlimited coupon
  reuse" example, which is about resubmitting the <em>same</em> code
  repeatedly over time — this one is about submitting <em>multiple
  distinct</em> codes in a single request.
</p>
{% endblock %}

{% block detect %}
<p>
  Submit the form with the code field duplicated — most HTTP clients let
  you send the same parameter name twice in one request body. If both
  discounts apply at once, the server is reading a list of values instead
  of validating a single code.
</p>
{% endblock %}

{% block exploitation %}
<pre><code class="language-bash">curl -X POST http://127.0.0.1:5001/a04/coupon-stack -d "code=WELCOME10&amp;code=SAVE20"</code></pre>
<p>
  Both the $5.00 and $10.00 discounts apply in one single order — a
  combination the storefront never intends to offer, since each code is
  meant to be used on its own.
</p>
{% endblock %}

{% block vulnerable_code %}submitted_codes = request.form.getlist("code")
for submitted_code in submitted_codes:
    # VULNERABLE: applies a discount for EVERY submitted code, not just one
    if submitted_code == COUPON_CODE:
        discount_cents += COUPON_DISCOUNT_CENTS
    elif submitted_code == SAVE20_CODE:
        discount_cents += SAVE20_DISCOUNT_CENTS
{% endblock %}

{% block secure_code %}submitted_code = request.form.get("code", "").strip()  # .get(), not .getlist()
if submitted_code == COUPON_CODE:
    discount_cents = COUPON_DISCOUNT_CENTS
elif submitted_code == SAVE20_CODE:
    discount_cents = SAVE20_DISCOUNT_CENTS
# only ever one discount applied, no matter how many "code" fields are submitted
{% endblock %}

{% block live_example %}
<div class="card mb-3">
  <div class="card-body">
    <h5 class="card-title">{{ product_name }}</h5>
    <p class="card-text">Price: {{ product_price_display }}</p>
    {% if applied_codes %}
    <p class="card-text">Applied codes: {{ applied_codes|join(', ') }}</p>
    <p class="card-text">Discount: {{ discount_display }}</p>
    {% endif %}
    <p class="card-text"><strong>Total: {{ total_display }}</strong></p>
  </div>
</div>
{% if error %}<p class="text-danger">{{ error }}</p>{% endif %}
<form method="post" class="d-flex gap-2">
  <input type="text" class="form-control" name="code" placeholder="WELCOME10 or SAVE20">
  <button type="submit" class="btn btn-primary">Apply code</button>
</form>
{% endblock %}
```

- [ ] **Step 5: Add the `ExampleNav` entry**

Modify `app/categories/a04_insecure_design/__init__.py`. Re-read the
actual current file (Tasks 1-2 already inserted entries before
`checkout-bypass`) and find the current `overselling-no-stock-check`
entry, followed by `checkout-bypass`:

```python
            ExampleNav(
                id="overselling-no-stock-check",
                title="Overselling — No Stock-Limit Check",
                group="Business Logic Abuse",
                difficulty="Medium",
                endpoint="a04_insecure_design.limited_stock_cart",
                hints=[
                    "This page advertises a very limited stock count. Submit an order for far more units than that — does the server reject it?",
                    "The order handler never compares your submitted quantity against the displayed stock count, or against any real inventory at all — it's a display-only decoration, not an enforced rule.",
                    "Submit quantity=500 to /a04/limited-stock-cart — the order confirms for 500 units of an item the page itself says only 3 of exist, with no rejection or capped total.",
                ],
            ),
            ExampleNav(
                id="checkout-bypass",
```

Insert immediately after `overselling-no-stock-check` (before
`checkout-bypass`):

```python
            ExampleNav(
                id="overselling-no-stock-check",
                title="Overselling — No Stock-Limit Check",
                group="Business Logic Abuse",
                difficulty="Medium",
                endpoint="a04_insecure_design.limited_stock_cart",
                hints=[
                    "This page advertises a very limited stock count. Submit an order for far more units than that — does the server reject it?",
                    "The order handler never compares your submitted quantity against the displayed stock count, or against any real inventory at all — it's a display-only decoration, not an enforced rule.",
                    "Submit quantity=500 to /a04/limited-stock-cart — the order confirms for 500 units of an item the page itself says only 3 of exist, with no rejection or capped total.",
                ],
            ),
            ExampleNav(
                id="discount-stacking",
                title="Discount Code Stacking via Parameter Pollution",
                group="Business Logic Abuse",
                difficulty="Medium",
                endpoint="a04_insecure_design.coupon_stack",
                hints=[
                    "This form has a single coupon-code field, implying one code per order. What happens if you submit the SAME field name twice in one request, with two different valid codes?",
                    "The server reads every submitted 'code' value (not just the first) and applies a discount for each one present — it never validates that exactly one code was submitted.",
                    "Send both valid codes as duplicate form fields in one POST: curl -X POST http://127.0.0.1:5000/a04/coupon-stack -d 'code=WELCOME10&code=SAVE20' — both the $5.00 and $10.00 discounts apply at once, a combination the storefront never intends to offer.",
                ],
            ),
            ExampleNav(
                id="checkout-bypass",
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a04_discount_stacking.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass, updating cross-cutting files again
(`test_a04_hints.py` → 7, `test_all_examples_have_hints.py` → 81,
`test_hints.py` → 1660 [+20]). New total: 511 (508 + 3 new).

- [ ] **Step 8: Commit**

```bash
git add app/categories/a04_insecure_design tests/test_a04_discount_stacking.py tests/test_a04_hints.py tests/test_a04_overview.py tests/test_all_examples_have_hints.py tests/test_hints.py
git commit -m "feat(a04): add discount-code-stacking-via-parameter-pollution example

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 4: A04 — Premium Access Persists After Cancellation

**Files:**
- Modify: `app/categories/a04_insecure_design/routes.py`
- Modify: `app/categories/a04_insecure_design/__init__.py`
- Create: `app/categories/a04_insecure_design/templates/a04_insecure_design/premium_content.html`
- Test: `tests/test_a04_premium_access.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: routes `a04_insecure_design.premium_subscribe` (`POST
  /a04/premium/subscribe`), `a04_insecure_design.premium_cancel` (`POST
  /a04/premium/cancel`), `a04_insecure_design.premium_content` (`GET
  /a04/premium/content`). New cookie constant `PREMIUM_TIER_COOKIE`.
  Nothing later depends on these.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a04_premium_access.py`:

```python
def test_premium_content_locked_before_subscribing(client):
    response = client.get("/a04/premium/content")
    assert response.status_code == 200
    assert b"Subscribe to see premium content" in response.data


def test_subscribing_unlocks_premium_content(client):
    client.post("/a04/premium/subscribe")
    response = client.get("/a04/premium/content")
    assert response.status_code == 200
    assert b"Premium content unlocked" in response.data


def test_cancelling_does_not_clear_the_premium_cookie(client):
    client.post("/a04/premium/subscribe")
    cancel_response = client.post("/a04/premium/cancel", follow_redirects=True)
    assert b"cancelled" in cancel_response.data.lower()

    # VULNERABLE: the premium-content route checks only the cookie set at
    # subscribe time, which cancellation never clears or invalidates.
    content_response = client.get("/a04/premium/content")
    assert content_response.status_code == 200
    assert b"Premium content unlocked" in content_response.data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_a04_premium_access.py -v`
Expected: FAIL — routes don't exist yet (404s).

- [ ] **Step 3: Add the three new routes**

Modify `app/categories/a04_insecure_design/routes.py`. Add this constant
near the other top-of-file constants:

```python
PREMIUM_TIER_COOKIE = "a04_premium_tier"
```

Append these three routes at the end of the file:

```python


@a04_bp.route("/premium/subscribe", methods=["POST"])
def premium_subscribe():
    resp = redirect(url_for("a04_insecure_design.premium_content"))
    # VULNERABLE: a raw, unsigned, client-visible cookie is the ONLY
    # record of an active subscription -- there's no server-side
    # subscription record anywhere.
    resp.set_cookie(PREMIUM_TIER_COOKIE, "gold")
    session["a04_premium_cancelled"] = False
    return resp


@a04_bp.route("/premium/cancel", methods=["POST"])
def premium_cancel():
    # VULNERABLE: records the cancellation in the session, but never
    # clears or expires the PREMIUM_TIER_COOKIE that actually gates
    # access -- the two pieces of state are never reconciled.
    session["a04_premium_cancelled"] = True
    return redirect(url_for("a04_insecure_design.premium_content"))


@a04_bp.route("/premium/content")
def premium_content():
    # VULNERABLE: access is gated purely by the presence of the client
    # cookie -- the cancellation flag recorded in the session is never
    # even read here.
    has_access = request.cookies.get(PREMIUM_TIER_COOKIE) == "gold"
    cancelled = session.get("a04_premium_cancelled", False)
    return render_template(
        "a04_insecure_design/premium_content.html", has_access=has_access, cancelled=cancelled
    )
```

- [ ] **Step 4: Create `premium_content.html`**

Create `app/categories/a04_insecure_design/templates/a04_insecure_design/premium_content.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Premium Access Persists After Cancellation" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A04{% endblock %}

{% block explanation %}
<p>
  Subscribing sets a raw, unsigned cookie (<code>a04_premium_tier=gold</code>)
  with no server-side subscription record backing it at all. Cancelling
  records the cancellation in your session — but never clears, expires,
  or otherwise invalidates that same cookie. The premium-content page
  checks only the cookie, never the cancellation state, so the two pieces
  of state are never reconciled.
</p>
{% endblock %}

{% block detect %}
<p>
  Subscribe, then cancel, then revisit the premium content page. A
  correctly implemented flow would deny access immediately after
  cancellation — check whether it actually does.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>POST to <code>/a04/premium/subscribe</code> — this sets the
      <code>a04_premium_tier</code> cookie.</li>
  <li>POST to <code>/a04/premium/cancel</code> — the page confirms
      cancellation.</li>
  <li>GET <code>/a04/premium/content</code> — the premium content still
      renders, because the cookie that actually gates access was never
      cleared by cancellation.</li>
</ol>
<p>
  This directly models a real class of bug: trusting unsigned
  client-side state as the sole proof of an active subscription, with
  the cancellation flow never touching that same piece of state. In a
  real system, this means a customer keeps paid-tier access indefinitely
  after cancelling, simply by never clearing that one cookie.
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/premium/cancel", methods=["POST"])
def premium_cancel():
    # VULNERABLE: never clears the cookie that /premium/content checks
    session["premium_cancelled"] = True
    return redirect(url_for("premium_content"))

@app.route("/premium/content")
def premium_content():
    # VULNERABLE: only checks the cookie, never the cancellation state
    has_access = request.cookies.get("premium_tier") == "gold"
    ...
{% endblock %}

{% block secure_code %}@app.route("/premium/cancel", methods=["POST"])
def premium_cancel():
    resp = redirect(url_for("premium_content"))
    resp.delete_cookie("premium_tier")  # actually revoke access
    session["premium_cancelled"] = True
    return resp

@app.route("/premium/content")
def premium_content():
    # Checks real, authoritative subscription state -- never a
    # client-controllable cookie alone
    has_access = get_active_subscription(current_user) is not None
    ...
{% endblock %}

{% block live_example %}
<form method="post" action="{{ url_for('a04_insecure_design.premium_subscribe') }}" class="d-inline">
  <button type="submit" class="btn btn-primary">Subscribe</button>
</form>
<form method="post" action="{{ url_for('a04_insecure_design.premium_cancel') }}" class="d-inline">
  <button type="submit" class="btn btn-outline-secondary">Cancel subscription</button>
</form>
<hr>
{% if cancelled %}
<p class="text-muted">Your subscription is cancelled.</p>
{% endif %}
{% if has_access %}
<div class="alert alert-success">Premium content unlocked: exclusive members-only article.</div>
{% else %}
<div class="alert alert-secondary">Subscribe to see premium content.</div>
{% endif %}
{% endblock %}
```

- [ ] **Step 5: Add the `ExampleNav` entry**

Modify `app/categories/a04_insecure_design/__init__.py`. Re-read the
actual current file (Tasks 1-3 already inserted three entries into
"Business Logic Abuse") and find the closing of the `examples=[...]`
list — the final existing entry `host-header-reset-poisoning`, followed
by `],`:

```python
            ExampleNav(
                id="host-header-reset-poisoning",
                title="Password Reset Poisoning via Host Header",
                group="Password Reset Design Flaws",
                difficulty="Hard",
                endpoint="a04_insecure_design.forgot_password",
                hints=[
                    "This 'forgot password' form generates a reset link for you (since this lab doesn't send real email). Look closely at the domain in the generated link — where does the server get it from?",
                    "The reset link's domain comes directly from the request's Host header (or X-Forwarded-Host if present) rather than a fixed, server-configured value.",
                    "Send the request with a forged Host header — e.g. curl -X POST http://127.0.0.1:5000/a04/forgot-password -H 'Host: attacker.evil.test' -d 'email=victim@owasp-lab.local' — the generated reset link now points to attacker.evil.test instead of the real site.",
                    "In a real deployment behind a reverse proxy, X-Forwarded-Host is often trusted the same way and is even easier to forge — try -H 'X-Forwarded-Host: attacker.evil.test' too. If a victim's real password-reset email had been built this way and they clicked the poisoned link, their reset token would be sent straight to the attacker's server instead of the real one.",
                ],
            ),
        ],
    )
)
```

Replace with (appending the new "Premium Access Design Flaws" group as a
new group at the end of the list):

```python
            ExampleNav(
                id="host-header-reset-poisoning",
                title="Password Reset Poisoning via Host Header",
                group="Password Reset Design Flaws",
                difficulty="Hard",
                endpoint="a04_insecure_design.forgot_password",
                hints=[
                    "This 'forgot password' form generates a reset link for you (since this lab doesn't send real email). Look closely at the domain in the generated link — where does the server get it from?",
                    "The reset link's domain comes directly from the request's Host header (or X-Forwarded-Host if present) rather than a fixed, server-configured value.",
                    "Send the request with a forged Host header — e.g. curl -X POST http://127.0.0.1:5000/a04/forgot-password -H 'Host: attacker.evil.test' -d 'email=victim@owasp-lab.local' — the generated reset link now points to attacker.evil.test instead of the real site.",
                    "In a real deployment behind a reverse proxy, X-Forwarded-Host is often trusted the same way and is even easier to forge — try -H 'X-Forwarded-Host: attacker.evil.test' too. If a victim's real password-reset email had been built this way and they clicked the poisoned link, their reset token would be sent straight to the attacker's server instead of the real one.",
                ],
            ),
            ExampleNav(
                id="premium-access-after-cancel",
                title="Premium Access Persists After Cancellation",
                group="Premium Access Design Flaws",
                difficulty="Medium",
                endpoint="a04_insecure_design.premium_content",
                hints=[
                    "Subscribe, then cancel, then revisit the premium content page. Does cancelling actually revoke your access?",
                    "Subscribing sets a raw cookie with no server-side subscription record. Cancelling only updates your session — check whether it ever touches that same cookie.",
                    "POST to /a04/premium/subscribe, then POST to /a04/premium/cancel (the page confirms cancellation), then GET /a04/premium/content — the premium content still renders, because the cookie gating access was never cleared.",
                    "This models a real class of bug: trusting unsigned client-side state as the sole proof of an active subscription, with the cancellation flow never reconciling that same piece of state.",
                ],
            ),
        ],
    )
)
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a04_premium_access.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass, updating cross-cutting files again
(`test_a04_hints.py` → 8, `test_all_examples_have_hints.py` → 82,
`test_hints.py` → 1680 [+20]). New total: 514 (511 + 3 new).

- [ ] **Step 8: Commit**

```bash
git add app/categories/a04_insecure_design tests/test_a04_premium_access.py tests/test_a04_hints.py tests/test_a04_overview.py tests/test_all_examples_have_hints.py tests/test_hints.py
git commit -m "feat(a04): add premium-access-persists-after-cancellation example

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 5: A04 — Store-Credit Rounding Exploit

**Files:**
- Modify: `app/categories/a04_insecure_design/routes.py`
- Modify: `app/categories/a04_insecure_design/__init__.py`
- Create: `app/categories/a04_insecure_design/templates/a04_insecure_design/loyalty_convert.html`
- Test: `tests/test_a04_rounding_exploit.py`

**Interfaces:**
- Consumes: `_format_cents()` (existing).
- Produces: route `a04_insecure_design.loyalty_convert` (`GET/POST
  /a04/loyalty-convert`). Nothing later depends on this.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a04_rounding_exploit.py`:

```python
def test_loyalty_convert_page_renders(client):
    response = client.get("/a04/loyalty-convert")
    assert response.status_code == 200
    assert b"Store-Credit Rounding Exploit" in response.data


def test_converting_one_point_credits_a_full_cent(client):
    # 1 point is worth 0.3 cents (0.3 * 1), which the buggy rounding
    # rounds UP to a minimum of 1 cent -- not truncated to 0.
    response = client.post("/a04/loyalty-convert", data={"points": "1"})
    assert response.status_code == 200
    assert b"Store credit balance: $0.01" in response.data


def test_repeating_the_conversion_nets_free_money(client):
    for _ in range(100):
        client.post("/a04/loyalty-convert", data={"points": "1"})
    response = client.get("/a04/loyalty-convert")
    assert response.status_code == 200
    # 100 conversions of a 0.3-cent-true-value point, each rounded up to
    # 1 cent with no floor or rate limit, nets $1.00 of pure rounding
    # profit -- the true value would have been $0.30.
    assert b"Store credit balance: $1.00" in response.data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_a04_rounding_exploit.py -v`
Expected: FAIL — route doesn't exist yet (404s).

- [ ] **Step 3: Add the new route**

Modify `app/categories/a04_insecure_design/routes.py`. Add this constant
near the other constants:

```python
POINTS_TO_CENTS_RATE = 0.3
```

Append this route at the end of the file:

```python


@a04_bp.route("/loyalty-convert", methods=["GET", "POST"])
def loyalty_convert():
    error = None
    if request.method == "POST":
        try:
            points = int(request.form.get("points", "0"))
        except (ValueError, OverflowError):
            points = 0
        if points > 0:
            true_value_cents = points * POINTS_TO_CENTS_RATE
            # VULNERABLE: rounds UP to a minimum of 1 cent whenever the
            # true fractional value is positive, with no minimum
            # conversion amount enforced and no rate limit on repeated
            # conversions -- a customer's balance never actually loses
            # anything on the sending side of this "conversion", so
            # repeating a tiny conversion many times mints real cents
            # from a fractional value that should have rounded to zero.
            credited_cents = max(1, round(true_value_cents))
            session["a04_store_credit_cents"] = session.get("a04_store_credit_cents", 0) + credited_cents
        else:
            error = "Enter a positive number of points."
    balance_cents = session.get("a04_store_credit_cents", 0)
    return render_template(
        "a04_insecure_design/loyalty_convert.html",
        balance_display=_format_cents(balance_cents),
        error=error,
    )
```

- [ ] **Step 4: Create `loyalty_convert.html`**

Create `app/categories/a04_insecure_design/templates/a04_insecure_design/loyalty_convert.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Store-Credit Rounding Exploit" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A04{% endblock %}

{% block explanation %}
<p>
  Converting loyalty points to store credit uses a rate of 0.3 cents per
  point — but the conversion always rounds the credited amount
  <strong>up</strong> to a minimum of 1 cent, even converting a single
  point (truly worth 0.3¢). There's no minimum-conversion-amount enforced
  and no rate limit on repeated conversions. Repeating a 1-point
  conversion many times credits 1 cent per call regardless of the true
  0.3¢ value each point should be worth — creating real money that was
  never actually present in the true fractional value.
</p>
{% endblock %}

{% block detect %}
<p>
  Convert 1 point and check the credited amount. If it's a full cent
  (rather than a fraction that gets truncated toward zero, or a rejected
  "below minimum" error), the rounding favors the customer with no floor.
</p>
{% endblock %}

{% block exploitation %}
<p>
  This directly adapts a real HackerOne-reported bug in a cryptocurrency
  platform's internal transfer system, where a sub-minimum-precision
  transfer rounded up on the receiving side without deducting anything
  equivalent from the sender:
</p>
<pre><code class="language-bash">for i in $(seq 1 100); do
  curl -s -X POST http://127.0.0.1:5001/a04/loyalty-convert -b cookies.txt -c cookies.txt -d "points=1" &gt; /dev/null
done
curl -s http://127.0.0.1:5001/a04/loyalty-convert -b cookies.txt | grep "Store credit balance"</code></pre>
<p>
  100 conversions of a point genuinely worth 0.3¢ each (true total value:
  30¢) nets a full $1.00 of store credit — 70 cents of pure rounding
  profit, entirely automatable since nothing limits how many times the
  conversion can be repeated.
</p>
{% endblock %}

{% block vulnerable_code %}POINTS_TO_CENTS_RATE = 0.3

true_value_cents = points * POINTS_TO_CENTS_RATE
# VULNERABLE: always rounds UP to at least 1 cent, no minimum
# conversion amount, no rate limit on repeated conversions
credited_cents = max(1, round(true_value_cents))
balance_cents += credited_cents
{% endblock %}

{% block secure_code %}POINTS_TO_CENTS_RATE = 0.3
MINIMUM_CONVERSION_POINTS = 10  # anything smaller truncates to 0, not rounds up

true_value_cents = points * POINTS_TO_CENTS_RATE
if points &lt; MINIMUM_CONVERSION_POINTS:
    abort(400)  # reject conversions too small to represent precisely
credited_cents = int(true_value_cents)  # truncate, never round up
balance_cents += credited_cents
{% endblock %}

{% block live_example %}
<p>Store credit balance: {{ balance_display }}</p>
{% if error %}<p class="text-danger">{{ error }}</p>{% endif %}
<form method="post" class="d-flex gap-2">
  <input type="number" class="form-control" name="points" value="1" min="1">
  <button type="submit" class="btn btn-primary">Convert points to store credit</button>
</form>
{% endblock %}
```

- [ ] **Step 5: Add the `ExampleNav` entry**

Modify `app/categories/a04_insecure_design/__init__.py`. Re-read the
actual current file (Task 4 already appended the "Premium Access Design
Flaws" group) and find the closing of the `examples=[...]` list — the
final existing entry `premium-access-after-cancel`, followed by `],`:

```python
            ExampleNav(
                id="premium-access-after-cancel",
                title="Premium Access Persists After Cancellation",
                group="Premium Access Design Flaws",
                difficulty="Medium",
                endpoint="a04_insecure_design.premium_content",
                hints=[
                    "Subscribe, then cancel, then revisit the premium content page. Does cancelling actually revoke your access?",
                    "Subscribing sets a raw cookie with no server-side subscription record. Cancelling only updates your session — check whether it ever touches that same cookie.",
                    "POST to /a04/premium/subscribe, then POST to /a04/premium/cancel (the page confirms cancellation), then GET /a04/premium/content — the premium content still renders, because the cookie gating access was never cleared.",
                    "This models a real class of bug: trusting unsigned client-side state as the sole proof of an active subscription, with the cancellation flow never reconciling that same piece of state.",
                ],
            ),
        ],
    )
)
```

Replace with (appending the new "Rounding & Arithmetic Errors" group as a
new group at the end of the list):

```python
            ExampleNav(
                id="premium-access-after-cancel",
                title="Premium Access Persists After Cancellation",
                group="Premium Access Design Flaws",
                difficulty="Medium",
                endpoint="a04_insecure_design.premium_content",
                hints=[
                    "Subscribe, then cancel, then revisit the premium content page. Does cancelling actually revoke your access?",
                    "Subscribing sets a raw cookie with no server-side subscription record. Cancelling only updates your session — check whether it ever touches that same cookie.",
                    "POST to /a04/premium/subscribe, then POST to /a04/premium/cancel (the page confirms cancellation), then GET /a04/premium/content — the premium content still renders, because the cookie gating access was never cleared.",
                    "This models a real class of bug: trusting unsigned client-side state as the sole proof of an active subscription, with the cancellation flow never reconciling that same piece of state.",
                ],
            ),
            ExampleNav(
                id="rounding-exploit",
                title="Store-Credit Rounding Exploit",
                group="Rounding & Arithmetic Errors",
                difficulty="Hard",
                endpoint="a04_insecure_design.loyalty_convert",
                hints=[
                    "Convert 1 loyalty point to store credit and check the exact amount credited. This point is worth a fraction of a cent — does it round toward zero, or up to a full cent?",
                    "Points convert at 0.3 cents each, but the credited amount always rounds UP to at least 1 cent, with no minimum conversion size enforced and no rate limit on repeating the conversion.",
                    "Repeat the same 1-point conversion many times in a row (e.g. a loop of 100 requests) — each one credits 1 full cent regardless of the true 0.3-cent value, netting real money that was never actually present.",
                    "This adapts a real HackerOne-reported bug in a cryptocurrency platform: automate 100 conversions of 1 point each and check the resulting balance — it reaches $1.00, not the true value of $0.30, purely from rounding favoring the customer with nothing throttling repetition.",
                ],
            ),
        ],
    )
)
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a04_rounding_exploit.py -v`
Expected: PASS (3 passed)

- [ ] **Step 7: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass, updating cross-cutting files again
(`test_a04_hints.py` → 9, `test_all_examples_have_hints.py` → 83,
`test_hints.py` → 1710 [+30 for this Hard example]). New total: 517
(514 + 3 new). This is the last A04 task — all 9 examples registered.

- [ ] **Step 8: Commit**

```bash
git add app/categories/a04_insecure_design tests/test_a04_rounding_exploit.py tests/test_a04_hints.py tests/test_a04_overview.py tests/test_all_examples_have_hints.py tests/test_hints.py
git commit -m "feat(a04): add store-credit-rounding-exploit example

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Orchestration Note: Tasks 6-8 All Edit A05's `routes.py`/`__init__.py`

Tasks 6, 7, and 8 each append a new route to
`app/categories/a05_security_misconfiguration/routes.py` and a new
`ExampleNav` entry to `app/categories/a05_security_misconfiguration/__init__.py`'s
`examples=[...]` list. As with the A04 orchestration note above, each
task's insertion point is described relative to a named existing `id`,
not a rigid full-block find/replace against the file's original
contents — **always re-read the actual current file state before
editing**, since Tasks 6-8 run in order and each changes what
immediately surrounds the next task's anchor.

The worked-out final result, after all three tasks land in order, is
(existing 7 examples shown alongside the 3 new ones, in final flat-list
order):

| # | id | Difficulty | Group |
|---|---|---|---|
| 1 | `exposed-backup` (existing) | Easy | Exposed Files & Directories |
| 2 | `directory-listing` (existing) | Easy | Exposed Files & Directories |
| 3 | `verbose-errors` (existing) | Medium | Insecure Response Configuration |
| 4 | `cors-credentials` (existing) | Medium | Insecure Response Configuration |
| 5 | `cors-null-origin` (Task 6) | Medium | Insecure Response Configuration |
| 6 | `cors-wildcard-internal-pivot` (Task 7) | Medium | Insecure Response Configuration |
| 7 | `cors-origin-regex-bypass` (Task 8) | Hard | Insecure Response Configuration |
| 8 | `debug-console-rce` (existing) | Hard | Exposed Debug & Admin Interfaces |
| 9 | `default-admin-creds` (existing) | Hard | Exposed Debug & Admin Interfaces |
| 10 | `clickjacking-delete-account` (existing) | Easy | Missing Security Headers |

Group display order (by first occurrence): Exposed Files & Directories,
Insecure Response Configuration, Exposed Debug & Admin Interfaces,
Missing Security Headers (unchanged from before this plan — no new
groups in A05). "Insecure Response Configuration"'s internal order is
Medium, Medium, Medium, Medium, Hard — Easy→Hard sorted. Task 9 gives the
exact resulting assertions this must produce.

All three new routes are inserted immediately after `cors-credentials`
and before whatever currently follows it (`debug-console-rce`, until an
earlier task in this trio has already inserted something there) — each
task finds `cors-credentials`'s entry and the entry immediately after it
in the real current file, and inserts its own new entry between them.

---

## Task 6: A05 — CORS: Null Origin Whitelisted

**Files:**
- Modify: `app/categories/a05_security_misconfiguration/routes.py`
- Modify: `app/categories/a05_security_misconfiguration/__init__.py`
- Create: `app/categories/a05_security_misconfiguration/templates/a05_security_misconfiguration/cors_null_origin.html`
- Create: `app/categories/a05_security_misconfiguration/templates/a05_security_misconfiguration/cors_null_origin_demo.html`
- Test: `tests/test_a05_cors_null_origin.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: routes `a05_security_misconfiguration.partner_directory_api`
  (`GET /a05/api/partner-directory`, the vulnerable JSON API),
  `a05_security_misconfiguration.cors_null_origin_demo` (`GET
  /a05/cors-null-origin-demo`, the sandboxed-iframe attacker demo page),
  and `a05_security_misconfiguration.cors_null_origin` (`GET
  /a05/cors-null-origin`, the example's HTML explanation page — this is
  what `ExampleNav.endpoint` must point at, NOT the raw API route,
  matching the app's universal convention that every example's endpoint
  renders its explanation page with the "mark as done" UI; the existing
  `cors-credentials` example already follows this split between
  `cors_credentials` (HTML) and `loyalty_status_api` (JSON)). Nothing
  later depends on these.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a05_cors_null_origin.py`:

```python
def test_cors_null_origin_page_renders(client):
    response = client.get("/a05/api/partner-directory")
    assert response.status_code == 200


def test_null_origin_is_reflected_with_credentials(client):
    response = client.get("/a05/api/partner-directory", headers={"Origin": "null"})
    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") == "null"
    assert response.headers.get("Access-Control-Allow-Credentials") == "true"


def test_a_real_specific_origin_is_not_reflected(client):
    # VULNERABLE-CONFIRMATION: only the literal "null" origin is
    # whitelisted -- a normal, specific attacker origin gets no CORS
    # headers at all from this endpoint (the flaw is specifically about
    # trusting "null", not about reflecting everything).
    response = client.get("/a05/api/partner-directory", headers={"Origin": "https://evil.com"})
    assert response.status_code == 200
    assert "Access-Control-Allow-Origin" not in response.headers


def test_null_origin_demo_page_embeds_sandboxed_data_uri_iframe(client):
    response = client.get("/a05/cors-null-origin-demo")
    assert response.status_code == 200
    assert b'sandbox="allow-scripts"' in response.data
    assert b"data:text/html" in response.data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_a05_cors_null_origin.py -v`
Expected: FAIL — routes don't exist yet (404s).

- [ ] **Step 3: Add the two new routes**

Modify `app/categories/a05_security_misconfiguration/routes.py`. Append
these two routes at the end of the file (after `delete_account_clickjack_demo`):

```python


PARTNER_DIRECTORY = [
    {"name": "Acme Logistics", "contact": "ops@acme-logistics.example"},
    {"name": "Nimbus Freight", "contact": "dispatch@nimbus-freight.example"},
]


@a05_bp.route("/api/partner-directory")
def partner_directory_api():
    resp = jsonify({"partners": PARTNER_DIRECTORY})
    origin = request.headers.get("Origin")
    # VULNERABLE: explicitly whitelists the literal "null" origin -- a
    # leftover from testing this endpoint via a sandboxed iframe or a
    # local file during development that was never removed. A normal,
    # specific attacker origin gets no CORS headers at all; only "null"
    # does, which is exactly what makes this a distinct, narrower flaw
    # than the existing origin-reflection example.
    if origin == "null":
        resp.headers["Access-Control-Allow-Origin"] = "null"
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


@a05_bp.route("/cors-null-origin-demo")
def cors_null_origin_demo():
    return render_template("a05_security_misconfiguration/cors_null_origin_demo.html")


@a05_bp.route("/cors-null-origin")
def cors_null_origin():
    # This is the example's own explanation/exploitation page -- separate
    # from the vulnerable JSON API above (partner_directory_api), matching
    # the established convention this app already uses for cors-credentials
    # (its own HTML page) vs. loyalty_status_api (the vulnerable JSON API
    # it demonstrates). ExampleNav.endpoint always points at the HTML
    # page, never directly at a raw JSON route, so the app's standard
    # explanation UI and "mark as done" flow both work.
    return render_template("a05_security_misconfiguration/cors_null_origin.html")
```

- [ ] **Step 4: Create `cors_null_origin.html`**

Create `app/categories/a05_security_misconfiguration/templates/a05_security_misconfiguration/cors_null_origin.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "CORS: Null Origin Whitelisted" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A05{% endblock %}

{% block explanation %}
<p>
  <code>/a05/api/partner-directory</code> explicitly trusts requests
  whose <code>Origin</code> header is the literal string
  <code>null</code>, responding with
  <code>Access-Control-Allow-Origin: null</code> and
  <code>Access-Control-Allow-Credentials: true</code>. This is a common
  leftover from testing an endpoint via a sandboxed iframe or a local
  file during development — browsers send a literal <code>null</code>
  Origin in exactly those situations, and an attacker can deliberately
  trigger one on demand.
</p>
{% endblock %}

{% block detect %}
<p>
  Request the endpoint with an <code>Origin: null</code> header and check
  whether the response reflects it back — a properly configured
  allowlist should never treat <code>null</code> as a real, trusted
  origin.
</p>
{% endblock %}

{% block exploitation %}
<p>
  A sandboxed iframe using a <code>data:</code> URI causes the browser to
  send a literal <code>null</code> Origin header on any request that
  iframe makes:
</p>
<pre><code class="language-html">&lt;iframe sandbox="allow-scripts" src="data:text/html,
  &lt;script&gt;
    fetch('http://127.0.0.1:5001/a05/api/partner-directory', {credentials: 'include'})
      .then(r =&gt; r.json())
      .then(j =&gt; parent.postMessage(JSON.stringify(j), '*'));
  &lt;/script&gt;
"&gt;&lt;/iframe&gt;</code></pre>
<p>
  Visit <a href="{{ url_for('a05_security_misconfiguration.cors_null_origin_demo') }}">the
  demo page</a> to see this exact technique running live — the
  sandboxed, data-URI iframe's requests carry a <code>null</code> Origin,
  which this endpoint explicitly trusts, letting the fetch succeed
  cross-origin with credentials attached.
</p>
{% endblock %}

{% block vulnerable_code %}origin = request.headers.get("Origin")
if origin == "null":
    # VULNERABLE: trusts the literal "null" origin as if it were a real,
    # specific trusted domain
    resp.headers["Access-Control-Allow-Origin"] = "null"
    resp.headers["Access-Control-Allow-Credentials"] = "true"
{% endblock %}

{% block secure_code %}ALLOWED_ORIGINS = {"https://partners.example.com"}

origin = request.headers.get("Origin")
if origin in ALLOWED_ORIGINS:  # "null" is never a member of a real allowlist
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
{% endblock %}

{% block live_example %}
<p class="text-muted">
  This is a JSON API endpoint — use curl as shown in the Exploitation
  section above, or visit
  <a href="{{ url_for('a05_security_misconfiguration.cors_null_origin_demo') }}">the
  live demo page</a> to see the sandboxed-iframe exploit in action.
</p>
{% endblock %}
```

- [ ] **Step 5: Create `cors_null_origin_demo.html`**

Create `app/categories/a05_security_misconfiguration/templates/a05_security_misconfiguration/cors_null_origin_demo.html`
(supporting flow page — extends plain `core/base.html`, matching
`delete_account_clickjack_demo.html`'s convention):

```html
{% extends "core/base.html" %}
{% block title %}Null Origin CORS Demo{% endblock %}

{% block content %}
<h1>Null Origin CORS Demo</h1>
<p class="text-muted">
  This page simulates an attacker-controlled site. The sandboxed iframe
  below uses a <code>data:</code> URI, which causes the browser to send
  a literal <code>null</code> Origin header on any request the iframe's
  script makes — exactly the value
  <code>/a05/api/partner-directory</code> whitelists.
</p>
<div id="result" class="border rounded p-2 bg-body-secondary mb-3">(pending)</div>
<iframe sandbox="allow-scripts" style="display:none"
  src="data:text/html,
  &lt;script&gt;
    fetch(&quot;http://127.0.0.1:5001/a05/api/partner-directory&quot;, {credentials: &quot;include&quot;})
      .then(r =&gt; r.json())
      .then(j =&gt; parent.postMessage(JSON.stringify(j), &quot;*&quot;))
      .catch(e =&gt; parent.postMessage(&quot;blocked: &quot; + e, &quot;*&quot;));
  &lt;/script&gt;
"></iframe>
<script>
window.addEventListener("message", function (event) {
  document.getElementById("result").textContent = event.data;
});
</script>
{% endblock %}
```

- [ ] **Step 6: Add the `ExampleNav` entry**

Modify `app/categories/a05_security_misconfiguration/__init__.py`. Find
the `cors-credentials` entry, followed by `debug-console-rce`:

```python
            ExampleNav(
                id="cors-credentials",
                title="Permissive CORS with Credentials",
                group="Insecure Response Configuration",
                difficulty="Medium",
                endpoint="a05_security_misconfiguration.cors_credentials",
                hints=[
                    "This page sets a cookie, then a separate API endpoint reads it back. Check that API endpoint's response headers — specifically anything starting with Access-Control-*.",
                    "/a05/api/loyalty-status reflects whatever Origin header the request sent back as Access-Control-Allow-Origin, and also sets Access-Control-Allow-Credentials: true — that combination lets a response be read cross-origin, cookies included, by literally any site.",
                    "From a page on a completely different origin, run: fetch('http://127.0.0.1:5000/a05/api/loyalty-status', {credentials: 'include'}).then(r => r.json()).then(console.log) — because the API reflects your page's Origin and allows credentials, the browser lets this cross-site request through and hands back the victim's real loyalty token, something the same-origin policy exists specifically to prevent.",
                    "Full attack shape: host that fetch() call on any other origin (even a plain local HTML file opened via a small http.server on a different port counts as cross-origin), first visit /a05/cors-credentials in the same browser to plant the cookie, then load your attacker page and watch it read the victim's token straight out of the JSON response.",
                ],
            ),
            ExampleNav(
                id="debug-console-rce",
```

Insert immediately after it (before `debug-console-rce`):

```python
            ExampleNav(
                id="cors-credentials",
                title="Permissive CORS with Credentials",
                group="Insecure Response Configuration",
                difficulty="Medium",
                endpoint="a05_security_misconfiguration.cors_credentials",
                hints=[
                    "This page sets a cookie, then a separate API endpoint reads it back. Check that API endpoint's response headers — specifically anything starting with Access-Control-*.",
                    "/a05/api/loyalty-status reflects whatever Origin header the request sent back as Access-Control-Allow-Origin, and also sets Access-Control-Allow-Credentials: true — that combination lets a response be read cross-origin, cookies included, by literally any site.",
                    "From a page on a completely different origin, run: fetch('http://127.0.0.1:5000/a05/api/loyalty-status', {credentials: 'include'}).then(r => r.json()).then(console.log) — because the API reflects your page's Origin and allows credentials, the browser lets this cross-site request through and hands back the victim's real loyalty token, something the same-origin policy exists specifically to prevent.",
                    "Full attack shape: host that fetch() call on any other origin (even a plain local HTML file opened via a small http.server on a different port counts as cross-origin), first visit /a05/cors-credentials in the same browser to plant the cookie, then load your attacker page and watch it read the victim's token straight out of the JSON response.",
                ],
            ),
            ExampleNav(
                id="cors-null-origin",
                title="CORS: Null Origin Whitelisted",
                group="Insecure Response Configuration",
                difficulty="Medium",
                endpoint="a05_security_misconfiguration.cors_null_origin",
                hints=[
                    "This endpoint's CORS behavior is different from the other CORS example in this app — it doesn't reflect just any origin. Try requesting it with an Origin header of the literal string 'null'.",
                    "The server explicitly whitelists the literal 'null' origin as if it were a real, specific trusted domain — a leftover from testing via a sandboxed iframe or local file during development.",
                    "Browsers send a literal null Origin header when a sandboxed iframe with no allow-same-origin uses a data: URI. Visit /a05/cors-null-origin-demo to see this exact technique running live against /a05/api/partner-directory.",
                    "curl -s http://127.0.0.1:5000/a05/api/partner-directory -H 'Origin: null' — the response includes Access-Control-Allow-Origin: null and Access-Control-Allow-Credentials: true, letting a null-origin context read this response with credentials attached.",
                ],
            ),
            ExampleNav(
                id="debug-console-rce",
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a05_cors_null_origin.py -v`
Expected: PASS (4 passed)

- [ ] **Step 8: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass, updating cross-cutting files (`test_a05_hints.py` →
8, `test_all_examples_have_hints.py` → 84, `test_hints.py` → 1730
[+20]). New total: 521 (517 + 4 new).

- [ ] **Step 9: Commit**

```bash
git add app/categories/a05_security_misconfiguration tests/test_a05_cors_null_origin.py tests/test_a05_hints.py tests/test_a05_overview.py tests/test_all_examples_have_hints.py tests/test_hints.py
git commit -m "feat(a05): add cors-null-origin-whitelisted example

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 7: A05 — CORS: Wildcard Origin, Internal Network Pivot

**Files:**
- Modify: `app/categories/a05_security_misconfiguration/routes.py`
- Modify: `app/categories/a05_security_misconfiguration/__init__.py`
- Create: `app/categories/a05_security_misconfiguration/templates/a05_security_misconfiguration/cors_wildcard_internal_pivot.html`
- Test: `tests/test_a05_cors_wildcard_internal_pivot.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: routes `a05_security_misconfiguration.internal_metrics_api`
  (`GET /a05/api/internal-metrics`, the vulnerable JSON API) and
  `a05_security_misconfiguration.cors_wildcard_internal_pivot` (`GET
  /a05/cors-wildcard-internal-pivot`, the example's HTML explanation
  page — this is what `ExampleNav.endpoint` must point at, NOT the raw
  API route, matching the app's universal convention that every
  example's endpoint renders its explanation page with the "mark as
  done" UI; the existing `cors-credentials` example already follows this
  split between `cors_credentials` (HTML) and `loyalty_status_api`
  (JSON)). Nothing later depends on these.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a05_cors_wildcard_internal_pivot.py`:

```python
def test_internal_metrics_page_renders(client):
    response = client.get("/a05/api/internal-metrics")
    assert response.status_code == 200


def test_wildcard_origin_header_present(client):
    response = client.get("/a05/api/internal-metrics", headers={"Origin": "https://evil.com"})
    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") == "*"


def test_no_credentials_header_sent_with_wildcard(client):
    # Wildcard + credentials is a combination real browsers refuse
    # outright, so a genuinely wildcard response never sets this header.
    response = client.get("/a05/api/internal-metrics", headers={"Origin": "https://evil.com"})
    assert "Access-Control-Allow-Credentials" not in response.headers


def test_no_authentication_required_at_all(client):
    # VULNERABLE: zero auth check -- this "internal" endpoint returns
    # sensitive data to any unauthenticated request whatsoever.
    response = client.get("/a05/api/internal-metrics")
    assert response.status_code == 200
    assert b"active_connections" in response.data
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_a05_cors_wildcard_internal_pivot.py -v`
Expected: FAIL — route doesn't exist yet (404s).

- [ ] **Step 3: Add the new route**

Modify `app/categories/a05_security_misconfiguration/routes.py`. Append
this route at the end of the file:

```python


@a05_bp.route("/api/internal-metrics")
def internal_metrics_api():
    # VULNERABLE: no authentication of any kind (no session check, no API
    # key) AND a wildcard CORS header, on an endpoint that returns
    # sensitive-looking internal data. The wildcard itself doesn't leak
    # cookies (browsers never attach credentials to a wildcard-CORS
    # request) -- the real vulnerability is the missing auth check, and
    # the permissive CORS header is what lets an external attacker's page
    # make this request at all instead of the browser blocking it
    # outright as cross-origin.
    resp = jsonify(
        {
            "active_connections": 1842,
            "internal_hostname": "metrics-collector-03.internal.owasp-lab.local",
            "queue_depth": 57,
        }
    )
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


@a05_bp.route("/cors-wildcard-internal-pivot")
def cors_wildcard_internal_pivot():
    # This is the example's own explanation/exploitation page -- separate
    # from the vulnerable JSON API above (internal_metrics_api), matching
    # the established convention this app already uses for cors-credentials
    # (its own HTML page) vs. loyalty_status_api (the vulnerable JSON API
    # it demonstrates). ExampleNav.endpoint always points at the HTML
    # page, never directly at a raw JSON route, so the app's standard
    # explanation UI and "mark as done" flow both work.
    return render_template("a05_security_misconfiguration/cors_wildcard_internal_pivot.html")
```

- [ ] **Step 4: Create `cors_wildcard_internal_pivot.html`**

Create `app/categories/a05_security_misconfiguration/templates/a05_security_misconfiguration/cors_wildcard_internal_pivot.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "CORS: Wildcard Origin, Internal Network Pivot" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A05{% endblock %}

{% block explanation %}
<p>
  This "internal metrics" endpoint sets
  <code>Access-Control-Allow-Origin: *</code> unconditionally and
  requires no authentication of any kind — no session, no API key. A
  wildcard origin means browsers never attach cookies to the request, so
  credential theft isn't the risk here — but since the endpoint itself
  never checks who's asking either, any external page can still read the
  sensitive response data through a victim's browser.
</p>
{% endblock %}

{% block detect %}
<p>
  Request the endpoint with no authentication at all and check two
  things: does it respond with real data anyway, and does its
  <code>Access-Control-Allow-Origin</code> header say <code>*</code>?
  Either alone is a misconfiguration; together, they mean any page on the
  internet can read this response through a victim's browser.
</p>
{% endblock %}

{% block exploitation %}
<pre><code class="language-bash">curl -s http://127.0.0.1:5001/a05/api/internal-metrics -H "Origin: https://evil.com"</code></pre>
<p>
  The response includes <code>Access-Control-Allow-Origin: *</code> and
  the full metrics payload — internal hostnames, connection counts, queue
  depth — with zero authentication required. Any external page's
  JavaScript can <code>fetch()</code> this endpoint directly:
</p>
<pre><code class="language-js">fetch('http://127.0.0.1:5001/a05/api/internal-metrics')
  .then(r =&gt; r.json())
  .then(console.log);</code></pre>
<p>
  In a real deployment, this endpoint would live on a network segment
  not directly reachable from the internet — but if a victim inside that
  network loads the attacker's page (e.g. a phishing link opened on a
  work laptop), their browser makes the request on the attacker's
  behalf, pivoting the read straight into an otherwise-unreachable
  internal service.
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/api/internal-metrics")
def internal_metrics_api():
    # VULNERABLE: no authentication check at all, on data that should be
    # internal-only
    resp = jsonify({"active_connections": ..., "internal_hostname": ...})
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp
{% endblock %}

{% block secure_code %}@app.route("/api/internal-metrics")
def internal_metrics_api():
    if not is_internal_network_request(request) and not valid_api_key(request):
        abort(403)
    resp = jsonify({"active_connections": ..., "internal_hostname": ...})
    # No CORS header at all -- this endpoint is never meant to be called
    # from a browser context outside the internal network
    return resp
{% endblock %}

{% block live_example %}
<p class="text-muted">
  This is a JSON API endpoint with no HTML form — use curl or your
  browser's JavaScript console as shown in the Exploitation section
  above: <code>GET /a05/api/internal-metrics</code>.
</p>
{% endblock %}
```

- [ ] **Step 5: Add the `ExampleNav` entry**

Modify `app/categories/a05_security_misconfiguration/__init__.py`. Find
the `cors-null-origin` entry (added by Task 6), followed by whatever now
comes after it (`debug-console-rce`, unless Task 6 landed differently —
re-read the real current file):

```python
            ExampleNav(
                id="cors-null-origin",
                title="CORS: Null Origin Whitelisted",
                group="Insecure Response Configuration",
                difficulty="Medium",
                endpoint="a05_security_misconfiguration.cors_null_origin",
                hints=[
                    "This endpoint's CORS behavior is different from the other CORS example in this app — it doesn't reflect just any origin. Try requesting it with an Origin header of the literal string 'null'.",
                    "The server explicitly whitelists the literal 'null' origin as if it were a real, specific trusted domain — a leftover from testing via a sandboxed iframe or local file during development.",
                    "Browsers send a literal null Origin header when a sandboxed iframe with no allow-same-origin uses a data: URI. Visit /a05/cors-null-origin-demo to see this exact technique running live against /a05/api/partner-directory.",
                    "curl -s http://127.0.0.1:5000/a05/api/partner-directory -H 'Origin: null' — the response includes Access-Control-Allow-Origin: null and Access-Control-Allow-Credentials: true, letting a null-origin context read this response with credentials attached.",
                ],
            ),
            ExampleNav(
                id="debug-console-rce",
```

Insert immediately after it (before `debug-console-rce`):

```python
            ExampleNav(
                id="cors-null-origin",
                title="CORS: Null Origin Whitelisted",
                group="Insecure Response Configuration",
                difficulty="Medium",
                endpoint="a05_security_misconfiguration.cors_null_origin",
                hints=[
                    "This endpoint's CORS behavior is different from the other CORS example in this app — it doesn't reflect just any origin. Try requesting it with an Origin header of the literal string 'null'.",
                    "The server explicitly whitelists the literal 'null' origin as if it were a real, specific trusted domain — a leftover from testing via a sandboxed iframe or local file during development.",
                    "Browsers send a literal null Origin header when a sandboxed iframe with no allow-same-origin uses a data: URI. Visit /a05/cors-null-origin-demo to see this exact technique running live against /a05/api/partner-directory.",
                    "curl -s http://127.0.0.1:5000/a05/api/partner-directory -H 'Origin: null' — the response includes Access-Control-Allow-Origin: null and Access-Control-Allow-Credentials: true, letting a null-origin context read this response with credentials attached.",
                ],
            ),
            ExampleNav(
                id="cors-wildcard-internal-pivot",
                title="CORS: Wildcard Origin, Internal Network Pivot",
                group="Insecure Response Configuration",
                difficulty="Medium",
                endpoint="a05_security_misconfiguration.cors_wildcard_internal_pivot",
                hints=[
                    "This 'internal metrics' endpoint has a wildcard CORS header. A wildcard blocks cookies from being attached — so what OTHER protection would need to be missing for that to still matter?",
                    "The endpoint requires no authentication at all — no session, no API key. A wildcard CORS header combined with zero auth means any external page's JavaScript can read this response directly.",
                    "curl -s http://127.0.0.1:5000/a05/api/internal-metrics -H 'Origin: https://evil.com' — the response includes Access-Control-Allow-Origin: * and real internal metrics data, with no authentication required at all.",
                    "This is the 'internal network pivot' variant: in a real deployment this endpoint would sit on a network segment unreachable from the internet, but a victim's browser inside that network can be made to fetch() it on an attacker's behalf via a page the victim merely visits — the missing auth check is the real bug, and the wildcard CORS header is what lets the cross-origin request through.",
                ],
            ),
            ExampleNav(
                id="debug-console-rce",
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a05_cors_wildcard_internal_pivot.py -v`
Expected: PASS (4 passed)

- [ ] **Step 7: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass, updating cross-cutting files (`test_a05_hints.py` →
9, `test_all_examples_have_hints.py` → 85, `test_hints.py` → 1750
[+20]). New total: 525 (521 + 4 new).

- [ ] **Step 8: Commit**

```bash
git add app/categories/a05_security_misconfiguration tests/test_a05_cors_wildcard_internal_pivot.py tests/test_a05_hints.py tests/test_a05_overview.py tests/test_all_examples_have_hints.py tests/test_hints.py
git commit -m "feat(a05): add cors-wildcard-origin-internal-network-pivot example

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 8: A05 — CORS: Origin Allowlist Regex Bypass

**Files:**
- Modify: `app/categories/a05_security_misconfiguration/routes.py`
- Modify: `app/categories/a05_security_misconfiguration/__init__.py`
- Create: `app/categories/a05_security_misconfiguration/templates/a05_security_misconfiguration/cors_origin_regex_bypass.html`
- Test: `tests/test_a05_cors_origin_regex_bypass.py`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: routes `a05_security_misconfiguration.partner_portal_api`
  (`GET /a05/api/partner-portal`, the vulnerable JSON API) and
  `a05_security_misconfiguration.cors_origin_regex_bypass` (`GET
  /a05/cors-origin-regex-bypass`, the example's HTML explanation page —
  this is what `ExampleNav.endpoint` must point at, NOT the raw API
  route, matching the app's universal convention that every example's
  endpoint renders its explanation page with the "mark as done" UI; the
  existing `cors-credentials` example already follows this split between
  `cors_credentials` (HTML) and `loyalty_status_api` (JSON)). Nothing
  later depends on these. This
  is the last A05 task — after this lands, A05 has 10 examples across 4
  groups.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_a05_cors_origin_regex_bypass.py`:

```python
def test_partner_portal_page_renders(client):
    response = client.get("/a05/api/partner-portal")
    assert response.status_code == 200


def test_real_partner_origin_is_accepted(client):
    response = client.get(
        "/a05/api/partner-portal", headers={"Origin": "https://partner.example.com"}
    )
    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") == "https://partner.example.com"
    assert response.headers.get("Access-Control-Allow-Credentials") == "true"


def test_unanchored_regex_accepts_a_lookalike_attacker_domain(client):
    # VULNERABLE: the allowlist regex has no end-anchor, so any origin
    # merely CONTAINING "example.com" after "https://" matches --
    # including a domain the real business never registered or trusts.
    response = client.get(
        "/a05/api/partner-portal", headers={"Origin": "https://evilexample.com"}
    )
    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") == "https://evilexample.com"
    assert response.headers.get("Access-Control-Allow-Credentials") == "true"


def test_a_completely_unrelated_origin_is_still_rejected(client):
    response = client.get(
        "/a05/api/partner-portal", headers={"Origin": "https://totally-unrelated.com"}
    )
    assert response.status_code == 200
    assert "Access-Control-Allow-Origin" not in response.headers
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_a05_cors_origin_regex_bypass.py -v`
Expected: FAIL — route doesn't exist yet (404s).

- [ ] **Step 3: Add the new route**

Modify `app/categories/a05_security_misconfiguration/routes.py`. Add
`import re` to the top-of-file imports if not already present (check the
current file first), then append this route at the end of the file:

```python


PARTNER_PORTAL_ORIGIN_PATTERN = re.compile(r"https://.*example\.com")


@a05_bp.route("/api/partner-portal")
def partner_portal_api():
    resp = jsonify({"partner_deals": ["Q4 volume discount", "Priority support tier"]})
    origin = request.headers.get("Origin")
    # VULNERABLE: this regex has no end-anchor ($), so re.match only
    # requires the STRING TO START WITH "https://" followed by anything,
    # then contain "example.com" anywhere after that -- it never confirms
    # the origin actually ENDS at example.com. "https://evilexample.com"
    # satisfies "https://" + ".*" + "example.com" just as validly as the
    # real "https://partner.example.com" does.
    if origin and PARTNER_PORTAL_ORIGIN_PATTERN.match(origin):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


@a05_bp.route("/cors-origin-regex-bypass")
def cors_origin_regex_bypass():
    # This is the example's own explanation/exploitation page -- separate
    # from the vulnerable JSON API above (partner_portal_api), matching
    # the established convention this app already uses for cors-credentials
    # (its own HTML page) vs. loyalty_status_api (the vulnerable JSON API
    # it demonstrates). ExampleNav.endpoint always points at the HTML
    # page, never directly at a raw JSON route, so the app's standard
    # explanation UI and "mark as done" flow both work.
    return render_template("a05_security_misconfiguration/cors_origin_regex_bypass.html")
```

- [ ] **Step 4: Create `cors_origin_regex_bypass.html`**

Create `app/categories/a05_security_misconfiguration/templates/a05_security_misconfiguration/cors_origin_regex_bypass.html`:

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "CORS: Origin Allowlist Regex Bypass" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A05{% endblock %}

{% block explanation %}
<p>
  This "partner portal" API is meant to allow only genuine
  <code>https://partner.example.com</code>-style origins, checked with
  the regular expression <code>https://.*example\.com</code>. The
  pattern has no end-anchor (<code>$</code>), so it only requires the
  origin to start with <code>https://</code> and contain
  <code>example.com</code> <em>somewhere</em> after that — it never
  confirms the origin actually <em>ends</em> at <code>example.com</code>.
</p>
{% endblock %}

{% block detect %}
<p>
  Try an origin that contains the trusted domain as a substring but
  isn't actually that domain — e.g. <code>https://evilexample.com</code>
  (no dot between "evil" and "example"). If it's accepted, the allowlist
  regex isn't properly anchored.
</p>
{% endblock %}

{% block exploitation %}
<pre><code class="language-bash">curl -s http://127.0.0.1:5001/a05/api/partner-portal -H "Origin: https://evilexample.com"</code></pre>
<p>
  The response reflects
  <code>Access-Control-Allow-Origin: https://evilexample.com</code> with
  <code>Access-Control-Allow-Credentials: true</code>, even though
  <code>evilexample.com</code> is not a real partner domain — a regex
  meant to match only <code>example.com</code> matches anything
  <em>containing</em> that substring after the scheme, with nothing
  requiring the string to actually end there. An attacker who registers
  any domain ending in <code>example.com</code> as a substring (or, with
  a different unescaped-dot variant of this same bug, a domain like
  <code>apiXexample.com</code> where the dot in the pattern was never
  escaped) gains a fully credentialed cross-origin channel to this API.
</p>
{% endblock %}

{% block vulnerable_code %}PARTNER_PORTAL_ORIGIN_PATTERN = re.compile(r"https://.*example\.com")

origin = request.headers.get("Origin")
# VULNERABLE: no end-anchor ($) -- matches "https://evilexample.com" just
# as validly as "https://partner.example.com"
if origin and PARTNER_PORTAL_ORIGIN_PATTERN.match(origin):
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
{% endblock %}

{% block secure_code %}PARTNER_PORTAL_ORIGIN_PATTERN = re.compile(r"^https://([a-z0-9-]+\.)?example\.com$")

origin = request.headers.get("Origin")
# Anchored at both ends, and the subdomain segment can't contain a
# literal dot itself -- "evilexample.com" and "apiXexample.com" both fail
if origin and PARTNER_PORTAL_ORIGIN_PATTERN.match(origin):
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
{% endblock %}

{% block live_example %}
<p class="text-muted">
  This is a JSON API endpoint with no HTML form — use curl as shown in
  the Exploitation section above:
  <code>GET /a05/api/partner-portal</code> with a forged
  <code>Origin</code> header.
</p>
{% endblock %}
```

- [ ] **Step 5: Add the `ExampleNav` entry**

Modify `app/categories/a05_security_misconfiguration/__init__.py`. Find
the `cors-wildcard-internal-pivot` entry (added by Task 7), followed by
whatever now comes after it (`debug-console-rce`, unless Task 7 landed
differently — re-read the real current file):

```python
            ExampleNav(
                id="cors-wildcard-internal-pivot",
                title="CORS: Wildcard Origin, Internal Network Pivot",
                group="Insecure Response Configuration",
                difficulty="Medium",
                endpoint="a05_security_misconfiguration.cors_wildcard_internal_pivot",
                hints=[
                    "This 'internal metrics' endpoint has a wildcard CORS header. A wildcard blocks cookies from being attached — so what OTHER protection would need to be missing for that to still matter?",
                    "The endpoint requires no authentication at all — no session, no API key. A wildcard CORS header combined with zero auth means any external page's JavaScript can read this response directly.",
                    "curl -s http://127.0.0.1:5000/a05/api/internal-metrics -H 'Origin: https://evil.com' — the response includes Access-Control-Allow-Origin: * and real internal metrics data, with no authentication required at all.",
                    "This is the 'internal network pivot' variant: in a real deployment this endpoint would sit on a network segment unreachable from the internet, but a victim's browser inside that network can be made to fetch() it on an attacker's behalf via a page the victim merely visits — the missing auth check is the real bug, and the wildcard CORS header is what lets the cross-origin request through.",
                ],
            ),
            ExampleNav(
                id="debug-console-rce",
```

Insert immediately after it (before `debug-console-rce`):

```python
            ExampleNav(
                id="cors-wildcard-internal-pivot",
                title="CORS: Wildcard Origin, Internal Network Pivot",
                group="Insecure Response Configuration",
                difficulty="Medium",
                endpoint="a05_security_misconfiguration.cors_wildcard_internal_pivot",
                hints=[
                    "This 'internal metrics' endpoint has a wildcard CORS header. A wildcard blocks cookies from being attached — so what OTHER protection would need to be missing for that to still matter?",
                    "The endpoint requires no authentication at all — no session, no API key. A wildcard CORS header combined with zero auth means any external page's JavaScript can read this response directly.",
                    "curl -s http://127.0.0.1:5000/a05/api/internal-metrics -H 'Origin: https://evil.com' — the response includes Access-Control-Allow-Origin: * and real internal metrics data, with no authentication required at all.",
                    "This is the 'internal network pivot' variant: in a real deployment this endpoint would sit on a network segment unreachable from the internet, but a victim's browser inside that network can be made to fetch() it on an attacker's behalf via a page the victim merely visits — the missing auth check is the real bug, and the wildcard CORS header is what lets the cross-origin request through.",
                ],
            ),
            ExampleNav(
                id="cors-origin-regex-bypass",
                title="CORS: Origin Allowlist Regex Bypass",
                group="Insecure Response Configuration",
                difficulty="Hard",
                endpoint="a05_security_misconfiguration.cors_origin_regex_bypass",
                hints=[
                    "This API is meant to trust only real partner.example.com-style origins. Try an origin that CONTAINS the trusted domain as a substring but isn't actually a subdomain of it — e.g. https://evilexample.com.",
                    "The origin-validation regex has no end-anchor — it only checks that the origin starts with https:// and contains example.com somewhere after that, never that it actually ENDS there.",
                    "curl -s http://127.0.0.1:5000/a05/api/partner-portal -H 'Origin: https://evilexample.com' — the response reflects that origin with credentials enabled, even though evilexample.com was never a real partner domain.",
                    "This is the 'Expanding the Origin' technique: a badly implemented regular expression intended to validate an origin allowlist accepts substrings or prefixes it shouldn't, because the pattern was never anchored to the full string. A real attacker just needs to register any domain containing the trusted substring.",
                ],
            ),
            ExampleNav(
                id="debug-console-rce",
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `.venv/bin/pytest tests/test_a05_cors_origin_regex_bypass.py -v`
Expected: PASS (4 passed)

- [ ] **Step 7: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass, updating cross-cutting files (`test_a05_hints.py` →
10, `test_all_examples_have_hints.py` → 86, `test_hints.py` → 1780
[+30]). New total: 529 (525 + 4 new). This is the last A05 task — all
10 examples registered.

- [ ] **Step 8: Commit**

```bash
git add app/categories/a05_security_misconfiguration tests/test_a05_cors_origin_regex_bypass.py tests/test_a05_hints.py tests/test_a05_overview.py tests/test_all_examples_have_hints.py tests/test_hints.py
git commit -m "feat(a05): add cors-origin-allowlist-regex-bypass example

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 9: Final Integration — Nav/Grouping Tests, Hints-Count Total, README

**Files:**
- Modify: `tests/test_a04_overview.py`
- Modify: `tests/test_a05_overview.py`
- Modify: `tests/test_all_examples_have_hints.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: the final `ExampleNav` lists produced by Tasks 1-8 (this task
  makes no code changes to any category — it only updates tests and docs
  to match what Tasks 1-8 actually registered).
- Produces: nothing new. This is the last task in the plan.

**Important — read before starting:** the prior PayloadsAllTheThings
round's own Task 9 discovered that every earlier task in that round had
already incrementally fixed the exact cross-cutting test files this task
targets, as a normal side effect of keeping its own commit's test suite
green (each new hinted example changes `test_aNN_overview.py`'s
difficulty-list/grouped-by-subtype assertions and
`test_all_examples_have_hints.py`'s running total). **Tasks 1-8 in THIS
plan are instructed to do the exact same thing** (see each task's Step 7
noting the expected cross-cutting file changes). By the time you start
this task, `tests/test_a04_overview.py`, `tests/test_a05_overview.py`,
and `tests/test_all_examples_have_hints.py` may ALREADY be fully correct
— **verify by running them first; only edit what's actually wrong.** Do
not blindly reapply the "Current file" old_string blocks below if the
file has already moved past that state — locate content by searching for
the real current text, or by reading `app/core/nav.py`'s live
`CATEGORIES` contents as ground truth if you're unsure what the correct
final assertion should be.

This task assumes Tasks 1-8 landed in order and produced exactly the
following final states. If any earlier task's actual landed result
differs from what its own plan text specified, reconcile these
assertions against the real `app/core/nav.py` `CATEGORIES` contents
rather than the numbers below.

- [ ] **Step 1: Verify (and fix only if wrong) `tests/test_a04_overview.py`**

Run: `.venv/bin/pytest tests/test_a04_overview.py -v` first. If it
already passes and its assertions already match the shape below, skip to
Step 2.

The final, correct state of the two nav-related test functions:

```python
def test_a04_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a04 = next(c for c in CATEGORIES if c.id == "a04_insecure_design")
    assert a04.short_id == "A04"
    assert [e.difficulty for e in a04.examples] == [
        "Easy",
        "Easy",
        "Medium",
        "Medium",
        "Medium",
        "Hard",
        "Hard",
        "Medium",
        "Hard",
    ]


def test_a04_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a04 = next(c for c in CATEGORIES if c.id == "a04_insecure_design")
    grouped = a04.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Business Logic Abuse",
        "Workflow Bypass",
        "Password Reset Design Flaws",
        "Premium Access Design Flaws",
        "Rounding & Arithmetic Errors",
    ]
    assert [e.id for e in grouped[0][1]] == [
        "unlimited-coupon",
        "free-shipping-trusted-flag",
        "negative-quantity",
        "overselling-no-stock-check",
        "discount-stacking",
    ]
    assert [e.id for e in grouped[1][1]] == ["checkout-bypass"]
    assert [e.id for e in grouped[2][1]] == ["host-header-reset-poisoning"]
    assert [e.id for e in grouped[3][1]] == ["premium-access-after-cancel"]
    assert [e.id for e in grouped[4][1]] == ["rounding-exploit"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a04_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a04/")
    body = response.data.decode()
    assert "Business Logic Abuse" in body
    assert "Workflow Bypass" in body
    assert "Password Reset Design Flaws" in body
    assert "Premium Access Design Flaws" in body
    assert "Rounding & Arithmetic Errors" in body
```

- [ ] **Step 2: Verify (and fix only if wrong) `tests/test_a05_overview.py`**

Run: `.venv/bin/pytest tests/test_a05_overview.py -v` first. If it
already passes and its assertions already match the shape below, skip to
Step 3.

The final, correct state of the two nav-related test functions:

```python
def test_a05_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a05 = next(c for c in CATEGORIES if c.id == "a05_security_misconfiguration")
    assert a05.short_id == "A05"
    assert [e.difficulty for e in a05.examples] == [
        "Easy",
        "Easy",
        "Medium",
        "Medium",
        "Medium",
        "Medium",
        "Hard",
        "Hard",
        "Hard",
        "Easy",
    ]


def test_a05_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a05 = next(c for c in CATEGORIES if c.id == "a05_security_misconfiguration")
    grouped = a05.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Exposed Files & Directories",
        "Insecure Response Configuration",
        "Exposed Debug & Admin Interfaces",
        "Missing Security Headers",
    ]
    assert [e.id for e in grouped[0][1]] == ["exposed-backup", "directory-listing"]
    assert [e.id for e in grouped[1][1]] == [
        "verbose-errors",
        "cors-credentials",
        "cors-null-origin",
        "cors-wildcard-internal-pivot",
        "cors-origin-regex-bypass",
    ]
    assert [e.id for e in grouped[2][1]] == ["debug-console-rce", "default-admin-creds"]
    assert [e.id for e in grouped[3][1]] == ["clickjacking-delete-account"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a05_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a05/")
    body = response.data.decode()
    # Group names contain "&", which Jinja2's default HTML autoescaping
    # (Flask's standard, secure behavior for .html templates) renders as
    # "&amp;" -- assert against the actual escaped output.
    assert "Exposed Files &amp; Directories" in body
    assert "Insecure Response Configuration" in body
    assert "Exposed Debug &amp; Admin Interfaces" in body
    assert "Missing Security Headers" in body
```

**If the actual landed order from Tasks 6-8 differs from the sequence
above** (e.g. a fix round changed an insertion point), update these
assertions to match the real `CATEGORIES` contents rather than force the
code to match this test — internal group Easy→Hard sortedness (verified
by the `difficulty_rank` loop) is the actual hard requirement, not this
exact literal id sequence.

- [ ] **Step 3: Verify (and fix only if wrong) `tests/test_all_examples_have_hints.py`**

Run: `.venv/bin/pytest tests/test_all_examples_have_hints.py -v` first.
If it already asserts `total == 86`, skip to Step 4.

The final assertion must read:

```python
    assert total == 86
```

(78 existing + 5 A04 + 3 A05 = 86.)

- [ ] **Step 4: Update `README.md`'s intro paragraph**

Modify the "Currently implemented" paragraph. Find (A04 clause):

```
**A04 Insecure Design** (unlimited coupon reuse, negative-quantity price manipulation,
multi-step checkout bypass, password-reset poisoning via the Host header),
```

Replace with:

```
**A04 Insecure Design** (unlimited coupon reuse, negative-quantity price manipulation,
multi-step checkout bypass, password-reset poisoning via the Host header,
free shipping via a client-trusted flag, overselling with no stock-limit
check, discount-code stacking via parameter pollution, premium access
persisting after cancellation, a store-credit rounding exploit),
```

Find (A05 clause):

```
**A05 Security Misconfiguration** (exposed database backup,
directory listing, verbose error disclosure, permissive CORS with credentials, exposed
debug console, forgotten admin panel with default credentials, clickjacking on a
sensitive action page), **A06 Vulnerable
```

Replace with:

```
**A05 Security Misconfiguration** (exposed database backup,
directory listing, verbose error disclosure, permissive CORS with credentials, exposed
debug console, forgotten admin panel with default credentials, clickjacking on a
sensitive action page, CORS null-origin whitelisting, CORS wildcard-origin
internal-network pivot, CORS origin-allowlist regex bypass), **A06 Vulnerable
```

- [ ] **Step 5: Update `README.md`'s category summary table**

Modify the table rows for A04 and A05. Find:

```
| A04 Insecure Design | Implemented | Unlimited Coupon Reuse (Easy), Negative Quantity Price Manipulation (Medium), Multi-Step Checkout Bypass (Hard), Password Reset Poisoning via Host Header (Hard) |
| A05 Security Misconfiguration | Implemented | Exposed Database Backup File (Easy), Directory Listing Exposed (Easy), Verbose Error Message Disclosure (Medium), Permissive CORS with Credentials (Medium), Exposed Debug Console (Hard), Forgotten Admin Panel with Default Credentials (Hard), Clickjacking on a Sensitive Action Page (Easy) |
```

Replace with:

```
| A04 Insecure Design | Implemented | Unlimited Coupon Reuse (Easy), Free Shipping via Client-Trusted Flag (Easy), Negative Quantity Price Manipulation (Medium), Overselling — No Stock-Limit Check (Medium), Discount Code Stacking via Parameter Pollution (Medium), Multi-Step Checkout Bypass (Hard), Password Reset Poisoning via Host Header (Hard), Premium Access Persists After Cancellation (Medium), Store-Credit Rounding Exploit (Hard) |
| A05 Security Misconfiguration | Implemented | Exposed Database Backup File (Easy), Directory Listing Exposed (Easy), Verbose Error Message Disclosure (Medium), Permissive CORS with Credentials (Medium), CORS: Null Origin Whitelisted (Medium), CORS: Wildcard Origin, Internal Network Pivot (Medium), CORS: Origin Allowlist Regex Bypass (Hard), Exposed Debug Console (Hard), Forgotten Admin Panel with Default Credentials (Hard), Clickjacking on a Sensitive Action Page (Easy) |
```

- [ ] **Step 6: Run the full test suite**

Run: `.venv/bin/pytest tests/ -q`
Expected: all pass, 529 (running total through Task 8). Reconcile this
number against the actual collected count —
`.venv/bin/pytest tests/ -q --collect-only 2>&1 | tail -1` — if any
earlier task's implementer added or removed a test during a fix round;
the exact number is a sanity check, not a hard requirement.

- [ ] **Step 7: Verify the app still boots and the nav renders end-to-end**

Run: `.venv/bin/python -c "from app import create_app; app = create_app(); client = app.test_client(); [print(r.status_code, r.request.path) for r in [client.get('/a04/'), client.get('/a05/')]]"`
Expected: both print `200 /a0N/`.

- [ ] **Step 8: Commit**

```bash
git add tests/test_a04_overview.py tests/test_a05_overview.py tests/test_all_examples_have_hints.py README.md
git commit -m "test(nav): update grouping/hints-count tests and README for 8 new Business Logic Errors and CORS Misconfiguration examples

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---
