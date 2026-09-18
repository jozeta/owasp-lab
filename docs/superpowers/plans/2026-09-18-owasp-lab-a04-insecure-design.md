# A04 Insecure Design Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the fourth OWASP category — A04 Insecure Design — to the training lab: an Overview page plus three graduated, genuinely exploitable examples that demonstrate missing business-logic enforcement rather than a coding bug: unlimited coupon reuse (Easy), negative-quantity price manipulation (Medium), and a multi-step checkout that can be completed without ever paying (Hard).

**Architecture:** A new Flask Blueprint (`app/categories/a04_insecure_design`) following the exact reference pattern A01/A02/A03 established. Unlike prior categories, A04's Easy and Medium examples need NO database model at all — they're pure session-state bugs against a single hardcoded demo product and coupon code, mirroring how A02/A03 hardcoded their vulnerable constants (AES key, reset-token salt) directly in `routes.py` rather than modeling them as DB data. Only the Hard example needs a model (`Order`, to persist "confirmed" orders so `db.drop_all()`/`create_all()` on "Reset lab" correctly clears any fraudulent ones created during the demo — the same mechanism every prior category's reset already relies on, no core changes needed). All three examples are public (no login required), consistent with A02/A03.

**Tech Stack:** Same as the existing app (Flask 3, Flask-SQLAlchemy, pytest). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-18-owasp-lab-design.md`

**Prior work this builds on:** `docs/superpowers/plans/2026-09-18-owasp-lab-scaffold-core-a01.md`, `docs/superpowers/plans/2026-09-18-owasp-lab-a02-crypto-failures.md`, `docs/superpowers/plans/2026-09-18-owasp-lab-a03-injection.md` (all merged to `main`) — read `app/categories/a03_injection/` for the most recent reference pattern this plan mirrors.

## Global Constraints

- App must bind only to `127.0.0.1` on the host (already true — no docker-compose/Dockerfile changes in this plan).
- Only synthetic/dummy data.
- Settings toggles (`show_explanations`, `show_exploit_instructions`) apply to every example page, independently gated, and hiding them must never disable the underlying vulnerability. Every example task in this plan includes its own "still works with both toggles off" regression test from the start (the standard established during A02's final review and carried through A03).
- No shared fictional brand across categories — A04's single demo product/coupon is self-contained to this category.
- `app/core` must never contain vulnerable logic — all of this plan's vulnerable code lives in `app/categories/a04_insecure_design`.
- Easy/Medium examples are pure Flask-session state (`session["a04_..."]`) against hardcoded constants — no database writes, no seed data needed for them. Only the Hard example writes to the database (`Order` rows), and needs no `seed_fn` either (orders are created dynamically by visiting the routes, not pre-seeded) — `reset_database()`'s existing `db.drop_all()`/`create_all()` step already clears the `Order` table on every reset regardless, since it operates on the whole SQLAlchemy metadata, not per-category seed hooks.
- None of A04's three example endpoints take URL parameters, so the existing `registered_endpoints` self-resolving nav guard needs no special zero-arg routing workaround (the lesson from A01's `idor`).

---

### Task 1: A04 blueprint scaffold + Overview page

**Files:**
- Create: `app/categories/a04_insecure_design/__init__.py`
- Create: `app/categories/a04_insecure_design/routes.py`
- Create: `app/categories/a04_insecure_design/templates/a04_insecure_design/overview.html`
- Modify: `app/__init__.py`
- Create: `tests/test_a04_overview.py`

**Interfaces:**
- Consumes: `CATEGORIES`, `CategoryNav`, `ExampleNav` (`app/core/nav.py`); `core/overview_base.html`.
- Produces: `a04_bp` Blueprint mounted at `/a04` with route `a04_insecure_design.overview` (GET `/a04/`); appends A04's `CategoryNav` (3 examples, endpoints `a04_insecure_design.coupon_cart`, `a04_insecure_design.quantity_cart`, `a04_insecure_design.checkout_shipping` — added in Tasks 2–4) to `CATEGORIES` on import.

- [ ] **Step 1: Write the failing test**

`tests/test_a04_overview.py`:
```python
def test_a04_overview_renders(client):
    response = client.get("/a04/")
    assert response.status_code == 200
    assert b"Insecure Design" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a04_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a04 = next(c for c in CATEGORIES if c.id == "a04_insecure_design")
    assert a04.short_id == "A04"
    assert [e.difficulty for e in a04.examples] == ["Easy", "Medium", "Hard"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a04_overview.py -v`
Expected: FAIL with 404 on `/a04/`.

- [ ] **Step 3: Write `app/categories/a04_insecure_design/__init__.py`**

```python
from flask import Blueprint

a04_bp = Blueprint(
    "a04_insecure_design", __name__, template_folder="templates", url_prefix="/a04"
)

from app.categories.a04_insecure_design import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a04_insecure_design",
        short_id="A04",
        title="Insecure Design",
        blueprint_name="a04_insecure_design",
        overview_endpoint="a04_insecure_design.overview",
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
    )
)
```

- [ ] **Step 4: Write `app/categories/a04_insecure_design/routes.py`**

```python
from flask import render_template

from app.categories.a04_insecure_design import a04_bp


@a04_bp.route("/")
def overview():
    return render_template("a04_insecure_design/overview.html")
```

(routes for `coupon_cart`, `quantity_cart`, `checkout_shipping`/`checkout_payment`/`checkout_confirm` are added in Tasks 2–4)

- [ ] **Step 5: Write `app/categories/a04_insecure_design/templates/a04_insecure_design/overview.html`**

```html
{% extends "core/overview_base.html" %}
{% set category_short_id = "A04" %}
{% set category_title = "Insecure Design" %}
{% block title %}A04: Insecure Design{% endblock %}

{% block what_it_is %}
<p>
  Insecure Design covers flaws that exist in the blueprint of an application, not just
  bugs in its implementation — missing rate limits, business rules that were never
  actually enforced on the server, and multi-step workflows that assume users (and
  attackers) will only ever interact with them in the intended order.
</p>
{% endblock %}

{% block why_it_matters %}
<p>
  Unlike a typo'd SQL query or a missing escape call, these flaws often can't be patched
  with a single line of code — they require rethinking how the feature was designed in
  the first place: what state the server tracks, what it validates, and what it assumes
  the client will never attempt.
</p>
{% endblock %}

{% block how_exploited %}
<p>
  Attackers look for the gap between what a UI shows and what the server actually
  enforces: a coupon field with no usage counter behind it, a quantity input with no
  lower bound, a "confirm" page reachable without ever completing the steps before it.
  None of these require special tools — just noticing what the server forgot to check.
</p>
{% endblock %}

{% block attack_flow_diagram %}
sequenceDiagram
    participant Attacker
    participant App as Vulnerable App
    Attacker->>App: Repeat an action, submit an out-of-range value, or skip a step
    Note over App: No server-side usage limit, bounds check, or workflow-state enforcement
    App-->>Attacker: Accepts it anyway, as if every rule had been followed
{% endblock %}

{% block real_world_impact %}
<p>
  Real incidents in this category include discount codes stacked into free orders at
  scale, shopping carts manipulated into negative totals that issued real refunds, and
  checkout flows completed without payment ever being captured — all without a single
  line of "hacking" in the traditional sense.
</p>
{% endblock %}

{% block vulnerable_code %}@app.route("/checkout/confirm")
def confirm():
    return render_template("confirm.html")
    # No check that payment actually happened first.
{% endblock %}

{% block secure_code %}@app.route("/checkout/confirm")
def confirm():
    if not session.get("payment_completed"):
        abort(403)
    return render_template("confirm.html")
{% endblock %}
```

- [ ] **Step 6: Modify `app/__init__.py`** — register the A04 blueprint after the A03 registration

```python
    from app.categories.a03_injection import a03_bp

    app.register_blueprint(a03_bp)

    from app.categories.a04_insecure_design import a04_bp

    app.register_blueprint(a04_bp)

    @app.route("/healthz")
```

- [ ] **Step 7: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass (including the two new A04 tests), 0 warnings, and the full previous suite (A01 + A02 + A03 + framework) stays green.

- [ ] **Step 8: Commit**

```bash
git add app/categories/a04_insecure_design app/__init__.py tests/test_a04_overview.py
git commit -m "feat: add A04 blueprint scaffold and overview page"
```

---

### Task 2: A04 Easy — Unlimited Coupon Reuse

**Files:**
- Modify: `app/categories/a04_insecure_design/routes.py`
- Create: `app/categories/a04_insecure_design/templates/a04_insecure_design/coupon_cart.html`
- Create: `tests/test_a04_coupon_cart.py`

**Interfaces:**
- Produces: `DEMO_PRODUCT_NAME`, `DEMO_PRODUCT_PRICE_CENTS`, `COUPON_CODE`, `COUPON_DISCOUNT_CENTS` (module constants) and `_format_cents(cents: int) -> str` (helper, e.g. `2999 -> "$29.99"`, `-2999 -> "-$29.99"`) in `app.categories.a04_insecure_design.routes` — reused by Tasks 3 and 4. Routes `a04_insecure_design.coupon_cart` (GET/POST `/a04/coupon-cart`) and `a04_insecure_design.coupon_cart_reset` (POST `/a04/coupon-cart/reset`), no login required.

- [ ] **Step 1: Write the failing test**

`tests/test_a04_coupon_cart.py`:
```python
def test_coupon_cart_shows_product(client):
    response = client.get("/a04/coupon-cart")
    assert response.status_code == 200
    assert b"Wireless Mouse" in response.data


def test_coupon_cart_rejects_invalid_code(client):
    response = client.post("/a04/coupon-cart", data={"code": "NOTREAL"})
    assert response.status_code == 200
    assert b"Invalid coupon code" in response.data


def test_coupon_cart_unlimited_reuse_drives_price_to_zero(client):
    response = None
    for _ in range(6):
        response = client.post("/a04/coupon-cart", data={"code": "WELCOME10"})
    assert response.status_code == 200
    assert b"Total: $0.00" in response.data


def test_coupon_cart_reset_clears_usage_count(client):
    client.post("/a04/coupon-cart", data={"code": "WELCOME10"})
    client.post("/a04/coupon-cart/reset")
    response = client.get("/a04/coupon-cart")
    assert response.status_code == 200
    assert b"applied 0 time" in response.data


def test_coupon_cart_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = None
    for _ in range(6):
        response = client.post("/a04/coupon-cart", data={"code": "WELCOME10"})
    assert response.status_code == 200
    assert b"Total: $0.00" in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_coupon_cart_link_appears_in_overview_once_registered(client):
    response = client.get("/a04/")
    assert response.status_code == 200
    assert b"Unlimited Coupon Reuse" in response.data
    assert b'href="/a04/coupon-cart"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a04_coupon_cart.py -v`
Expected: FAIL with 404 on `/a04/coupon-cart`.

- [ ] **Step 3: Modify `app/categories/a04_insecure_design/routes.py`** — add imports, constants, the helper, and the two routes

```python
from flask import redirect, render_template, request, session, url_for

from app.categories.a04_insecure_design import a04_bp

DEMO_PRODUCT_NAME = "Wireless Mouse"
DEMO_PRODUCT_PRICE_CENTS = 2999
COUPON_CODE = "WELCOME10"
COUPON_DISCOUNT_CENTS = 500


def _format_cents(cents):
    sign = "-" if cents < 0 else ""
    return f"{sign}${abs(cents) / 100:.2f}"


@a04_bp.route("/")
def overview():
    return render_template("a04_insecure_design/overview.html")


@a04_bp.route("/coupon-cart", methods=["GET", "POST"])
def coupon_cart():
    error = None
    if request.method == "POST":
        submitted_code = request.form.get("code", "").strip()
        if submitted_code == COUPON_CODE:
            # VULNERABLE: no check for whether this coupon was already applied --
            # every submission stacks another discount, with no usage limit at all.
            session["a04_coupon_uses"] = session.get("a04_coupon_uses", 0) + 1
        else:
            error = "Invalid coupon code."
    uses = session.get("a04_coupon_uses", 0)
    discount_cents = uses * COUPON_DISCOUNT_CENTS
    total_cents = max(0, DEMO_PRODUCT_PRICE_CENTS - discount_cents)
    return render_template(
        "a04_insecure_design/coupon_cart.html",
        product_name=DEMO_PRODUCT_NAME,
        product_price_display=_format_cents(DEMO_PRODUCT_PRICE_CENTS),
        uses=uses,
        discount_display=_format_cents(discount_cents),
        total_display=_format_cents(total_cents),
        error=error,
    )


@a04_bp.route("/coupon-cart/reset", methods=["POST"])
def coupon_cart_reset():
    session.pop("a04_coupon_uses", None)
    return redirect(url_for("a04_insecure_design.coupon_cart"))
```

(the `overview` route above stays unchanged)

- [ ] **Step 4: Write `app/categories/a04_insecure_design/templates/a04_insecure_design/coupon_cart.html`**

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Unlimited Coupon Reuse" %}
{% set example_difficulty = "Easy" %}
{% block title %}{{ example_title }} — A04{% endblock %}

{% block explanation %}
<p>
  This cart accepts a one-time "WELCOME10" discount code — but the server never records
  that the code has already been used. There's no rate limiting, no usage counter, no
  "already applied" check of any kind. Every time you submit the same code, it stacks
  another discount on top of the last one.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Enter the coupon code <code>WELCOME10</code> and submit it.</li>
  <li>Submit the exact same code again. And again.</li>
  <li>Each submission knocks another $5.00 off the price — keep going and the
      $29.99 mouse becomes free.</li>
</ol>
{% endblock %}

{% block live_example %}
<div class="card mb-3">
  <div class="card-body">
    <h5 class="card-title">{{ product_name }}</h5>
    <p class="card-text">Price: {{ product_price_display }}</p>
    <p class="card-text">Coupon applied {{ uses }} time(s) — total discount {{ discount_display }}</p>
    <p class="card-text"><strong>Total: {{ total_display }}</strong></p>
  </div>
</div>
{% if error %}
<div class="alert alert-danger">{{ error }}</div>
{% endif %}
<form method="post" class="d-flex gap-2 mb-2">
  <input type="text" class="form-control" name="code" placeholder="Coupon code">
  <button type="submit" class="btn btn-primary">Apply</button>
</form>
<form method="post" action="{{ url_for('a04_insecure_design.coupon_cart_reset') }}">
  <button type="submit" class="btn btn-outline-secondary btn-sm">Start over</button>
</form>
{% endblock %}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add app/categories/a04_insecure_design/routes.py \
  app/categories/a04_insecure_design/templates/a04_insecure_design/coupon_cart.html \
  tests/test_a04_coupon_cart.py
git commit -m "feat: add A04 Easy unlimited-coupon-reuse example"
```

---

### Task 3: A04 Medium — Negative Quantity Price Manipulation

**Files:**
- Modify: `app/categories/a04_insecure_design/routes.py`
- Create: `app/categories/a04_insecure_design/templates/a04_insecure_design/quantity_cart.html`
- Create: `tests/test_a04_quantity_cart.py`

**Interfaces:**
- Consumes: `DEMO_PRODUCT_NAME`, `DEMO_PRODUCT_PRICE_CENTS`, `_format_cents` (Task 2).
- Produces: route `a04_insecure_design.quantity_cart` (GET/POST `/a04/quantity-cart`), no login required.

- [ ] **Step 1: Write the failing test**

`tests/test_a04_quantity_cart.py`:
```python
def test_quantity_cart_default_quantity_is_one(client):
    response = client.get("/a04/quantity-cart")
    assert response.status_code == 200
    assert b"Total: $29.99" in response.data


def test_quantity_cart_negative_quantity_produces_negative_total(client):
    response = client.post("/a04/quantity-cart", data={"quantity": "-1"})
    assert response.status_code == 200
    assert b"Total: -$29.99" in response.data


def test_quantity_cart_negative_quantity_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post("/a04/quantity-cart", data={"quantity": "-1"})
    assert response.status_code == 200
    assert b"Total: -$29.99" in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_quantity_cart_link_appears_in_overview_once_registered(client):
    response = client.get("/a04/")
    assert response.status_code == 200
    assert b"Negative Quantity Price Manipulation" in response.data
    assert b'href="/a04/quantity-cart"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a04_quantity_cart.py -v`
Expected: FAIL with 404 on `/a04/quantity-cart`.

- [ ] **Step 3: Modify `app/categories/a04_insecure_design/routes.py`** — add the `quantity_cart` route (no new imports needed — `request`, `session`, `render_template` are already imported from Task 2)

```python
@a04_bp.route("/quantity-cart", methods=["GET", "POST"])
def quantity_cart():
    if request.method == "POST":
        try:
            quantity = int(request.form.get("quantity", "1"))
        except ValueError:
            quantity = 1
        # VULNERABLE: no validation that quantity is non-negative or has a sane upper bound
        session["a04_quantity"] = quantity
    quantity = session.get("a04_quantity", 1)
    total_cents = DEMO_PRODUCT_PRICE_CENTS * quantity
    return render_template(
        "a04_insecure_design/quantity_cart.html",
        product_name=DEMO_PRODUCT_NAME,
        product_price_display=_format_cents(DEMO_PRODUCT_PRICE_CENTS),
        quantity=quantity,
        total_display=_format_cents(total_cents),
    )
```

(add this after the `coupon_cart`/`coupon_cart_reset` routes; those and `overview` stay unchanged)

- [ ] **Step 4: Write `app/categories/a04_insecure_design/templates/a04_insecure_design/quantity_cart.html`**

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Negative Quantity Price Manipulation" %}
{% set example_difficulty = "Medium" %}
{% block title %}{{ example_title }} — A04{% endblock %}

{% block explanation %}
<p>
  This cart lets you set the quantity for an item directly, and the total is computed as
  <code>quantity × price</code> with no check that quantity is a sane, positive number.
  Submit a negative quantity and the "total" goes negative too — as if the store owed
  you money instead of the other way around.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>Set the quantity field to <code>-1</code> and submit.</li>
  <li>The total now reads <code>-$29.99</code> — a negative charge that a real payment
      processor might interpret as a refund.</li>
</ol>
{% endblock %}

{% block live_example %}
<div class="card mb-3">
  <div class="card-body">
    <h5 class="card-title">{{ product_name }}</h5>
    <p class="card-text">Price: {{ product_price_display }}</p>
    <p class="card-text">Quantity: {{ quantity }}</p>
    <p class="card-text"><strong>Total: {{ total_display }}</strong></p>
  </div>
</div>
<form method="post" class="d-flex gap-2">
  <input type="number" class="form-control" name="quantity" value="{{ quantity }}">
  <button type="submit" class="btn btn-primary">Update quantity</button>
</form>
{% endblock %}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add app/categories/a04_insecure_design/routes.py \
  app/categories/a04_insecure_design/templates/a04_insecure_design/quantity_cart.html \
  tests/test_a04_quantity_cart.py
git commit -m "feat: add A04 Medium negative-quantity example"
```

---

### Task 4: A04 Hard — Multi-Step Checkout Bypass

**Files:**
- Create: `app/categories/a04_insecure_design/models.py`
- Modify: `app/categories/a04_insecure_design/routes.py`
- Create: `app/categories/a04_insecure_design/templates/a04_insecure_design/checkout_shipping.html`
- Create: `app/categories/a04_insecure_design/templates/a04_insecure_design/checkout_payment.html`
- Create: `app/categories/a04_insecure_design/templates/a04_insecure_design/checkout_confirm.html`
- Create: `tests/test_a04_checkout.py`

**Interfaces:**
- Consumes: `DEMO_PRODUCT_PRICE_CENTS`, `_format_cents` (Task 2).
- Produces: `Order` model (`id`, `total_cents`, `paid`) in `app.categories.a04_insecure_design.models`; routes `a04_insecure_design.checkout_shipping` (GET/POST `/a04/checkout/shipping` — this is the example's registered entry point), `a04_insecure_design.checkout_payment` (GET/POST `/a04/checkout/payment`), `a04_insecure_design.checkout_confirm` (GET `/a04/checkout/confirm`). No login required. No `seed_fn` needed — `Order` rows are created dynamically, not pre-seeded, and `reset_database()`'s existing `db.drop_all()`/`create_all()` already clears them on every reset.

- [ ] **Step 1: Write the failing test**

`tests/test_a04_checkout.py`:
```python
from app.categories.a04_insecure_design.models import Order


def test_checkout_full_flow_creates_paid_order(app, client):
    client.post("/a04/checkout/shipping", data={"address": "123 Demo St"})
    client.post("/a04/checkout/payment")
    response = client.get("/a04/checkout/confirm")
    assert response.status_code == 200
    assert b"Thank you for your order" in response.data

    with app.app_context():
        order = Order.query.order_by(Order.id.desc()).first()
        assert order.paid is True


def test_checkout_confirm_skips_shipping_and_payment_and_still_confirms(app, client):
    response = client.get("/a04/checkout/confirm")
    assert response.status_code == 200
    assert b"Thank you for your order" in response.data

    with app.app_context():
        order = Order.query.order_by(Order.id.desc()).first()
        assert order is not None
        assert order.paid is False


def test_checkout_bypass_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get("/a04/checkout/confirm")
    assert response.status_code == 200
    assert b"Thank you for your order" in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data

    with app.app_context():
        order = Order.query.order_by(Order.id.desc()).first()
        assert order.paid is False


def test_checkout_link_appears_in_overview_once_registered(client):
    response = client.get("/a04/")
    assert response.status_code == 200
    assert b"Multi-Step Checkout Bypass" in response.data
    assert b'href="/a04/checkout/shipping"' in response.data
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_a04_checkout.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.categories.a04_insecure_design.models'`.

- [ ] **Step 3: Write `app/categories/a04_insecure_design/models.py`**

```python
from app.extensions import db


class Order(db.Model):
    __tablename__ = "a04_orders"

    id = db.Column(db.Integer, primary_key=True)
    total_cents = db.Column(db.Integer, nullable=False)
    paid = db.Column(db.Boolean, nullable=False, default=False)
```

- [ ] **Step 4: Modify `app/categories/a04_insecure_design/routes.py`** — add imports and the three checkout routes

```python
from app.categories.a04_insecure_design.models import Order
from app.extensions import db


@a04_bp.route("/checkout/shipping", methods=["GET", "POST"])
def checkout_shipping():
    if request.method == "POST":
        session["a04_shipping_done"] = True
        return redirect(url_for("a04_insecure_design.checkout_payment"))
    return render_template("a04_insecure_design/checkout_shipping.html")


@a04_bp.route("/checkout/payment", methods=["GET", "POST"])
def checkout_payment():
    if request.method == "POST":
        order = Order(total_cents=DEMO_PRODUCT_PRICE_CENTS, paid=True)
        db.session.add(order)
        db.session.commit()
        session["a04_order_id"] = order.id
        return redirect(url_for("a04_insecure_design.checkout_confirm"))
    return render_template("a04_insecure_design/checkout_payment.html")


@a04_bp.route("/checkout/confirm")
def checkout_confirm():
    order_id = session.get("a04_order_id")
    if order_id:
        order = db.session.get(Order, order_id)
    else:
        # VULNERABLE: no verification that the shipping/payment steps ever ran --
        # visiting this URL directly still produces a "confirmed" order, unpaid.
        order = Order(total_cents=DEMO_PRODUCT_PRICE_CENTS, paid=False)
        db.session.add(order)
        db.session.commit()
        session["a04_order_id"] = order.id
    return render_template(
        "a04_insecure_design/checkout_confirm.html",
        order=order,
        total_display=_format_cents(order.total_cents),
    )
```

(add these after the `quantity_cart` route; `overview`, `coupon_cart`, `coupon_cart_reset`, `quantity_cart` stay unchanged)

- [ ] **Step 5: Write `app/categories/a04_insecure_design/templates/a04_insecure_design/checkout_shipping.html`**

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Multi-Step Checkout Bypass" %}
{% set example_difficulty = "Hard" %}
{% block title %}{{ example_title }} — A04{% endblock %}

{% block explanation %}
<p>
  This checkout has three steps: shipping, payment, and confirmation. The confirmation
  page is supposed to be the final reward for completing the first two — but nothing on
  the server actually checks that payment happened before confirming the order. The app
  trusts that visitors will follow the steps in order, instead of enforcing it.
</p>
{% endblock %}

{% block exploitation %}
<ol>
  <li>You could go through the normal flow below: Shipping → Payment → Confirm.</li>
  <li>Or skip straight to
      <a href="{{ url_for('a04_insecure_design.checkout_confirm') }}">the confirmation page</a>
      without ever visiting shipping or payment.</li>
  <li>Either way, you land on a "confirmed" order — but only the first path actually
      charged anything. The skipped order is created with <code>paid = False</code>.</li>
</ol>
{% endblock %}

{% block live_example %}
<form method="post">
  <p>Step 1 of 3: Shipping</p>
  <div class="mb-2">
    <label class="form-label">Shipping address</label>
    <input type="text" class="form-control" name="address" value="123 Demo St">
  </div>
  <button type="submit" class="btn btn-primary">Continue to payment</button>
</form>
{% endblock %}
```

- [ ] **Step 6: Write `app/categories/a04_insecure_design/templates/a04_insecure_design/checkout_payment.html`**

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Multi-Step Checkout Bypass" %}
{% set example_difficulty = "Hard" %}
{% block title %}Payment — A04{% endblock %}

{% block explanation %}
<p>See the <a href="{{ url_for('a04_insecure_design.checkout_shipping') }}">shipping step</a>
  for how this multi-step flow can be bypassed entirely.</p>
{% endblock %}

{% block exploitation %}
<p>Complete this step normally, or skip straight to
  <a href="{{ url_for('a04_insecure_design.checkout_confirm') }}">confirmation</a> instead.</p>
{% endblock %}

{% block live_example %}
<form method="post">
  <p>Step 2 of 3: Payment</p>
  <div class="mb-2">
    <label class="form-label">Card number</label>
    <input type="text" class="form-control" value="4242 4242 4242 4242" readonly>
  </div>
  <button type="submit" class="btn btn-primary">Pay and continue</button>
</form>
{% endblock %}
```

- [ ] **Step 7: Write `app/categories/a04_insecure_design/templates/a04_insecure_design/checkout_confirm.html`**

```html
{% extends "core/example_page_base.html" %}
{% set example_title = "Multi-Step Checkout Bypass" %}
{% set example_difficulty = "Hard" %}
{% block title %}Order Confirmed — A04{% endblock %}

{% block explanation %}
<p>See the <a href="{{ url_for('a04_insecure_design.checkout_shipping') }}">shipping step</a>
  for how this page can be reached without ever paying.</p>
{% endblock %}

{% block exploitation %}
<p>If you arrived here directly, notice the order below is marked
  <code>paid = False</code> below — the "confirmation" happened anyway.</p>
{% endblock %}

{% block live_example %}
<div class="alert alert-success">Thank you for your order!</div>
<p>Order #{{ order.id }} — total {{ total_display }} — paid: <strong>{{ order.paid }}</strong></p>
{% endblock %}
```

- [ ] **Step 8: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: all tests pass, 0 warnings — this is the full test suite for A04's scope.

- [ ] **Step 9: Commit**

```bash
git add app/categories/a04_insecure_design/models.py app/categories/a04_insecure_design/routes.py \
  app/categories/a04_insecure_design/templates/a04_insecure_design/checkout_shipping.html \
  app/categories/a04_insecure_design/templates/a04_insecure_design/checkout_payment.html \
  app/categories/a04_insecure_design/templates/a04_insecure_design/checkout_confirm.html \
  tests/test_a04_checkout.py
git commit -m "feat: add A04 Hard multi-step checkout bypass example"
```

---

### Task 5: README update, Docker end-to-end verification

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: everything built in Tasks 1–4.
- Produces: updated category summary table; a manually-verified running container stack covering all three A04 exploits plus the reset-restores-A04-state check — no automated test, this is the plan's final integration check.

- [ ] **Step 1: Modify `README.md`'s "What this is" prose and category summary table**

Check the exact current wording first (it's been updated twice already, for A02 and A03) and adjust precisely. Update the "Currently implemented" sentence to add A04, e.g.:
```markdown
Currently implemented: **A01 Broken Access Control** (IDOR, missing function-level
authorization, mass assignment / role escalation), **A02 Cryptographic Failures**
(leaked credential dump, weak ECB encryption, predictable password-reset token),
**A03 Injection** (SQL injection auth bypass, UNION-based exfiltration, reflected XSS,
blind time-based SQLi, OS command injection, stored XSS), and **A04 Insecure Design**
(unlimited coupon reuse, negative-quantity price manipulation, multi-step checkout
bypass). Remaining categories (A05–A10) are tracked separately and follow the same
pattern.
```

Update the category summary table:
```markdown
| A01 Broken Access Control | Implemented | IDOR (Easy), Hidden Admin Panel (Medium), Mass Assignment Role Escalation (Hard) |
| A02 Cryptographic Failures | Implemented | Leaked Credential Dump (Easy), Weak Encryption / ECB Mode (Medium), Predictable Password Reset Token (Hard) |
| A03 Injection | Implemented | SQLi Auth Bypass (Easy), UNION SQLi Exfiltration (Medium), Reflected XSS (Medium), Blind Time-Based SQLi (Hard), OS Command Injection (Hard), Stored XSS (Hard) |
| A04 Insecure Design | Implemented | Unlimited Coupon Reuse (Easy), Negative Quantity Price Manipulation (Medium), Multi-Step Checkout Bypass (Hard) |
| A05–A10 | Planned | See `docs/superpowers/specs/2026-09-18-owasp-lab-design.md` |
```

- [ ] **Step 2: Rebuild and start the stack**

Run: `docker compose up --build -d`
Expected: both services healthy/running; no errors in `docker compose logs app`.

- [ ] **Step 3: Verify A04 overview and nav**

Run: `curl -s http://127.0.0.1:5001/a04/ | grep -i "Insecure Design"`
Expected: match found. Confirm all three A04 example links appear on `/a04/`, and that A01/A02/A03/A04 appear in that sorted order in the top nav.

- [ ] **Step 4: Manually verify all three A04 exploits end-to-end**

```bash
# Easy: unlimited coupon reuse -- apply 6 times, price should hit $0.00
for i in 1 2 3 4 5 6; do
  curl -s -c cookies-a04.txt -b cookies-a04.txt -X POST http://127.0.0.1:5001/a04/coupon-cart -d "code=WELCOME10" -o /dev/null
done
curl -s -b cookies-a04.txt http://127.0.0.1:5001/a04/coupon-cart | grep -i "Total: \$0.00"

# Medium: negative quantity -- total should go negative
curl -s -X POST http://127.0.0.1:5001/a04/quantity-cart -d "quantity=-1" | grep -i "Total: -\$29.99"

# Hard: checkout bypass -- confirm directly, expect an unpaid order
curl -s http://127.0.0.1:5001/a04/checkout/confirm | grep -i "Thank you for your order"
docker compose exec postgres psql -U lab -d owasp_lab -c "select id, total_cents, paid from a04_orders order by id desc limit 1;"
# expect paid = f (false)

rm -f cookies-a04.txt
```
Expected: each exploit succeeds exactly as described.

- [ ] **Step 5: Verify reset restores A04's clean state too**

```bash
curl -s -X POST http://127.0.0.1:5001/settings/reset -o /dev/null
docker compose exec postgres psql -U lab -d owasp_lab -c "select count(*) from a04_orders;"
```
Expected: `0` — the fraudulent unpaid order (and any others created during Step 4) are gone; `a04_orders` was dropped and recreated empty (no seed data for this table by design).

- [ ] **Step 6: Tear down**

Run: `docker compose down`
Expected: containers stop cleanly.

- [ ] **Step 7: Commit**

```bash
git add README.md
git commit -m "docs: mark A04 Insecure Design as implemented"
```
