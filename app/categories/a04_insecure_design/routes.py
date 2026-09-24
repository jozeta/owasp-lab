import secrets

from flask import redirect, render_template, request, session, url_for

from app.categories.a04_insecure_design import a04_bp
from app.categories.a04_insecure_design.models import Order
from app.extensions import db

DEMO_PRODUCT_NAME = "Wireless Mouse"
DEMO_PRODUCT_PRICE_CENTS = 2999
COUPON_CODE = "WELCOME10"
COUPON_DISCOUNT_CENTS = 500
STOCK_COUNT = 3


def _format_cents(cents):
    sign = "-" if cents < 0 else ""
    try:
        return f"{sign}${abs(cents) / 100:.2f}"
    except OverflowError:
        # A pathologically large (e.g. hundreds-of-digits) quantity/total can make
        # the float division above overflow. This is a display robustness fix only --
        # it doesn't add bounds validation, it just keeps the page from crashing.
        return f"{sign}$(number too large to display)"


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


@a04_bp.route("/quantity-cart", methods=["GET", "POST"])
def quantity_cart():
    if request.method == "POST":
        try:
            quantity = int(request.form.get("quantity", "1"))
        except (ValueError, OverflowError):
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


@a04_bp.route("/quantity-cart/reset", methods=["POST"])
def quantity_cart_reset():
    session.pop("a04_quantity", None)
    return redirect(url_for("a04_insecure_design.quantity_cart"))


@a04_bp.route("/checkout/shipping", methods=["GET", "POST"])
def checkout_shipping():
    if request.method == "POST":
        # Recorded but deliberately never checked anywhere -- the app tracks that
        # this step happened without ever enforcing that it must have.
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
    order = db.session.get(Order, order_id) if order_id else None
    if order is None:
        # VULNERABLE: no verification that the shipping/payment steps ever ran --
        # visiting this URL directly (or with a stale/reset session) still produces
        # a "confirmed" order, unpaid.
        order = Order(total_cents=DEMO_PRODUCT_PRICE_CENTS, paid=False)
        db.session.add(order)
        db.session.commit()
        session["a04_order_id"] = order.id
    return render_template(
        "a04_insecure_design/checkout_confirm.html",
        order=order,
        total_display=_format_cents(order.total_cents),
    )


@a04_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    reset_link = None
    email = None
    if request.method == "POST":
        email = request.form.get("email", "")
        # VULNERABLE: builds the password-reset link using the Host the
        # client claims to be talking to -- preferring X-Forwarded-Host
        # when present, exactly as a real app behind a reverse proxy
        # often does -- instead of a fixed, server-configured domain. An
        # attacker who controls either header controls where the "reset"
        # link points.
        host = request.headers.get("X-Forwarded-Host") or request.host
        token = secrets.token_hex(8)
        reset_link = f"http://{host}/a04/reset-password-confirm?token={token}&email={email}"
    return render_template(
        "a04_insecure_design/forgot_password.html", reset_link=reset_link, email=email
    )


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
