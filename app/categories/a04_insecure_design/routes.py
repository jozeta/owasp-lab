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
