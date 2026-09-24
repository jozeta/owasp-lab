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
        blurb="Missing security controls baked into the design itself, not just a coding mistake.",
        blueprint_name="a04_insecure_design",
        overview_endpoint="a04_insecure_design.overview",
        examples=[
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
                title="Multi-Step Checkout Bypass",
                group="Workflow Bypass",
                difficulty="Hard",
                endpoint="a04_insecure_design.checkout_shipping",
                hints=[
                    "This checkout has three steps: shipping, payment, confirm. Does the server actually verify you completed steps 1 and 2 before letting you reach step 3?",
                    "The shipping step just records 'shipping done' in your session and is never read again by any later step. The confirm step only checks whether an order ID already exists in your session.",
                    "Visit /a04/checkout/confirm directly, skipping /a04/checkout/shipping and /a04/checkout/payment entirely (clear your session first, or use a fresh browser/incognito window) — the server creates a new 'confirmed' order anyway, marked unpaid, with no verification any prior step occurred.",
                    "This is a workflow-bypass / business-logic flaw: enforcing a UI sequence (multi-page checkout) is not the same as enforcing it server-side. The fix is for the confirm step to verify session state set by the earlier steps rather than trusting that the user simply followed the intended page order.",
                ],
            ),
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
