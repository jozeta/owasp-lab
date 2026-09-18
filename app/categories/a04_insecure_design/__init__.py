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
    )
)
