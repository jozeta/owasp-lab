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
