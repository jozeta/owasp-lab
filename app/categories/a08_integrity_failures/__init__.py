from flask import Blueprint

a08_bp = Blueprint(
    "a08_integrity_failures", __name__, template_folder="templates", url_prefix="/a08"
)

from app.categories.a08_integrity_failures import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a08_integrity_failures",
        short_id="A08",
        title="Software and Data Integrity Failures",
        blurb="Deserialized data, installed code, and signed tokens trusted without ever verifying they weren't tampered with.",
        blueprint_name="a08_integrity_failures",
        overview_endpoint="a08_integrity_failures.overview",
        examples=[
            ExampleNav(
                id="cart-pickle-tampering",
                title="Pickle Cart Tampering",
                group="Insecure Deserialization",
                difficulty="Easy",
                endpoint="a08_integrity_failures.cart",
            ),
            ExampleNav(
                id="plugin-marketplace-tampering",
                title="Unsigned Plugin Content Trust",
                group="Unsigned Software Updates & Supply Chain",
                difficulty="Medium",
                endpoint="a08_integrity_failures.plugin_marketplace",
            ),
            ExampleNav(
                id="unchecked-signature-cookie",
                title="Unchecked Signature on Preferences Cookie",
                group="Broken Signature Verification",
                difficulty="Easy",
                endpoint="a08_integrity_failures.preferences",
            ),
            ExampleNav(
                id="jwt-alg-none-bypass",
                title="JWT alg:none Signature Bypass",
                group="Broken Signature Verification",
                difficulty="Medium",
                endpoint="a08_integrity_failures.admin_api",
            ),
        ],
    )
)
