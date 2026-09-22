from flask import Blueprint

a10_bp = Blueprint(
    "a10_ssrf", __name__, template_folder="templates", url_prefix="/a10"
)

from app.categories.a10_ssrf import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a10_ssrf",
        short_id="A10",
        title="Server-Side Request Forgery",
        blurb="A URL field the server fetches on your behalf, an unrestricted scheme, or a blocklist/allowlist with a gap wide enough to reach an internal-only endpoint that should never have been visible from outside.",
        blueprint_name="a10_ssrf",
        overview_endpoint="a10_ssrf.overview",
        examples=[
            ExampleNav(
                id="webhook-internal-metadata",
                title="Webhook Tester Reaches Internal Metadata Endpoint",
                group="Unrestricted Server-Side Fetch",
                difficulty="Easy",
                endpoint="a10_ssrf.webhook_tester",
            ),
        ],
    )
)
