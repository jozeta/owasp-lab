from flask import Blueprint

a07_bp = Blueprint(
    "a07_auth_failures", __name__, template_folder="templates", url_prefix="/a07"
)

from app.categories.a07_auth_failures import routes  # noqa: E402,F401
from app.categories.a07_auth_failures.seed import seed_a07_accounts  # noqa: E402
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a07_auth_failures",
        short_id="A07",
        title="Identification and Authentication Failures",
        blurb="Broken login protections and session-lifecycle handling that let attackers impersonate real users.",
        blueprint_name="a07_auth_failures",
        overview_endpoint="a07_auth_failures.overview",
        examples=[
            ExampleNav(
                id="brute-force-login",
                title="No Rate Limiting Enables Brute Force",
                group="Brute Force & Credential Stuffing",
                difficulty="Easy",
                endpoint="a07_auth_failures.brute_force_login",
            ),
            ExampleNav(
                id="credential-stuffing",
                title="Credential Stuffing Across Multiple Accounts",
                group="Brute Force & Credential Stuffing",
                difficulty="Medium",
                endpoint="a07_auth_failures.credential_stuffing",
            ),
            ExampleNav(
                id="session-in-url",
                title="Session Identifier Exposed in URL",
                group="Session Identity & Lifecycle",
                difficulty="Easy",
                endpoint="a07_auth_failures.share_session_link",
            ),
        ],
        seed_fn=seed_a07_accounts,
    )
)
