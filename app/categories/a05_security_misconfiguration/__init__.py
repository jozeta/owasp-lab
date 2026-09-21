from flask import Blueprint

a05_bp = Blueprint(
    "a05_security_misconfiguration", __name__, template_folder="templates", url_prefix="/a05"
)

from app.categories.a05_security_misconfiguration import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a05_security_misconfiguration",
        short_id="A05",
        title="Security Misconfiguration",
        blurb="Missing hardening, insecure defaults, and debug/admin interfaces left reachable in production.",
        blueprint_name="a05_security_misconfiguration",
        overview_endpoint="a05_security_misconfiguration.overview",
        examples=[
            ExampleNav(
                id="exposed-backup",
                title="Exposed Database Backup File",
                group="Exposed Files & Directories",
                difficulty="Easy",
                endpoint="a05_security_misconfiguration.backup_exposure",
            ),
            ExampleNav(
                id="directory-listing",
                title="Directory Listing Exposed",
                group="Exposed Files & Directories",
                difficulty="Easy",
                endpoint="a05_security_misconfiguration.directory_listing",
            ),
            ExampleNav(
                id="verbose-errors",
                title="Verbose Error Message Disclosure",
                group="Insecure Response Configuration",
                difficulty="Medium",
                endpoint="a05_security_misconfiguration.inventory_check",
            ),
        ],
    )
)
