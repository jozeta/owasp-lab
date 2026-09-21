from flask import Blueprint

a06_bp = Blueprint(
    "a06_vulnerable_components", __name__, template_folder="templates", url_prefix="/a06"
)

from app.categories.a06_vulnerable_components import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a06_vulnerable_components",
        short_id="A06",
        title="Vulnerable and Outdated Components",
        blurb="Outdated, unpatched dependencies with known public CVEs still running in production.",
        blueprint_name="a06_vulnerable_components",
        overview_endpoint="a06_vulnerable_components.overview",
        examples=[
            ExampleNav(
                id="version-disclosure",
                title="Component Version Disclosure",
                group="Component Reconnaissance",
                difficulty="Easy",
                endpoint="a06_vulnerable_components.component_inventory",
            ),
            ExampleNav(
                id="outdated-jquery-detection",
                title="Outdated Vulnerable JS Library Detection",
                group="Component Reconnaissance",
                difficulty="Easy",
                endpoint="a06_vulnerable_components.legacy_widgets",
            ),
            ExampleNav(
                id="jquery-dom-xss",
                title="jQuery DOM XSS via Vulnerable htmlPrefilter",
                group="Vulnerable Library: jQuery HTML Sanitization Bypass",
                difficulty="Medium",
                endpoint="a06_vulnerable_components.comment_preview",
            ),
        ],
    )
)
