from flask import Blueprint

a09_bp = Blueprint(
    "a09_logging_monitoring_failures",
    __name__,
    template_folder="templates",
    url_prefix="/a09",
)

from app.categories.a09_logging_monitoring_failures import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a09_logging_monitoring_failures",
        short_id="A09",
        title="Security Logging and Monitoring Failures",
        blurb="Auditable events go unrecorded, logs leak sensitive data or sit exposed to anyone, and nothing ever alerts on an attack already in progress.",
        blueprint_name="a09_logging_monitoring_failures",
        overview_endpoint="a09_logging_monitoring_failures.overview",
        examples=[
            ExampleNav(
                id="failed-logins-not-logged",
                title="Failed Login Attempts Never Logged",
                group="Missing Audit Logging",
                difficulty="Easy",
                endpoint="a09_logging_monitoring_failures.login",
            ),
            ExampleNav(
                id="admin-action-no-audit",
                title="High-Value Admin Action With No Audit Trail",
                group="Missing Audit Logging",
                difficulty="Medium",
                endpoint="a09_logging_monitoring_failures.admin_actions",
            ),
            ExampleNav(
                id="sensitive-data-in-logs",
                title="Sensitive Data Leaked Into Log Files",
                group="Insecure Log Storage",
                difficulty="Easy",
                endpoint="a09_logging_monitoring_failures.support_login",
            ),
        ],
    )
)
