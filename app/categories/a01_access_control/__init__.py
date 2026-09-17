from flask import Blueprint

a01_bp = Blueprint(
    "a01_access_control", __name__, template_folder="templates", url_prefix="/a01"
)

from app.categories.a01_access_control import routes  # noqa: E402,F401
from app.core.nav import CATEGORIES, CategoryNav, ExampleNav  # noqa: E402

CATEGORIES.append(
    CategoryNav(
        id="a01_access_control",
        short_id="A01",
        title="Broken Access Control",
        blueprint_name="a01_access_control",
        overview_endpoint="a01_access_control.overview",
        examples=[
            ExampleNav(
                id="idor",
                title="View Another User's Profile (IDOR)",
                difficulty="Easy",
                endpoint="a01_access_control.idor",
            ),
            ExampleNav(
                id="admin-users",
                title="Hidden Admin Panel",
                difficulty="Medium",
                endpoint="a01_access_control.admin_users",
            ),
            ExampleNav(
                id="mass-assignment",
                title="Account Update Role Escalation",
                difficulty="Hard",
                endpoint="a01_access_control.account_update",
            ),
        ],
    )
)
