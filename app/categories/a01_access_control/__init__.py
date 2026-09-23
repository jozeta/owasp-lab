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
        blurb="Access control that is not enforced on the server, letting users act outside their intended permissions.",
        blueprint_name="a01_access_control",
        overview_endpoint="a01_access_control.overview",
        examples=[
            ExampleNav(
                id="idor",
                title="View Another User's Profile (IDOR)",
                group="Insecure Direct Object References (IDOR)",
                difficulty="Easy",
                endpoint="a01_access_control.idor",
                hints=[
                    "This page shows a user profile by ID, and the ID is right there in the URL. What happens if you don't view your own profile, but someone else's?",
                    "The route is /a01/profile/<user_id> — nothing on the server checks whether the ID you ask for belongs to the account you're logged in as.",
                    "Log in as any user, then edit the URL to /a01/profile/2 (or any other user ID) — the server happily returns that other user's full profile with no ownership check at all.",
                ],
            ),
            ExampleNav(
                id="admin-users",
                title="Hidden Admin Panel",
                group="Missing Function-Level Access Control",
                difficulty="Medium",
                endpoint="a01_access_control.admin_users",
                hints=[
                    "This admin panel changes another user's role. Who's actually allowed to submit that form?",
                    "The route only checks that SOMEONE is logged in — it never checks that the logged-in user is themselves an admin before letting them promote anyone.",
                    "Log in as any regular (non-admin) user, navigate to /a01/admin/users, and submit the form with your own user ID and role=admin — the server grants it with no authorization check at all.",
                ],
            ),
            ExampleNav(
                id="mass-assignment",
                title="Account Update Role Escalation",
                group="Mass Assignment",
                difficulty="Hard",
                endpoint="a01_access_control.account_update",
                hints=[
                    "This form is meant to update your display name and bio. Look at how the server processes the submission — does it only accept the fields the form actually shows you?",
                    "The handler loops over every key in the submitted form data and sets it directly as an attribute on your user record, skipping only the 'id' field. Nothing limits it to display_name/bio.",
                    "The User model has a 'role' column. Submit the account-update form with an extra field named role set to admin (e.g. by adding a hidden field via your browser's dev tools, or crafting the raw request) — the handler happily sets your own role to admin, since it never restricts which fields it accepts.",
                    "Exact reproduction: POST to /a01/account/update with form data including role=admin alongside the normal fields — e.g. curl -X POST -d \"display_name=Me&bio=hi&role=admin\" http://127.0.0.1:5000/a01/account/update (with your session cookie) works.",
                ],
            ),
        ],
    )
)
