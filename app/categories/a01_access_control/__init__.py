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
                id="password-change-idor",
                title="IDOR on Password-Change API",
                group="Insecure Direct Object References (IDOR)",
                difficulty="Medium",
                endpoint="a01_access_control.password_change_api",
                hints=[
                    "This JSON API is meant to change YOUR password. Look at how it decides whose password to change — does it use your session, or something you supply?",
                    "The endpoint looks up the target account by an 'email' field in your request body, never checking it against any authenticated session at all.",
                    "With no login, no cookie, no authentication header whatsoever: curl -X POST http://127.0.0.1:5000/a01/api/password-change -H 'Content-Type: application/json' -d '{\"email\": \"bob@owasp-lab.local\", \"new_password\": \"attacker-chosen-password\"}' — Bob's password is now whatever you set it to, with zero proof you own his account.",
                ],
            ),
            ExampleNav(
                id="idor-wildcard-lookup",
                title="IDOR via Wildcard Pattern-Matched Lookup",
                group="Insecure Direct Object References (IDOR)",
                difficulty="Medium",
                endpoint="a01_access_control.lookup_account",
                hints=[
                    "This 'find my account' feature looks up a user by username. Look at exactly how the comparison is implemented -- is it checking for an EXACT match, or something looser?",
                    "The query uses SQLAlchemy's .like() instead of == -- that's SQL pattern matching, not equality. In LIKE syntax, % matches any sequence of characters at all, including an empty one.",
                    "Submit a bare % as the username to look up. Every account in the system matches a pattern that matches everything, so the response discloses every user's data in one request -- no guessing a specific ID required at all.",
                    "This is a different bug shape from a classic IDOR: instead of guessing one identifier at a time, a single wildcard character exploits the WRONG comparison operator being used for what was supposed to be an exact-match lookup.",
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
            ExampleNav(
                id="csrf-email-change",
                title="Account Takeover via CSRF (Email Change)",
                group="Cross-Site Request Forgery",
                difficulty="Medium",
                endpoint="a01_access_control.change_email",
                hints=[
                    "This 'change my email' form updates a sensitive field with a plain POST. Check the form's HTML source for anything that would stop a DIFFERENT website from submitting the exact same request on your behalf.",
                    "There is no CSRF token anywhere in this form, and the server never checks where the request came from — only that a valid session cookie was attached, which browsers do automatically for same-origin AND cross-origin form submissions alike.",
                    "Build a tiny HTML page hosted anywhere else with an auto-submitting form targeting http://127.0.0.1:5000/a01/change-email with a hidden new_email field set to an address you control, then visit that page while logged in here — your email changes with no further interaction.",
                    "Why this matters beyond just changing an email: whoever controls the email on file controls every future password-reset flow for that account, making an email-change CSRF just as dangerous as a direct password-change CSRF.",
                ],
            ),
            ExampleNav(
                id="csrf-token-presence-only",
                title="CSRF via Token Presence-Only Validation",
                group="Cross-Site Request Forgery",
                difficulty="Medium",
                endpoint="a01_access_control.change_display_name",
                hints=[
                    "This form includes a hidden csrf_token field, unlike the email-change example elsewhere in this category. Before assuming it's safe, check exactly WHAT the server does with that field's value once submitted.",
                    "The route confirms a csrf_token value was submitted at all, but never compares it against the real per-session token this page issued. Submit the form with the token field present but set to an obviously wrong value, like 'wrong' -- does it still work?",
                    "An attacker's cross-site page can never read this session's real token, but it doesn't need to: any non-empty string in the csrf_token field passes the server's check. A hidden field alongside the real display_name field, auto-submitted from a completely different origin, changes the victim's display name exactly as easily as if there were no token check at all.",
                    "This is a common real-world CSRF-protection mistake: implementing 'does a token exist' instead of 'does the submitted token match the one this session was actually issued' -- the presence check makes the form LOOK protected in the page source without providing any actual protection.",
                ],
            ),
            ExampleNav(
                id="arbitrary-file-read",
                title="Arbitrary File Read via Document Download",
                group="Path Traversal",
                difficulty="Medium",
                endpoint="a01_access_control.download_document",
                hints=[
                    "This 'document center' downloads a file by name from a shared folder. Look at how the name you provide gets combined with that folder's path -- is there any check at all on what the name can contain?",
                    "The server builds the path with os.path.join(DOCUMENTS_DIR, name) and opens it directly. Try a name containing several ../ sequences to climb out of the documents folder -- e.g. ?name=../../../../../../etc/passwd. (The exact count needed depends on how deep this app is installed on disk -- if that many aren't enough on your setup, add more; extra ../ segments beyond the root are harmless, since climbing above / is a no-op.)",
                    "There's an even simpler technique specific to Python: os.path.join() discards its FIRST argument entirely if the second argument is an absolute path. Try ?name=/etc/passwd -- no ../ needed at all, and the real contents of /etc/passwd come back.",
                ],
            ),
            ExampleNav(
                id="path-traversal-filter-bypass",
                title="Path Traversal Filter Bypass via Absolute Path",
                group="Path Traversal",
                difficulty="Hard",
                endpoint="a01_access_control.download_document_filtered",
                hints=[
                    "This version blocks any name containing the substring '..' before opening the file. Confirm it: try the same ../../../etc/passwd payload that worked on the sibling 'Arbitrary File Read' example in this group -- it's rejected here.",
                    "The filter only ever looks for '..'. Think back to the OTHER technique from that sibling example -- does a bare absolute path contain that substring anywhere at all?",
                    "Submit ?name=/etc/passwd -- zero dots-in-sequence for the filter to catch, so it sails straight through untouched and reaches the exact same unguarded open() call as the unfiltered example.",
                    "This is the same class of mistake as this lab's command-injection filter-bypass example: a blacklist that enumerates 'the obvious' attack shape has to anticipate every equivalent way to reach the same outcome, not just the first one its author thought of.",
                ],
            ),
            ExampleNav(
                id="unvalidated-open-redirect",
                title="Unvalidated Open Redirect",
                group="Open Redirect",
                difficulty="Medium",
                endpoint="a01_access_control.continue_redirect",
                hints=[
                    "This 'continue to your destination' feature redirects to whatever URL is in the next parameter. Check whether there's any validation on that URL at all before redirecting.",
                    "Flask's redirect() sends the exact string it's given as the response's Location header -- it performs no host-checking of its own. Submit ?next=/a01/ first to confirm the basic flow works.",
                    "Now submit ?next=https://evil.example.com/phish -- the response redirects straight there, no validation stops it. A crafted link using this app's own trusted domain, with this payload as the next parameter, would look far more trustworthy to a victim than a raw link to the attacker's site.",
                ],
            ),
            ExampleNav(
                id="open-redirect-allowlist-bypass",
                title="Open Redirect Allowlist Bypass via Domain Suffix",
                group="Open Redirect",
                difficulty="Hard",
                endpoint="a01_access_control.continue_redirect_filtered",
                hints=[
                    "This version only allows redirecting to trusted-partner.example -- confirm the filter genuinely blocks an unrelated domain first. Then think about exactly WHAT the check tests: is it really confirming the URL's host, or something weaker?",
                    "The check is 'trusted-partner.example' in next_url -- a plain substring test, not a real URL-host comparison. Does that substring have to be at the START of the host to pass?",
                    "Submit ?next=https://trusted-partner.example.evil.example.com/phish -- the substring 'trusted-partner.example' genuinely appears in this string, so the check passes, but the URL's real host is trusted-partner.example.evil.example.com, a domain entirely controlled by whoever registered evil.example.com.",
                    "This is the classic 'substring allowlist' mistake, the same technique real-world open-redirect filter bypasses use against domains like 'whitelisted-site.com.evil.com' -- checking 'does this string contain the trusted name' is never equivalent to 'is this URL's actual host the trusted one.'",
                ],
            ),
        ],
    )
)
