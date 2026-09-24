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
                hints=[
                    "This page talks about a nightly database backup file. Where might an automated backup job have written that file, and is that location actually protected from outside access?",
                    "The backup file lives at a predictable, web-reachable path under /a05/backups/ — nothing checks who's requesting it.",
                    "Request /a05/backups/db_backup_2024-01-15.sql.bak directly — the server serves the full backup file's contents to anyone, no login or authorization required at all.",
                ],
            ),
            ExampleNav(
                id="directory-listing",
                title="Directory Listing Exposed",
                group="Exposed Files & Directories",
                difficulty="Easy",
                endpoint="a05_security_misconfiguration.directory_listing",
                hints=[
                    "This page hints at an uploads folder. What happens if you visit the folder itself, rather than a specific file inside it?",
                    "Visit /a05/uploads/ — directory listing is enabled, so the server shows you every filename in that folder, whether or not you were ever told it existed.",
                    "One of the listed files, Q3_payroll_export.csv, is directly downloadable at /a05/uploads/Q3_payroll_export.csv — and its contents include real employee SSNs and salaries, exposed purely because the folder listing revealed a filename nobody was supposed to guess.",
                ],
            ),
            ExampleNav(
                id="verbose-errors",
                title="Verbose Error Message Disclosure",
                group="Insecure Response Configuration",
                difficulty="Medium",
                endpoint="a05_security_misconfiguration.inventory_check",
                hints=[
                    "Submit anything into this SKU lookup form and see what the error response actually contains — is it a generic 'something went wrong', or something much more detailed?",
                    "Every submission triggers a real exception, and the app renders the raw exception message AND full Python traceback straight back to you instead of a safe generic error.",
                    "Submit any SKU value at /a05/inventory-check — the error message includes a full PostgreSQL connection string, complete with a real-looking internal hostname, port, database name, and a plaintext password (wh_S3rv1ce_2024!) for the warehouse_svc account, leaked purely by an overly verbose error handler.",
                ],
            ),
            ExampleNav(
                id="cors-credentials",
                title="Permissive CORS with Credentials",
                group="Insecure Response Configuration",
                difficulty="Medium",
                endpoint="a05_security_misconfiguration.cors_credentials",
                hints=[
                    "This page sets a cookie, then a separate API endpoint reads it back. Check that API endpoint's response headers — specifically anything starting with Access-Control-*.",
                    "/a05/api/loyalty-status reflects whatever Origin header the request sent back as Access-Control-Allow-Origin, and also sets Access-Control-Allow-Credentials: true — that combination lets a response be read cross-origin, cookies included, by literally any site.",
                    "From a page on a completely different origin, run: fetch('http://127.0.0.1:5000/a05/api/loyalty-status', {credentials: 'include'}).then(r => r.json()).then(console.log) — because the API reflects your page's Origin and allows credentials, the browser lets this cross-site request through and hands back the victim's real loyalty token, something the same-origin policy exists specifically to prevent.",
                    "Full attack shape: host that fetch() call on any other origin (even a plain local HTML file opened via a small http.server on a different port counts as cross-origin), first visit /a05/cors-credentials in the same browser to plant the cookie, then load your attacker page and watch it read the victim's token straight out of the JSON response.",
                ],
            ),
            ExampleNav(
                id="cors-null-origin",
                title="CORS: Null Origin Whitelisted",
                group="Insecure Response Configuration",
                difficulty="Medium",
                endpoint="a05_security_misconfiguration.cors_null_origin",
                hints=[
                    "This endpoint's CORS behavior is different from the other CORS example in this app — it doesn't reflect just any origin. Try requesting it with an Origin header of the literal string 'null'.",
                    "The server explicitly whitelists the literal 'null' origin as if it were a real, specific trusted domain — a leftover from testing via a sandboxed iframe or local file during development.",
                    "Browsers send a literal null Origin header when a sandboxed iframe with no allow-same-origin uses a data: URI. Visit /a05/cors-null-origin-demo to see this exact technique running live against /a05/api/partner-directory.",
                    "curl -s http://127.0.0.1:5000/a05/api/partner-directory -H 'Origin: null' — the response includes Access-Control-Allow-Origin: null and Access-Control-Allow-Credentials: true, letting a null-origin context read this response with credentials attached.",
                ],
            ),
            ExampleNav(
                id="cors-wildcard-internal-pivot",
                title="CORS: Wildcard Origin, Internal Network Pivot",
                group="Insecure Response Configuration",
                difficulty="Medium",
                endpoint="a05_security_misconfiguration.cors_wildcard_internal_pivot",
                hints=[
                    "This 'internal metrics' endpoint has a wildcard CORS header. A wildcard blocks cookies from being attached — so what OTHER protection would need to be missing for that to still matter?",
                    "The endpoint requires no authentication at all — no session, no API key. A wildcard CORS header combined with zero auth means any external page's JavaScript can read this response directly.",
                    "curl -s http://127.0.0.1:5000/a05/api/internal-metrics -H 'Origin: https://evil.com' — the response includes Access-Control-Allow-Origin: * and real internal metrics data, with no authentication required at all.",
                    "This is the 'internal network pivot' variant: in a real deployment this endpoint would sit on a network segment unreachable from the internet, but a victim's browser inside that network can be made to fetch() it on an attacker's behalf via a page the victim merely visits — the missing auth check is the real bug, and the wildcard CORS header is what lets the cross-origin request through.",
                ],
            ),
            ExampleNav(
                id="cors-origin-regex-bypass",
                title="CORS: Origin Allowlist Regex Bypass",
                group="Insecure Response Configuration",
                difficulty="Hard",
                endpoint="a05_security_misconfiguration.cors_origin_regex_bypass",
                hints=[
                    "This API is meant to trust only real partner.example.com-style origins. Try an origin that CONTAINS the trusted domain as a substring but isn't actually a subdomain of it — e.g. https://evilexample.com.",
                    "The origin-validation regex has no end-anchor — it only checks that the origin starts with https:// and contains example.com somewhere after that, never that it actually ENDS there.",
                    "curl -s http://127.0.0.1:5000/a05/api/partner-portal -H 'Origin: https://evilexample.com' — the response reflects that origin with credentials enabled, even though evilexample.com was never a real partner domain.",
                    "This is the 'Expanding the Origin' technique: a badly implemented regular expression intended to validate an origin allowlist accepts substrings or prefixes it shouldn't, because the pattern was never anchored to the full string. A real attacker just needs to register any domain containing the trusted substring.",
                ],
            ),
            ExampleNav(
                id="debug-console-rce",
                title="Exposed Debug Console",
                group="Exposed Debug & Admin Interfaces",
                difficulty="Hard",
                endpoint="a05_security_misconfiguration.internal_diagnostics",
                hints=[
                    "This example mentions a legacy diagnostics tool mounted separately from the main app. Visit its URL directly and look closely at what kind of error page comes back — does it look like anything else in this app?",
                    "The diagnostics route always raises an error, and because debug mode is left on for that mounted tool, the error page isn't a normal error page at all — it's Werkzeug's interactive debugger, a live console running inside the server.",
                    "On that debugger page, click the bottom-most stack frame — a small console icon opens an interactive Python prompt attached to that exact point in the running server process.",
                    "Type a real Python expression into that console and press Enter — e.g. __import__('subprocess').check_output(['id']).decode() — it executes for real, inside the live server process, and returns actual command output. This is genuine remote code execution: nothing stops you from reading any file the server can read or going further from there.",
                ],
            ),
            ExampleNav(
                id="default-admin-creds",
                title="Forgotten Admin Panel with Default Credentials",
                group="Exposed Debug & Admin Interfaces",
                difficulty="Hard",
                endpoint="a05_security_misconfiguration.admin_login",
                hints=[
                    "This is a forgotten internal admin panel. Before trying anything clever, consider: tools like this often ship with default credentials that get forgotten after deployment. What's this tool's typical default username?",
                    "Try the single most common default admin username: admin. The password is a specific, memorable-looking string that was clearly set once and never rotated since — think in terms of the product name plus a deployment year.",
                    "Log in at /a05/admin-login with username admin and password DataVault@2019 — these factory-default credentials were never changed after this internal tool went live, and they grant full access to the admin panel's customer records (names, emails, and password hints) at /a05/admin-panel.",
                ],
            ),
            ExampleNav(
                id="clickjacking-delete-account",
                title="Clickjacking on a Sensitive Action Page",
                group="Missing Security Headers",
                difficulty="Easy",
                endpoint="a05_security_misconfiguration.delete_account",
                hints=[
                    "This 'delete my account' page performs a real, irreversible action from a plain POST. Check its response headers — is there anything that would stop this page from being loaded inside another site's <iframe>?",
                    "There's no X-Frame-Options header and no Content-Security-Policy frame-ancestors directive anywhere in this app — any page on the internet can embed this exact page inside an invisible iframe.",
                    "Visit /a05/delete-account-clickjack-demo — it shows a fake 'Claim your prize' button with the real delete-account page loaded invisibly underneath it, precisely aligned. Clicking the decoy button actually clicks the real Delete Account button hidden beneath it.",
                    "This is a real technique: an attacker hosts a page styled however they like, embeds the victim's already-logged-in sensitive-action page in a transparent iframe positioned exactly under a decoy element, and tricks the victim into clicking through — the browser sends the victim's real session cookie, so the resulting action is completely genuine from the server's point of view.",
                ],
            ),
        ],
    )
)
