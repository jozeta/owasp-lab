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
        ],
    )
)
