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
                hints=[
                    "Log in successfully first and check the security event log — a new entry appears immediately. Now think about the OTHER branch of a login form: what happens when the credentials are wrong?",
                    "Submit one wrong password at /a09/login. Does anything new show up in the security event log afterward?",
                    "Submit 10 or more wrong passwords in a row at /a09/login, then check /a09/security-events — the event count never moves at all. The failure branch never calls log_security_event(), so repeated failed logins leave zero trace for an operator to ever notice.",
                ],
            ),
            ExampleNav(
                id="admin-action-no-audit",
                title="High-Value Admin Action With No Audit Trail",
                group="Missing Audit Logging",
                difficulty="Medium",
                endpoint="a09_logging_monitoring_failures.admin_actions",
                hints=[
                    "Creating a user here logs an event correctly. Now try the OTHER, more destructive action this page offers — does it get the same treatment?",
                    "Delete an existing user from the list at /a09/admin-actions, then check whether the security event log gained a new entry for that action.",
                    "Delete a user at /a09/admin-actions, then check /a09/security-events — the user is genuinely gone from the list, but no event was ever logged for the deletion. The 'delete' branch never calls log_security_event(), unlike the 'create' branch right above it in the same function.",
                ],
            ),
            ExampleNav(
                id="sensitive-data-in-logs",
                title="Sensitive Data Leaked Into Log Files",
                group="Insecure Log Storage",
                difficulty="Easy",
                endpoint="a09_logging_monitoring_failures.support_login",
                hints=[
                    "This support login form fails on purpose with a wrong password. Where does that failure get recorded, and exactly what does it write down?",
                    "Failed attempts here are written to the app's own log file through a helper that formats the submitted username AND password directly into the log line, unescaped.",
                    "Submit any password (make it memorable) at /a09/support-login, then view the raw log via /a09/security-events — the password you typed appears in plaintext, sitting in a file meant for operational diagnostics, not credential storage.",
                ],
            ),
            ExampleNav(
                id="log-file-world-readable",
                title="Unauthenticated Log File Exposure",
                group="Insecure Log Storage",
                difficulty="Hard",
                endpoint="a09_logging_monitoring_failures.log_exposure_demo",
                hints=[
                    "Visiting this page plants another secret into the shared application log file. Now think about who's actually allowed to READ that file back.",
                    "There's a dedicated route that serves the raw log file's full contents. Check what access control, if any, it enforces before handing the file over.",
                    "Fetch that log-download route directly in a fresh incognito window or with curl — no login, no cookie, nothing.",
                    "curl http://127.0.0.1:5000/a09/download-log — the entire raw log downloads with zero authentication, including any plaintext credentials logged by the 'Sensitive Data Leaked Into Log Files' example (visit /a09/log-exposure-demo first for a freshly planted secret).",
                ],
            ),
            ExampleNav(
                id="no-alert-threshold",
                title="No Alert Threshold for Repeated Failures",
                group="No Detection & Alerting for Active Attacks",
                difficulty="Medium",
                endpoint="a09_logging_monitoring_failures.monitored_login",
                hints=[
                    "Every login attempt here genuinely IS logged, unlike the very first example in this category. So what's actually missing — think about what should happen once a pattern of failures repeats.",
                    "Submit several wrong passwords in a row at /a09/monitored-login and watch the security event log fill up correctly. Now look at the 'Active Alerts' count on that same page.",
                    "Submit 20 or more consecutive wrong passwords at /a09/monitored-login. All 20 attempts show up individually in the event log — correct, complete data — but 'Active Alerts' never leaves 0. Nothing anywhere counts failures per user or raises an alert once a threshold like 5 is crossed.",
                ],
            ),
            ExampleNav(
                id="attack-signature-not-flagged",
                title="Attack Signature Logged But Never Flagged",
                group="No Detection & Alerting for Active Attacks",
                difficulty="Hard",
                endpoint="a09_logging_monitoring_failures.product_search",
                hints=[
                    "This search box logs every query verbatim — true, working detection, unlike some other examples here. The gap is one step further downstream: what should happen once a LOGGED query looks like an attack?",
                    "Search for something that's unmistakably an attack probe, not just an ordinary product name, and check what 'Active Alerts' shows on the security event log page afterward.",
                    "Search for ' OR '1'='1' -- (a classic SQL injection probe) or ../../../../etc/passwd (path traversal) at /a09/product-search?q=... — the exact string gets logged faithfully, but nothing in this app ever pattern-matches logged queries against known attack signatures, so 'Active Alerts' stays at 0 no matter how obvious the signal already sitting in the log is.",
                ],
            ),
            ExampleNav(
                id="log-injection-display-name",
                title="Audit Log Forged via Unescaped Display Name",
                group="Log Injection / Forging",
                difficulty="Medium",
                endpoint="a09_logging_monitoring_failures.update_display_name",
                hints=[
                    "This 'change your display name' feature writes a line to the application's log file every time you save. Look at exactly how that log line gets built -- is your input treated as one opaque value, or just spliced into a line of text?",
                    "The log line is built as a literal f-string: f\"display name updated to '{display_name}'\", then appended to the log file. A log line is only a 'line' because it ends in a newline character -- what happens if your OWN input already contains one?",
                    "Submit a display name that spans two lines -- the field below is a text area, so you can type a real newline directly -- then check /a09/download-log. Does your input still read as ONE entry, or has it split into two independent-looking lines?",
                    "Craft the second line to look like a genuine, unrelated event: submit a display name shaped like Johan, then a real newline, then [2026-01-01 00:00:00] ADMIN: granted superuser role to attacker. The forged second line now sits in the log file indistinguishable from a real, separately-logged admin action, visible to anyone who reads /a09/download-log or the Security Events dashboard.",
                ],
            ),
        ],
    )
)
