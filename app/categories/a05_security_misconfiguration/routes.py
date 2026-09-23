import os
import secrets
import traceback

from flask import Response, abort, jsonify, make_response, redirect, render_template, request, session, url_for

from app.categories.a05_security_misconfiguration import a05_bp

BACKUP_FILE_PATH = os.path.join(os.path.dirname(__file__), "backups", "db_backup_2024-01-15.sql.bak")


@a05_bp.route("/")
def overview():
    return render_template("a05_security_misconfiguration/overview.html")


@a05_bp.route("/backup-exposure")
def backup_exposure():
    return render_template(
        "a05_security_misconfiguration/backup_exposure.html", backup_path=BACKUP_FILE_PATH
    )


@a05_bp.route("/backups/db_backup_2024-01-15.sql.bak")
def backup_file():
    # VULNERABLE: automated nightly backups are written to a predictable,
    # web-accessible path with no access control at all -- anyone who
    # guesses (or scans for) this filename can download it directly.
    with open(BACKUP_FILE_PATH) as f:
        content = f.read()
    return Response(content, mimetype="text/plain")


UPLOADS_FILES = {
    "Q3_payroll_export.csv": (
        "employee_id,name,ssn,salary\n"
        "1001,Dana Whitfield,412-88-7734,88500\n"
        "1002,Marcus Ibe,558-21-0093,76200\n"
        "1003,Priya Chandran,301-44-9982,94750\n"
    ),
    "meeting_notes.txt": (
        "Q3 planning notes -- do not distribute externally.\n"
        "- New warehouse lease signed, terms confidential until Q4.\n"
        "- Payroll export sent to finance (see Q3_payroll_export.csv)\n"
    ),
    "site_backup_old.zip": "PK\x03\x04(not a real zip -- placeholder binary marker for this demo)",
}


@a05_bp.route("/uploads/")
def uploads_index():
    # VULNERABLE: directory listing is enabled on this upload folder --
    # nothing prevents a visitor from seeing every filename in it, whether
    # or not they know it exists.
    return render_template(
        "a05_security_misconfiguration/uploads_index.html", filenames=sorted(UPLOADS_FILES)
    )


@a05_bp.route("/uploads/<path:filename>")
def uploads_file(filename):
    content = UPLOADS_FILES.get(filename)
    if content is None:
        abort(404)
    return Response(content, mimetype="text/plain")


@a05_bp.route("/directory-listing")
def directory_listing():
    return render_template("a05_security_misconfiguration/directory_listing.html")


WAREHOUSE_DB_PASSWORD = "wh_S3rv1ce_2024!"


@a05_bp.route("/inventory-check", methods=["GET", "POST"])
def inventory_check():
    sku = ""
    error_detail = None
    if request.method == "POST":
        sku = request.form.get("sku", "")
        try:
            # VULNERABLE: a real internal connection string, including a
            # real-looking password, gets embedded directly in the
            # exception message
            raise ConnectionError(
                f"Failed to connect to warehouse DB at "
                f"postgresql://warehouse_svc:{WAREHOUSE_DB_PASSWORD}@10.0.4.12:5432/inventory "
                f"while looking up SKU '{sku}'"
            )
        except Exception as e:
            # VULNERABLE: the raw exception message and full traceback are
            # rendered directly back to the client instead of a generic
            # "something went wrong" message
            error_detail = "".join(traceback.format_exception(type(e), e, e.__traceback__))
    return render_template(
        "a05_security_misconfiguration/inventory_check.html", sku=sku, error_detail=error_detail
    )


LOYALTY_TOKEN_COOKIE = "a05_loyalty_token"


@a05_bp.route("/cors-credentials")
def cors_credentials():
    resp = make_response(render_template("a05_security_misconfiguration/cors_credentials.html"))
    if LOYALTY_TOKEN_COOKIE not in request.cookies:
        # This demo cookie uses SameSite=None so it's sent on genuinely
        # cross-site requests too -- a real-world requirement for many
        # legitimately-embedded widgets/APIs, and exactly what makes the
        # CORS misconfiguration below actually exploitable rather than
        # already blocked by the browser's own same-site cookie policy.
        resp.set_cookie(LOYALTY_TOKEN_COOKIE, secrets.token_hex(8), samesite="None", secure=True)
    return resp


@a05_bp.route("/api/loyalty-status")
def loyalty_status_api():
    token = request.cookies.get(
        LOYALTY_TOKEN_COOKIE, "(no token set -- visit /a05/cors-credentials first)"
    )
    resp = jsonify({"loyalty_token": token, "tier": "Gold"})
    origin = request.headers.get("Origin")
    if origin:
        # VULNERABLE: reflects ANY Origin header verbatim instead of
        # checking it against an allowlist, combined with credentials
        # support -- lets any third-party site read this response using
        # the victim's own cookie.
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp


@a05_bp.route("/internal-diagnostics")
def internal_diagnostics():
    return render_template("a05_security_misconfiguration/internal_diagnostics.html")


ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "DataVault@2019"

FAKE_CUSTOMER_RECORDS = [
    {"name": "Renata Solis", "email": "renata.solis@example.test", "password_hint": "childhood pet's name"},
    {"name": "Owen Baptiste", "email": "owen.baptiste@example.test", "password_hint": "first car model"},
    {"name": "Yuki Nakashima", "email": "yuki.nakashima@example.test", "password_hint": "mother's maiden name"},
]


@a05_bp.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULNERABLE: hardcoded, factory-default credentials that were
        # never rotated after this internal tool was deployed
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["a05_admin_authenticated"] = True
            return redirect(url_for("a05_security_misconfiguration.admin_panel"))
        error = "Invalid username or password."
    return render_template("a05_security_misconfiguration/admin_login.html", error=error)


@a05_bp.route("/admin-panel")
def admin_panel():
    if not session.get("a05_admin_authenticated"):
        return redirect(url_for("a05_security_misconfiguration.admin_login"))
    return render_template(
        "a05_security_misconfiguration/admin_panel.html", records=FAKE_CUSTOMER_RECORDS
    )


@a05_bp.route("/delete-account", methods=["GET", "POST"])
def delete_account():
    deleted = False
    if request.method == "POST":
        # VULNERABLE: performs a real, irreversible action immediately
        # from a plain POST with no confirmation step -- and, just as
        # importantly, this response (like every other page in this app)
        # sets no X-Frame-Options header and no Content-Security-Policy
        # frame-ancestors directive, so it can be embedded in an
        # invisible iframe on any attacker-controlled page and clicked
        # through without the victim ever realizing it.
        deleted = True
    return render_template("a05_security_misconfiguration/delete_account.html", deleted=deleted)


@a05_bp.route("/delete-account-clickjack-demo")
def delete_account_clickjack_demo():
    return render_template("a05_security_misconfiguration/delete_account_clickjack_demo.html")
