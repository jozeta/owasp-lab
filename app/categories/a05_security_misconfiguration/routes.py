import os

from flask import Response, abort, render_template

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
