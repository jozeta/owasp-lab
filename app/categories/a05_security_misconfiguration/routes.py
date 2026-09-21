import os

from flask import Response, render_template

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
