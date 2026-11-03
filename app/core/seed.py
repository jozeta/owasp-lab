import os
import shutil

from werkzeug.security import generate_password_hash

from app.core.models import Settings, User
from app.core.nav import CATEGORIES
from app.extensions import db

SEED_USERS = [
    dict(
        username="alice",
        email="alice@example.test",
        password="alice-training-pw1",
        display_name="Alice Anderson",
        bio="Loves hiking and open source.",
        private_notes="Doctor's appointment 3pm Friday.",
        role="user",
    ),
    dict(
        username="bob",
        email="bob@example.test",
        password="bob-training-pw1",
        display_name="Bob Baker",
        bio="Coffee enthusiast, backend engineer.",
        private_notes="Gym locker PIN: 4471.",
        role="user",
    ),
    dict(
        username="carol",
        email="carol@example.test",
        password="carol-training-pw1",
        display_name="Carol Chen",
        bio="Runs the office book club.",
        private_notes="Planning a surprise party for Dave.",
        role="user",
    ),
    dict(
        username="admin",
        email="admin@example.test",
        password="admin-training-pw1",
        display_name="Site Admin",
        bio="System administrator account.",
        private_notes="Rotate backup encryption keys quarterly.",
        role="admin",
    ),
]


def seed_database(app):
    with app.app_context():
        db.create_all()
        if User.query.count() == 0:
            for entry in SEED_USERS:
                db.session.add(
                    User(
                        username=entry["username"],
                        email=entry["email"],
                        password_hash=generate_password_hash(entry["password"], method="pbkdf2:sha256"),
                        display_name=entry["display_name"],
                        bio=entry["bio"],
                        private_notes=entry["private_notes"],
                        role=entry["role"],
                    )
                )
            db.session.commit()
        Settings.get()
        for category in CATEGORIES:
            if category.seed_fn is not None:
                category.seed_fn()


def reset_database(app):
    with app.app_context():
        db.drop_all()
        db.create_all()
    seed_database(app)
    # The A07 "MFA Code Not Bound to Session" example keeps pending codes in
    # a module-level dict, not in the database, so a DB reset alone would
    # otherwise leave old codes valid indefinitely. Import locally to avoid
    # a circular import at module load time.
    from app.categories.a07_auth_failures.routes import PENDING_MFA_CODES_BY_USERNAME

    PENDING_MFA_CODES_BY_USERNAME.clear()

    # Several exercises write proof/log/upload state to the filesystem
    # instead of the database -- a DB reset alone leaves all of it behind,
    # so "Reset lab" silently fails to give these exercises a clean state.
    # Import locally, same reason as above.
    from app.categories.a03_injection.routes import (
        ARCHIVE_EXPORT_DIR,
        ATTACHMENTS_DIR,
        CSS_EXFIL_LOG_PATH,
        SNIPPETS_DIR,
    )
    from app.categories.a06_vulnerable_components.routes import IMAGETRAGICK_PROOF_PATH
    from app.categories.a09_logging_monitoring_failures.routes import LOG_FILE_PATH

    for stale_file in (CSS_EXFIL_LOG_PATH, LOG_FILE_PATH, IMAGETRAGICK_PROOF_PATH):
        if os.path.exists(stale_file):
            os.remove(stale_file)
    for stale_dir in (SNIPPETS_DIR, ATTACHMENTS_DIR, ARCHIVE_EXPORT_DIR):
        if os.path.isdir(stale_dir):
            shutil.rmtree(stale_dir)
