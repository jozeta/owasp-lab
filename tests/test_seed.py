import os

from werkzeug.security import check_password_hash

from app.categories.a03_injection.routes import (
    ARCHIVE_EXPORT_DIR,
    ATTACHMENTS_DIR,
    CSS_EXFIL_LOG_PATH,
    SNIPPETS_DIR,
)
from app.categories.a06_vulnerable_components.routes import IMAGETRAGICK_PROOF_PATH
from app.categories.a09_logging_monitoring_failures.routes import LOG_FILE_PATH
from app.core.models import User
from app.core.seed import SEED_USERS, reset_database, seed_database
from app.extensions import db


def _touch(path, content="stale"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def test_seed_database_creates_expected_users(app):
    seed_database(app)
    with app.app_context():
        usernames = {u.username for u in User.query.all()}
        assert usernames == {"alice", "bob", "carol", "admin"}

        admin = User.query.filter_by(username="admin").first()
        assert admin.role == "admin"

        alice = User.query.filter_by(username="alice").first()
        assert alice.role == "user"
        seed_alice = next(u for u in SEED_USERS if u["username"] == "alice")
        assert check_password_hash(alice.password_hash, seed_alice["password"])
        assert alice.password_hash != seed_alice["password"]


def test_seed_database_is_idempotent(app):
    seed_database(app)
    seed_database(app)
    with app.app_context():
        assert User.query.count() == 4


def test_reset_database_restores_clean_state(app):
    seed_database(app)
    with app.app_context():
        alice = User.query.filter_by(username="alice").first()
        alice.role = "admin"
        alice.bio = "tampered"
        db.session.commit()

    reset_database(app)

    with app.app_context():
        alice = User.query.filter_by(username="alice").first()
        assert alice.role == "user"
        assert alice.bio != "tampered"
        assert User.query.count() == 4


def test_reset_database_clears_stale_files_and_dirs(app):
    _touch(CSS_EXFIL_LOG_PATH)
    _touch(LOG_FILE_PATH)
    _touch(IMAGETRAGICK_PROOF_PATH)
    os.makedirs(SNIPPETS_DIR, exist_ok=True)
    _touch(os.path.join(SNIPPETS_DIR, "leftover.txt"))
    os.makedirs(ATTACHMENTS_DIR, exist_ok=True)
    _touch(os.path.join(ATTACHMENTS_DIR, "poc.svg"))
    os.makedirs(ARCHIVE_EXPORT_DIR, exist_ok=True)
    _touch(os.path.join(ARCHIVE_EXPORT_DIR, "notes.txt"))

    reset_database(app)

    assert not os.path.exists(CSS_EXFIL_LOG_PATH)
    assert not os.path.exists(LOG_FILE_PATH)
    assert not os.path.exists(IMAGETRAGICK_PROOF_PATH)
    assert not os.path.isdir(SNIPPETS_DIR)
    assert not os.path.isdir(ATTACHMENTS_DIR)
    assert not os.path.isdir(ARCHIVE_EXPORT_DIR)


def test_reset_database_does_not_error_when_nothing_stale_exists(app):
    # Paths may legitimately not exist yet on a fresh app -- reset must
    # not crash just because there's nothing to clean up.
    reset_database(app)
