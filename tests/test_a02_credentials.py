import hashlib

from app.categories.a02_crypto_failures.models import LegacyCredential
from app.core.seed import SEED_USERS, reset_database, seed_database
from app.extensions import db


def test_seed_legacy_credentials_creates_md5_hashes(app):
    seed_database(app)
    with app.app_context():
        credentials = {c.username: c.weak_password_hash for c in LegacyCredential.query.all()}
        assert set(credentials) == {u["username"] for u in SEED_USERS}
        for entry in SEED_USERS:
            expected = hashlib.md5(entry["password"].encode()).hexdigest()
            assert credentials[entry["username"]] == expected


def test_seed_legacy_credentials_is_idempotent(app):
    seed_database(app)
    seed_database(app)
    with app.app_context():
        assert LegacyCredential.query.count() == 4


def test_reset_database_restores_legacy_credentials(app):
    seed_database(app)
    with app.app_context():
        alice = LegacyCredential.query.filter_by(username="alice").first()
        alice.weak_password_hash = "tampered"
        db.session.commit()

    reset_database(app)

    with app.app_context():
        alice = LegacyCredential.query.filter_by(username="alice").first()
        expected_password = next(u for u in SEED_USERS if u["username"] == "alice")["password"]
        assert alice.weak_password_hash == hashlib.md5(expected_password.encode()).hexdigest()
