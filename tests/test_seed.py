from werkzeug.security import check_password_hash

from app.core.models import User
from app.core.seed import SEED_USERS, reset_database, seed_database
from app.extensions import db


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
