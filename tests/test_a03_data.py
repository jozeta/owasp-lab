from app.categories.a03_injection.models import Comment, InjectionAccount, Secret
from app.core.seed import reset_database, seed_database
from app.extensions import db


def test_seed_injection_data_creates_accounts_secrets_and_a_comment(app):
    seed_database(app)
    with app.app_context():
        usernames = {a.username for a in InjectionAccount.query.all()}
        assert usernames == {"alice", "admin"}
        admin = InjectionAccount.query.filter_by(username="admin").first()
        assert admin.is_admin is True
        assert Secret.query.count() == 2
        assert Comment.query.count() == 1


def test_seed_injection_data_is_idempotent(app):
    seed_database(app)
    seed_database(app)
    with app.app_context():
        assert InjectionAccount.query.count() == 2
        assert Secret.query.count() == 2
        assert Comment.query.count() == 1


def test_reset_database_restores_injection_accounts(app):
    seed_database(app)
    with app.app_context():
        admin = InjectionAccount.query.filter_by(username="admin").first()
        admin.password = "tampered"
        db.session.commit()

    reset_database(app)

    with app.app_context():
        admin = InjectionAccount.query.filter_by(username="admin").first()
        assert admin.password == "sup3r-s3cret-admin-pw"
