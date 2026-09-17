import pytest

from app import create_app
from app.config import TestConfig
from app.extensions import db


@pytest.fixture
def app():
    flask_app = create_app(TestConfig)
    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def login(app, client):
    def _login(username):
        from app.core.models import User
        from app.core.seed import seed_database

        seed_database(app)
        with app.app_context():
            user = User.query.filter_by(username=username).first()
            user_id = user.id
        with client.session_transaction() as sess:
            sess["user_id"] = user_id
        return user_id

    return _login
