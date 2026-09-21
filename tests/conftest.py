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


class CookieHeaderAwareClient:
    """Test client that properly handles Cookie headers passed via headers parameter."""

    def __init__(self, flask_client):
        self._client = flask_client

    def __getattr__(self, name):
        """Delegate all other attributes to the wrapped client."""
        return getattr(self._client, name)

    def get(self, path, **kwargs):
        """Override get to handle Cookie headers."""
        headers = kwargs.get("headers", {})
        if isinstance(headers, dict) and "Cookie" in headers:
            cookie_header = headers.pop("Cookie")
            # Parse and set cookies from the header
            for cookie_str in cookie_header.split(";"):
                cookie_str = cookie_str.strip()
                if "=" in cookie_str:
                    name, value = cookie_str.split("=", 1)
                    self._client.set_cookie(name.strip(), value.strip(), domain="localhost")

        return self._client.get(path, **kwargs)


@pytest.fixture
def client(app):
    return CookieHeaderAwareClient(app.test_client())


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


@pytest.fixture
def mock_ldap(monkeypatch):
    """Monkeypatches ldap_client.get_ldap_connection to return a fresh,
    pre-seeded ldap3 MOCK_SYNC in-memory connection on every call -- no
    real LDAP server needed. A fresh connection is built each call (not a
    shared/reused one) because a real Connection object cannot be
    searched again after unbind(), and each route call does its own
    bind-search-unbind cycle, matching real usage."""
    from ldap3 import MOCK_SYNC, Connection, Server

    from app.categories.a03_injection import ldap_client

    def _make_connection():
        server = Server("mock-ldap-server")
        conn = Connection(server, client_strategy=MOCK_SYNC)
        conn.strategy.add_entry(
            ldap_client.LDAP_ADMIN_DN, {"userPassword": ldap_client.LDAP_ADMIN_PASSWORD}
        )
        conn.strategy.add_entry(
            f"uid=alice,ou=people,{ldap_client.LDAP_BASE_DN}",
            {
                "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
                "cn": "Alice Example",
                "sn": "Example",
                "uid": "alice",
                "userPassword": "alice123",
                "mail": "alice@owasp-lab.local",
            },
        )
        conn.strategy.add_entry(
            f"uid=root_admin,ou=people,{ldap_client.LDAP_BASE_DN}",
            {
                "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
                "cn": "Root Administrator",
                "sn": "Administrator",
                "uid": "root_admin",
                "userPassword": "sup3r-s3cret-ldap-admin-pw",
                "mail": "root_admin@owasp-lab.local",
                "description": "recovery-code-x7k2p9",
            },
        )
        conn.bind()
        return conn

    monkeypatch.setattr(ldap_client, "get_ldap_connection", _make_connection)
