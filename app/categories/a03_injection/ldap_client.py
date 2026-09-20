import os

from ldap3 import Connection, Server

LDAP_URL = os.environ.get("LDAP_URL", "ldap://localhost:3890")
LDAP_BASE_DN = os.environ.get("LDAP_BASE_DN", "dc=owasp-lab,dc=local")
LDAP_ADMIN_DN = os.environ.get("LDAP_ADMIN_DN", "cn=admin,dc=owasp-lab,dc=local")
LDAP_ADMIN_PASSWORD = os.environ.get("LDAP_ADMIN_PASSWORD", "admin123")


def get_ldap_connection():
    """Returns a fresh, bound LDAP connection. Tests monkeypatch this
    function (see the `mock_ldap` fixture in tests/conftest.py) to return
    an in-memory mock connection instead of binding to a real server."""
    server = Server(LDAP_URL)
    return Connection(server, LDAP_ADMIN_DN, LDAP_ADMIN_PASSWORD, auto_bind=True)
