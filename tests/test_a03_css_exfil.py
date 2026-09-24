import os
import re

import pytest

from app.categories.a03_injection.routes import CSS_EXFIL_LOG_PATH


@pytest.fixture(autouse=True)
def _clean_css_exfil_log():
    if os.path.exists(CSS_EXFIL_LOG_PATH):
        os.remove(CSS_EXFIL_LOG_PATH)
    yield
    if os.path.exists(CSS_EXFIL_LOG_PATH):
        os.remove(CSS_EXFIL_LOG_PATH)


def test_theme_preview_page_renders(client):
    response = client.get("/a03/theme-preview")
    assert response.status_code == 200
    assert b"CSS Attribute-Selector Data Exfiltration" in response.data


def test_submitted_css_renders_completely_unescaped(client):
    payload = 'input[value^="test"]{background:url(/x)}<!--marker-->'
    response = client.post("/a03/theme-preview", data={"custom_css": payload})
    assert response.status_code == 200
    assert payload.encode() in response.data


def test_hidden_recovery_pin_is_genuinely_present_in_the_dom(client):
    response = client.get("/a03/theme-preview")
    assert b'value="7429"' in response.data
    assert b'name="account_recovery_pin"' in response.data


def test_exfil_demo_page_embeds_the_real_pin_and_the_attribute_selector_rule(client):
    response = client.get("/a03/css-exfil-demo")
    assert response.status_code == 200
    body = response.data.decode()
    assert "7429" in body
    assert "account_recovery_pin" in body
    assert 'value^=&quot;7&quot;' in body
    assert "/a03/css-exfil-collector?leak=7" in body


def test_exfil_rule_targets_a_rendered_sibling_not_the_hidden_input_directly(client):
    # Regression guard for the bug that slipped through 3 prior reviews:
    # a rule that matches the hidden input directly never fires in any
    # browser, because browsers never issue background-image requests for
    # display:none elements. The rule must instead target a rendered
    # sibling via a `+` (or `~`) combinator immediately after the hidden
    # input's attribute selector.
    response = client.get("/a03/css-exfil-demo")
    assert response.status_code == 200
    body = response.data.decode()

    # The attribute-selector rule is followed by a sibling combinator and
    # a rendered element (e.g. `+ p`), not by the rule's opening brace.
    assert re.search(
        r'input\[name=&quot;account_recovery_pin&quot;\]\[value\^=&quot;7&quot;\]\s*[+~]\s*p\s*\{',
        body,
    ), "expected the CSS rule to target a rendered sibling via a + or ~ combinator"

    # Guard against regressing back to a bare, sibling-less selector that
    # matches the hidden input directly (no combinator/rendered element
    # between the attribute selector and the opening brace).
    assert not re.search(
        r'input\[name=&quot;account_recovery_pin&quot;\]\[value\^=&quot;7&quot;\]\s*\{',
        body,
    ), "a background-image rule must never target the hidden input directly"


def test_collector_accepts_and_stores_an_arbitrary_leak_value_with_no_auth(client):
    response = client.get("/a03/css-exfil-collector?leak=zzz-test-marker")
    assert response.status_code == 204

    demo_response = client.get("/a03/css-exfil-demo")
    assert b"zzz-test-marker" in demo_response.data


def test_collector_write_survives_with_no_session_cookie(app, client):
    # The real-world attack fires the collector request from a sandboxed
    # data: URI iframe with an opaque origin, which never carries the
    # app's session cookie. Simulate that by clearing cookies before the
    # collector request -- the leak must still be captured (file-backed,
    # not session-backed) and visible on a completely separate client.
    client.get("/a03/css-exfil-demo")  # establish a session cookie
    client.delete_cookie("session")

    response = client.get("/a03/css-exfil-collector?leak=no-cookie-marker")
    assert response.status_code == 204

    # A brand-new client on the same app, sharing no cookies at all with
    # `client`, must still see it -- proving the value is stored
    # server-side outside of any session.
    fresh_client = app.test_client()
    demo_response = fresh_client.get("/a03/css-exfil-demo")
    assert b"no-cookie-marker" in demo_response.data
