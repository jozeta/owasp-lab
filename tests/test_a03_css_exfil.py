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


def test_collector_accepts_and_stores_an_arbitrary_leak_value_with_no_auth(client):
    response = client.get("/a03/css-exfil-collector?leak=zzz-test-marker")
    assert response.status_code == 204

    demo_response = client.get("/a03/css-exfil-demo")
    assert b"zzz-test-marker" in demo_response.data
