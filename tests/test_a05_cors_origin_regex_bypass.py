def test_partner_portal_page_renders(client):
    response = client.get("/a05/api/partner-portal")
    assert response.status_code == 200


def test_real_partner_origin_is_accepted(client):
    response = client.get(
        "/a05/api/partner-portal", headers={"Origin": "https://partner.example.com"}
    )
    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") == "https://partner.example.com"
    assert response.headers.get("Access-Control-Allow-Credentials") == "true"


def test_unanchored_regex_accepts_a_lookalike_attacker_domain(client):
    # VULNERABLE: the allowlist regex has no end-anchor, so any origin
    # merely CONTAINING "example.com" after "https://" matches --
    # including a domain the real business never registered or trusts.
    response = client.get(
        "/a05/api/partner-portal", headers={"Origin": "https://evilexample.com"}
    )
    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") == "https://evilexample.com"
    assert response.headers.get("Access-Control-Allow-Credentials") == "true"


def test_a_completely_unrelated_origin_is_still_rejected(client):
    response = client.get(
        "/a05/api/partner-portal", headers={"Origin": "https://totally-unrelated.com"}
    )
    assert response.status_code == 200
    assert "Access-Control-Allow-Origin" not in response.headers


def test_explanation_page_renders_html(client):
    # Proves ExampleNav.endpoint (cors_origin_regex_bypass) genuinely
    # renders the HTML explanation page, not the raw JSON API -- the
    # exact convention a Task 6 fix-round established after a reviewer
    # caught an endpoint wired directly to a JSON route.
    response = client.get("/a05/cors-origin-regex-bypass")
    assert response.status_code == 200
    assert response.content_type.startswith("text/html")
    assert b"Origin Allowlist Regex Bypass" in response.data
