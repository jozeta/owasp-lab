def test_cors_null_origin_page_renders(client):
    response = client.get("/a05/api/partner-directory")
    assert response.status_code == 200


def test_null_origin_is_reflected_with_credentials(client):
    response = client.get("/a05/api/partner-directory", headers={"Origin": "null"})
    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") == "null"
    assert response.headers.get("Access-Control-Allow-Credentials") == "true"


def test_a_real_specific_origin_is_not_reflected(client):
    # VULNERABLE-CONFIRMATION: only the literal "null" origin is
    # whitelisted -- a normal, specific attacker origin gets no CORS
    # headers at all from this endpoint (the flaw is specifically about
    # trusting "null", not about reflecting everything).
    response = client.get("/a05/api/partner-directory", headers={"Origin": "https://evil.com"})
    assert response.status_code == 200
    assert "Access-Control-Allow-Origin" not in response.headers


def test_null_origin_demo_page_embeds_sandboxed_data_uri_iframe(client):
    response = client.get("/a05/cors-null-origin-demo")
    assert response.status_code == 200
    assert b'sandbox="allow-scripts"' in response.data
    assert b"data:text/html" in response.data
