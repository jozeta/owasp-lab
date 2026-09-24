def test_internal_metrics_page_renders(client):
    response = client.get("/a05/api/internal-metrics")
    assert response.status_code == 200


def test_wildcard_origin_header_present(client):
    response = client.get("/a05/api/internal-metrics", headers={"Origin": "https://evil.com"})
    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") == "*"


def test_no_credentials_header_sent_with_wildcard(client):
    # Wildcard + credentials is a combination real browsers refuse
    # outright, so a genuinely wildcard response never sets this header.
    response = client.get("/a05/api/internal-metrics", headers={"Origin": "https://evil.com"})
    assert "Access-Control-Allow-Credentials" not in response.headers


def test_no_authentication_required_at_all(client):
    # VULNERABLE: zero auth check -- this "internal" endpoint returns
    # sensitive data to any unauthenticated request whatsoever.
    response = client.get("/a05/api/internal-metrics")
    assert response.status_code == 200
    assert b"active_connections" in response.data


def test_explanation_page_renders_html(client):
    # Proves ExampleNav.endpoint (cors_wildcard_internal_pivot) genuinely
    # renders the HTML explanation page, not the raw JSON API -- the
    # exact convention this task's own fix-round is reinforcing.
    response = client.get("/a05/cors-wildcard-internal-pivot")
    assert response.status_code == 200
    assert response.content_type.startswith("text/html")
    assert b"CORS: Wildcard Origin, Internal Network Pivot" in response.data
