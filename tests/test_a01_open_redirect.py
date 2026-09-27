def test_continue_redirects_to_internal_path(client):
    response = client.get("/a01/continue", query_string={"next": "/a01/"})
    assert response.status_code == 302
    assert response.headers["Location"] == "/a01/"


def test_continue_redirects_to_arbitrary_external_url(client):
    payload = "https://evil.example.com/phish"
    response = client.get("/a01/continue", query_string={"next": payload})
    assert response.status_code == 302
    assert response.headers["Location"] == payload


def test_continue_filtered_blocks_unrelated_external_url(client):
    response = client.get(
        "/a01/continue-filtered", query_string={"next": "https://evil.example.com/phish"}
    )
    assert response.status_code == 400


def test_continue_filtered_bypassed_via_domain_suffix(client):
    payload = "https://trusted-partner.example.evil.example.com/phish"
    response = client.get("/a01/continue-filtered", query_string={"next": payload})
    assert response.status_code == 302
    assert response.headers["Location"] == payload


def test_continue_renders_explanation_page_on_bare_nav_visit(client):
    # Test that accessing /a01/continue without next param renders the explanation page
    response = client.get("/a01/continue")
    assert response.status_code == 200
    assert b"Unvalidated Open Redirect" in response.data
