def test_a05_overview_renders(client):
    response = client.get("/a05/")
    assert response.status_code == 200
    assert b"Security Misconfiguration" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data
