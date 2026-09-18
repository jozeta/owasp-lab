def test_a02_overview_renders(client):
    response = client.get("/a02/")
    assert response.status_code == 200
    assert b"Cryptographic Failures" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a02_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a02 = next(c for c in CATEGORIES if c.id == "a02_crypto_failures")
    assert a02.short_id == "A02"
    assert [e.difficulty for e in a02.examples] == ["Easy", "Medium", "Hard"]
