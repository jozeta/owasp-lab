def test_a01_overview_renders(client):
    response = client.get("/a01/")
    assert response.status_code == 200
    assert b"Broken Access Control" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a01_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a01 = next(c for c in CATEGORIES if c.id == "a01_access_control")
    assert a01.short_id == "A01"
    assert [e.difficulty for e in a01.examples] == ["Easy", "Medium", "Hard"]
