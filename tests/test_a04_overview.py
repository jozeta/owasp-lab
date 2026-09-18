def test_a04_overview_renders(client):
    response = client.get("/a04/")
    assert response.status_code == 200
    assert b"Insecure Design" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a04_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a04 = next(c for c in CATEGORIES if c.id == "a04_insecure_design")
    assert a04.short_id == "A04"
    assert [e.difficulty for e in a04.examples] == ["Easy", "Medium", "Hard"]
