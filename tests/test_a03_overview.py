def test_a03_overview_renders(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Injection" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a03_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    assert a03.short_id == "A03"
    assert [e.difficulty for e in a03.examples] == [
        "Easy",
        "Medium",
        "Medium",
        "Hard",
        "Hard",
        "Hard",
    ]
