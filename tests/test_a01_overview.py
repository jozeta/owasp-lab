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
    assert [e.difficulty for e in a01.examples] == [
        "Easy",
        "Medium",
        "Medium",
        "Medium",
        "Hard",
        "Medium",
        "Medium",
        "Medium",
        "Hard",
        "Medium",
        "Hard",
        "Hard",
    ]


def test_a01_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a01 = next(c for c in CATEGORIES if c.id == "a01_access_control")
    grouped = a01.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Insecure Direct Object References (IDOR)",
        "Missing Function-Level Access Control",
        "Mass Assignment",
        "Cross-Site Request Forgery",
        "Path Traversal",
        "Open Redirect",
        "HTTP Parameter Pollution",
    ]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a01_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a01/")
    body = response.data.decode()
    assert "Insecure Direct Object References (IDOR)" in body
    assert "Missing Function-Level Access Control" in body
    assert "Mass Assignment" in body
    assert "Cross-Site Request Forgery" in body
    assert "Path Traversal" in body
    assert "Open Redirect" in body
    assert "HTTP Parameter Pollution" in body
