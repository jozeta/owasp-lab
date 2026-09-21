def test_a06_overview_renders(client):
    response = client.get("/a06/")
    assert response.status_code == 200
    assert b"Vulnerable and Outdated Components" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a06_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a06 = next(c for c in CATEGORIES if c.id == "a06_vulnerable_components")
    assert a06.short_id == "A06"
    assert [e.difficulty for e in a06.examples] == [
        "Easy",
        "Easy",
        "Medium",
        "Medium",
        "Hard",
        "Hard",
    ]


def test_a06_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a06 = next(c for c in CATEGORIES if c.id == "a06_vulnerable_components")
    grouped = a06.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Component Reconnaissance",
        "Vulnerable Library: jQuery HTML Sanitization Bypass",
        "Vulnerable Library: Lodash Prototype Pollution",
    ]
    assert [e.id for e in grouped[0][1]] == ["version-disclosure", "outdated-jquery-detection"]
    assert [e.id for e in grouped[1][1]] == ["jquery-dom-xss", "jquery-xss-session-theft"]
    assert [e.id for e in grouped[2][1]] == ["lodash-prototype-pollution", "prototype-pollution-bypass"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a06_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a06/")
    body = response.data.decode()
    assert "Component Reconnaissance" in body
    assert "Vulnerable Library: jQuery HTML Sanitization Bypass" in body
    assert "Vulnerable Library: Lodash Prototype Pollution" in body
