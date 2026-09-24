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
    assert [e.difficulty for e in a04.examples] == ["Easy", "Easy", "Medium", "Hard", "Hard"]


def test_a04_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a04 = next(c for c in CATEGORIES if c.id == "a04_insecure_design")
    grouped = a04.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Business Logic Abuse",
        "Workflow Bypass",
        "Password Reset Design Flaws",
    ]
    assert [e.id for e in grouped[0][1]] == ["unlimited-coupon", "free-shipping-trusted-flag", "negative-quantity"]
    assert [e.id for e in grouped[1][1]] == ["checkout-bypass"]
    assert [e.id for e in grouped[2][1]] == ["host-header-reset-poisoning"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a04_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a04/")
    body = response.data.decode()
    assert "Business Logic Abuse" in body
    assert "Workflow Bypass" in body
    assert "Password Reset Design Flaws" in body
