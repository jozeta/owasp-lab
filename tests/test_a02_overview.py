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
    assert [e.difficulty for e in a02.examples] == ["Easy", "Medium", "Hard", "Easy", "Medium", "Hard"]


def test_a02_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a02 = next(c for c in CATEGORIES if c.id == "a02_crypto_failures")
    grouped = a02.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Weak Hashing",
        "Weak Encryption",
        "Predictable Tokens",
        "Token Leakage",
        "Weak Random Number Generation",
    ]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a02_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a02/")
    body = response.data.decode()
    assert '<h3 class="h6 mt-3">Weak Hashing</h3>' in body
    assert '<h3 class="h6 mt-3">Weak Encryption</h3>' in body
    assert '<h3 class="h6 mt-3">Predictable Tokens</h3>' in body
    assert '<h3 class="h6 mt-3">Token Leakage</h3>' in body
    assert '<h3 class="h6 mt-3">Weak Random Number Generation</h3>' in body
