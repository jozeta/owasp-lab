def test_a08_overview_renders(client):
    response = client.get("/a08/")
    assert response.status_code == 200
    assert b"Software and Data Integrity Failures" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a08_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a08 = next(c for c in CATEGORIES if c.id == "a08_integrity_failures")
    assert a08.short_id == "A08"
    assert [e.difficulty for e in a08.examples] == [
        "Easy",
        "Medium",
        "Easy",
        "Medium",
        "Hard",
        "Hard",
    ]


def test_a08_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a08 = next(c for c in CATEGORIES if c.id == "a08_integrity_failures")
    grouped = a08.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Insecure Deserialization",
        "Unsigned Software Updates & Supply Chain",
        "Broken Signature Verification",
    ]
    assert [e.id for e in grouped[0][1]] == ["cart-pickle-tampering", "cart-pickle-rce"]
    assert [e.id for e in grouped[1][1]] == [
        "plugin-marketplace-tampering",
        "plugin-marketplace-rce",
    ]
    assert [e.id for e in grouped[2][1]] == [
        "unchecked-signature-cookie",
        "jwt-alg-none-bypass",
    ]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a08_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a08/")
    body = response.data.decode()
    assert "Insecure Deserialization" in body
    assert "Unsigned Software Updates &amp; Supply Chain" in body
    assert "Broken Signature Verification" in body
