def test_a10_overview_renders(client):
    response = client.get("/a10/")
    assert response.status_code == 200
    assert b"Server-Side Request Forgery" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a10_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")
    assert a10.short_id == "A10"
    assert [e.difficulty for e in a10.examples] == [
        "Easy",
        "Medium",
        "Easy",
        "Medium",
        "Hard",
    ]


def test_a10_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a10 = next(c for c in CATEGORIES if c.id == "a10_ssrf")
    grouped = a10.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Unrestricted Server-Side Fetch",
        "Unsafe URL Scheme Handling",
        "Blocklist Bypass Techniques",
    ]
    assert [e.id for e in grouped[0][1]] == [
        "webhook-internal-metadata",
        "fetch-based-port-scan",
    ]
    assert [e.id for e in grouped[1][1]] == ["file-scheme-local-read"]
    assert [e.id for e in grouped[2][1]] == [
        "blocklist-alternate-ip-bypass",
        "blocklist-redirect-bypass",
    ]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a10_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a10/")
    body = response.data.decode()
    assert "Unrestricted Server-Side Fetch" in body
    assert "Unsafe URL Scheme Handling" in body
    assert "Blocklist Bypass Techniques" in body
