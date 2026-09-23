def test_a07_overview_renders(client):
    response = client.get("/a07/")
    assert response.status_code == 200
    assert b"Identification and Authentication Failures" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a07_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a07 = next(c for c in CATEGORIES if c.id == "a07_auth_failures")
    assert a07.short_id == "A07"
    assert [e.difficulty for e in a07.examples] == [
        "Easy",
        "Medium",
        "Easy",
        "Medium",
        "Hard",
        "Easy",
        "Medium",
        "Hard",
        "Medium",
        "Hard",
        "Hard",
    ]


def test_a07_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a07 = next(c for c in CATEGORIES if c.id == "a07_auth_failures")
    grouped = a07.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Brute Force & Credential Stuffing",
        "Session Identity & Lifecycle",
        "Multi-Factor Authentication Bypass",
        "Account Recovery Abuse",
    ]
    assert [e.id for e in grouped[0][1]] == ["brute-force-login", "credential-stuffing"]
    assert [e.id for e in grouped[1][1]] == [
        "session-in-url",
        "session-survives-logout",
        "session-fixation",
    ]
    assert [e.id for e in grouped[2][1]] == ["mfa-leaked-code", "mfa-reusable-code", "mfa-bypass"]
    assert [e.id for e in grouped[3][1]] == [
        "password-reset-disables-mfa",
        "username-collision-reset",
        "unicode-normalization-takeover",
    ]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a07_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a07/")
    body = response.data.decode()
    assert "Brute Force &amp; Credential Stuffing" in body
    assert "Session Identity &amp; Lifecycle" in body
    assert "Multi-Factor Authentication Bypass" in body
    assert "Account Recovery Abuse" in body
