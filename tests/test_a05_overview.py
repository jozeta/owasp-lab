def test_a05_overview_renders(client):
    response = client.get("/a05/")
    assert response.status_code == 200
    assert b"Security Misconfiguration" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a05_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a05 = next(c for c in CATEGORIES if c.id == "a05_security_misconfiguration")
    assert a05.short_id == "A05"
    assert [e.difficulty for e in a05.examples] == [
        "Easy",
        "Easy",
        "Medium",
        "Medium",
        "Medium",
        "Medium",
        "Hard",
        "Hard",
        "Easy",
    ]


def test_a05_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a05 = next(c for c in CATEGORIES if c.id == "a05_security_misconfiguration")
    grouped = a05.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Exposed Files & Directories",
        "Insecure Response Configuration",
        "Exposed Debug & Admin Interfaces",
        "Missing Security Headers",
    ]
    assert [e.id for e in grouped[0][1]] == ["exposed-backup", "directory-listing"]
    assert [e.id for e in grouped[1][1]] == ["verbose-errors", "cors-credentials", "cors-null-origin", "cors-wildcard-internal-pivot"]
    assert [e.id for e in grouped[2][1]] == ["debug-console-rce", "default-admin-creds"]
    assert [e.id for e in grouped[3][1]] == ["clickjacking-delete-account"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a05_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a05/")
    body = response.data.decode()
    # Group names contain "&", which Jinja2's default HTML autoescaping
    # (Flask's standard, secure behavior for .html templates) renders as
    # "&amp;" -- assert against the actual escaped output.
    assert "Exposed Files &amp; Directories" in body
    assert "Insecure Response Configuration" in body
    assert "Exposed Debug &amp; Admin Interfaces" in body
    assert "Missing Security Headers" in body
