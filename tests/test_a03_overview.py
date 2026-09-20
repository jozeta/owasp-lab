def test_a03_overview_renders(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Injection" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a03_overview_mermaid_diagram_has_no_embedded_html_tags(client):
    response = client.get("/a03/")
    html = response.data.decode()
    start = html.index('<div class="mermaid">')
    end = html.index("</div>", start)
    diagram_source = html[start:end]
    assert "<script" not in diagram_source.lower()
    assert "Unauthorized data, command output, or script execution" in diagram_source


def test_a03_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    assert a03.short_id == "A03"
    assert [e.difficulty for e in a03.examples] == [
        "Easy",
        "Medium",
        "Hard",
        "Medium",
        "Hard",
        "Hard",
        "Easy",
        "Hard",
        "Easy",
        "Hard",
        "Easy",
    ]


def test_a03_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a03 = next(c for c in CATEGORIES if c.id == "a03_injection")
    grouped = a03.grouped_examples()
    assert [name for name, _ in grouped] == [
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "OS Command Injection",
        "XML External Entity Injection (XXE)",
        "Server-Side Template Injection (SSTI)",
        "LDAP Injection",
    ]
    assert [e.id for e in grouped[0][1]] == ["sqli-login", "union-exfiltration", "blind-sqli"]
    assert [e.id for e in grouped[1][1]] == ["reflected-xss", "stored-xss"]
    assert [e.id for e in grouped[2][1]] == ["command-injection"]
    assert [e.id for e in grouped[3][1]] == ["xml-import", "xxe-ssrf"]
    assert [e.id for e in grouped[4][1]] == ["ssti-email-preview", "ssti-blacklist-bypass"]
    assert [e.id for e in grouped[5][1]] == ["ldap-directory-login"]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a03_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a03/")
    body = response.data.decode()
    assert '<h3 class="h6 mt-3">SQL Injection</h3>' in body
    assert '<h3 class="h6 mt-3">Cross-Site Scripting (XSS)</h3>' in body
    assert '<h3 class="h6 mt-3">OS Command Injection</h3>' in body
