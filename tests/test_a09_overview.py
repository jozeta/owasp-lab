def test_a09_overview_renders(client):
    response = client.get("/a09/")
    assert response.status_code == 200
    assert b"Security Logging and Monitoring Failures" in response.data
    assert b"mermaid" in response.data
    assert b"language-python" in response.data


def test_a09_registered_in_nav(app):
    from app.core.nav import CATEGORIES

    a09 = next(c for c in CATEGORIES if c.id == "a09_logging_monitoring_failures")
    assert a09.short_id == "A09"
    assert [e.difficulty for e in a09.examples] == [
        "Easy",
        "Medium",
        "Easy",
        "Hard",
        "Medium",
        "Hard",
    ]


def test_a09_examples_grouped_by_vulnerability_subtype(app):
    from app.core.nav import CATEGORIES

    a09 = next(c for c in CATEGORIES if c.id == "a09_logging_monitoring_failures")
    grouped = a09.grouped_examples()
    assert [name for name, _ in grouped] == [
        "Missing Audit Logging",
        "Insecure Log Storage",
        "No Detection & Alerting for Active Attacks",
    ]
    assert [e.id for e in grouped[0][1]] == [
        "failed-logins-not-logged",
        "admin-action-no-audit",
    ]
    assert [e.id for e in grouped[1][1]] == [
        "sensitive-data-in-logs",
        "log-file-world-readable",
    ]
    assert [e.id for e in grouped[2][1]] == [
        "no-alert-threshold",
        "attack-signature-not-flagged",
    ]
    difficulty_rank = {"Easy": 0, "Medium": 1, "Hard": 2}
    for _, examples in grouped:
        ranks = [difficulty_rank[e.difficulty] for e in examples]
        assert ranks == sorted(ranks), "group examples must be Easy-to-Hard"


def test_a09_overview_shows_vulnerability_subtype_group_headings(client):
    response = client.get("/a09/")
    body = response.data.decode()
    assert "Missing Audit Logging" in body
    assert "Insecure Log Storage" in body
    assert "No Detection &amp; Alerting for Active Attacks" in body
