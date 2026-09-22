def test_product_search_with_no_query_does_not_log(app, client):
    from app.categories.a09_logging_monitoring_failures.models import SecurityEvent

    with app.app_context():
        before = SecurityEvent.query.count()

    response = client.get("/a09/product-search")
    assert response.status_code == 200

    with app.app_context():
        after = SecurityEvent.query.count()

    assert after == before


def test_attack_signature_is_logged_verbatim_but_never_flagged(app, client):
    from app.categories.a09_logging_monitoring_failures.models import SecurityEvent

    # Deliberately a query with no HTML-special characters (no quotes,
    # angle brackets, or ampersands) -- Jinja2/MarkupSafe autoescaping
    # would otherwise rewrite a literal "'" to "&#39;" on the rendered
    # page, making a raw-substring check below fail even when the code
    # is correct. The DB-level assertion just below is unaffected either
    # way (SQLAlchemy stores the raw string, untouched by HTML escaping),
    # but the rendered-page check needs a string that survives escaping
    # unchanged, so this test uses a path-traversal probe instead of a
    # SQL-injection probe -- both are illustrated in the template's own
    # teaching prose (see Step 5 below), and either is an equally valid
    # "obvious attack signature" for this lesson.
    attack_query = "../../../../etc/passwd"

    with app.app_context():
        before = SecurityEvent.query.count()

    response = client.get("/a09/product-search", query_string={"q": attack_query})
    assert response.status_code == 200

    with app.app_context():
        after = SecurityEvent.query.count()
        latest = SecurityEvent.query.order_by(SecurityEvent.id.desc()).first()

    assert after == before + 1
    assert latest.detail == f"query={attack_query}"

    events_response = client.get("/a09/security-events")
    assert attack_query.encode() in events_response.data
    assert b"Active Alerts (0)" in events_response.data


def test_reflected_query_is_html_escaped_not_raw(client):
    response = client.get(
        "/a09/product-search", query_string={"q": "<script>alert(1)</script>"}
    )
    assert response.status_code == 200
    assert b"<script>alert(1)</script>" not in response.data
    assert b"&lt;script&gt;" in response.data


def test_attack_signature_not_flagged_link_appears_in_overview_once_registered(client):
    response = client.get("/a09/")
    assert response.status_code == 200
    assert b"Attack Signature Logged But Never Flagged" in response.data
    assert b'href="/a09/product-search"' in response.data
