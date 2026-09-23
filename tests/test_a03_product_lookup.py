from app.categories.a03_injection.models import Secret
from app.core.seed import seed_database


def test_product_lookup_page_renders(client):
    response = client.get("/a03/product-lookup")
    assert response.status_code == 200


def test_product_lookup_finds_a_legitimate_product(app, client):
    seed_database(app)
    with app.app_context():
        secret = Secret.query.filter_by(label="Internal API Key").first()
        secret_id = secret.id

    response = client.post("/a03/product-lookup", data={"product_id": str(secret_id)})
    assert response.status_code == 200
    assert b"sk_live_51NxFakeKeyForTraining000" in response.data


def test_product_lookup_surfaces_raw_database_error_on_broken_syntax(client):
    # A lone single quote breaks the raw SQL string open -- this is
    # portable across SQLite and Postgres alike (both raise a syntax
    # error for an unterminated string literal), unlike the Postgres-only
    # CAST-based data-leaking payload shown in this example's own
    # teaching text, which this test deliberately does not attempt.
    response = client.post("/a03/product-lookup", data={"product_id": "'"})
    assert response.status_code == 200
    assert b"unrecognized token" in response.data


def test_product_lookup_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Error-Based SQL Injection via Product Lookup" in response.data
    assert b'href="/a03/product-lookup"' in response.data
