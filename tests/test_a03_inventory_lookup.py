from app.categories.a03_injection.models import Secret
from app.core.seed import seed_database


def test_inventory_lookup_page_renders(client):
    response = client.get("/a03/inventory-lookup")
    assert response.status_code == 200


def test_inventory_lookup_counts_a_legitimate_sku(app, client):
    seed_database(app)
    with app.app_context():
        secret_id = Secret.query.first().id

    response = client.post("/a03/inventory-lookup", data={"sku": str(secret_id)})
    assert response.status_code == 200
    assert b"Inventory count: 1" in response.data


def test_inventory_lookup_boolean_injection_returns_the_full_table_count(app, client):
    # Portable boolean-based injection: "0 OR 1=1" makes every row match,
    # proving the field reaches raw SQL. This test deliberately stops
    # here -- the stacked-query and COPY FROM PROGRAM escalation shown in
    # this example's own teaching text is Postgres-specific and was
    # already live-verified against the real app (see this plan's Global
    # Constraints); it is never attempted against SQLite here.
    seed_database(app)
    response = client.post("/a03/inventory-lookup", data={"sku": "0 OR 1=1"})
    assert response.status_code == 200
    assert b"Inventory count: 2" in response.data


def test_inventory_lookup_link_appears_in_overview_once_registered(client):
    response = client.get("/a03/")
    assert response.status_code == 200
    assert b"Advanced SQL Injection: From Detection to Remote Code Execution" in response.data
    assert b'href="/a03/inventory-lookup"' in response.data
