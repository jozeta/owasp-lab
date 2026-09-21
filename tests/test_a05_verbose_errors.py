def test_inventory_check_page_loads(client):
    response = client.get("/a05/inventory-check")
    assert response.status_code == 200
    assert b"Verbose Error Message Disclosure" in response.data


def test_inventory_check_leaks_warehouse_password_in_error(client):
    response = client.post("/a05/inventory-check", data={"sku": "SKU-001"})
    assert response.status_code == 200
    assert b"wh_S3rv1ce_2024!" in response.data
    assert b"postgresql://warehouse_svc:wh_S3rv1ce_2024!@10.0.4.12:5432/inventory" in response.data
    assert b"Traceback" in response.data


def test_inventory_check_includes_submitted_sku_in_leaked_message(client):
    response = client.post("/a05/inventory-check", data={"sku": "SKU-XYZ-999"})
    assert response.status_code == 200
    assert b"SKU-XYZ-999" in response.data


def test_inventory_check_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post("/a05/inventory-check", data={"sku": "SKU-001"})
    assert response.status_code == 200
    assert b"wh_S3rv1ce_2024!" in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_inventory_check_link_appears_in_overview_once_registered(client):
    response = client.get("/a05/")
    assert response.status_code == 200
    assert b"Verbose Error Message Disclosure" in response.data
    assert b'href="/a05/inventory-check"' in response.data
