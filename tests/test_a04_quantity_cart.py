def test_quantity_cart_default_quantity_is_one(client):
    response = client.get("/a04/quantity-cart")
    assert response.status_code == 200
    assert b"Total: $29.99" in response.data


def test_quantity_cart_negative_quantity_produces_negative_total(client):
    response = client.post("/a04/quantity-cart", data={"quantity": "-1"})
    assert response.status_code == 200
    assert b"Total: -$29.99" in response.data


def test_quantity_cart_negative_quantity_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.post("/a04/quantity-cart", data={"quantity": "-1"})
    assert response.status_code == 200
    assert b"Total: -$29.99" in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_quantity_cart_link_appears_in_overview_once_registered(client):
    response = client.get("/a04/")
    assert response.status_code == 200
    assert b"Negative Quantity Price Manipulation" in response.data
    assert b'href="/a04/quantity-cart"' in response.data


def test_quantity_cart_handles_pathologically_large_quantity_without_crashing(client):
    response = client.post("/a04/quantity-cart", data={"quantity": "9" * 320})
    assert response.status_code == 200


def test_quantity_cart_reset_clears_session(client):
    client.post("/a04/quantity-cart", data={"quantity": "-1"})
    client.post("/a04/quantity-cart/reset")
    response = client.get("/a04/quantity-cart")
    assert response.status_code == 200
    assert b"Total: $29.99" in response.data


def test_quantity_cart_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a04/quantity-cart")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"min(quantity, 99)" in response.data


def test_quantity_cart_shows_detect_content(client):
    response = client.get("/a04/quantity-cart")
    assert response.status_code == 200
    assert b"no bounds validation" in response.data
