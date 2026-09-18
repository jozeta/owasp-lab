from app.categories.a04_insecure_design.models import Order


def test_checkout_full_flow_creates_paid_order(app, client):
    client.post("/a04/checkout/shipping", data={"address": "123 Demo St"})
    client.post("/a04/checkout/payment")
    response = client.get("/a04/checkout/confirm")
    assert response.status_code == 200
    assert b"Thank you for your order" in response.data

    with app.app_context():
        order = Order.query.order_by(Order.id.desc()).first()
        assert order.paid is True


def test_checkout_confirm_skips_shipping_and_payment_and_still_confirms(app, client):
    response = client.get("/a04/checkout/confirm")
    assert response.status_code == 200
    assert b"Thank you for your order" in response.data

    with app.app_context():
        order = Order.query.order_by(Order.id.desc()).first()
        assert order is not None
        assert order.paid is False


def test_checkout_bypass_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = client.get("/a04/checkout/confirm")
    assert response.status_code == 200
    assert b"Thank you for your order" in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data

    with app.app_context():
        order = Order.query.order_by(Order.id.desc()).first()
        assert order.paid is False


def test_checkout_link_appears_in_overview_once_registered(client):
    response = client.get("/a04/")
    assert response.status_code == 200
    assert b"Multi-Step Checkout Bypass" in response.data
    assert b'href="/a04/checkout/shipping"' in response.data
