def test_coupon_cart_shows_product(client):
    response = client.get("/a04/coupon-cart")
    assert response.status_code == 200
    assert b"Wireless Mouse" in response.data


def test_coupon_cart_rejects_invalid_code(client):
    response = client.post("/a04/coupon-cart", data={"code": "NOTREAL"})
    assert response.status_code == 200
    assert b"Invalid coupon code" in response.data


def test_coupon_cart_unlimited_reuse_drives_price_to_zero(client):
    response = None
    for _ in range(6):
        response = client.post("/a04/coupon-cart", data={"code": "WELCOME10"})
    assert response.status_code == 200
    assert b"Total: $0.00" in response.data


def test_coupon_cart_reset_clears_usage_count(client):
    client.post("/a04/coupon-cart", data={"code": "WELCOME10"})
    client.post("/a04/coupon-cart/reset")
    response = client.get("/a04/coupon-cart")
    assert response.status_code == 200
    assert b"applied 0 time" in response.data


def test_coupon_cart_still_works_with_teaching_text_hidden(app, client):
    from app.core.models import Settings
    from app.extensions import db

    with app.app_context():
        settings = Settings.get()
        settings.show_explanations = False
        settings.show_exploit_instructions = False
        db.session.commit()

    response = None
    for _ in range(6):
        response = client.post("/a04/coupon-cart", data={"code": "WELCOME10"})
    assert response.status_code == 200
    assert b"Total: $0.00" in response.data
    assert b"Explanation" not in response.data
    assert b"Exploitation" not in response.data


def test_coupon_cart_link_appears_in_overview_once_registered(client):
    response = client.get("/a04/")
    assert response.status_code == 200
    assert b"Unlimited Coupon Reuse" in response.data
    assert b'href="/a04/coupon-cart"' in response.data


def test_coupon_cart_shows_vulnerable_vs_secure_code(client):
    response = client.get("/a04/coupon-cart")
    assert response.status_code == 200
    assert b"Vulnerable vs. Secure" in response.data
    assert b"a04_coupon_applied" in response.data


def test_coupon_cart_shows_detect_content(app, client):
    with app.app_context():
        from app.core.models import Settings
        from app.extensions import db

        settings = Settings.get()
        settings.show_exploit_instructions = True
        settings.scoring_enabled = False
        db.session.commit()
    response = client.get("/a04/coupon-cart")
    assert response.status_code == 200
    assert b"code once and note the total" in response.data
